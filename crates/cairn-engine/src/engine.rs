//! The end-to-end orchestrator: scan → log → catalog → backup → push.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cairn_cas::{CdcChunker, ChunkTransform, Encrypt, Identity};
use cairn_catalog::{Catalog, CatalogChange, LocalChainState, PassUpdates};
use cairn_log::ChainTip;
use cairn_log::{LocationState, MachineLog, Projection, Segment};
use cairn_remote::Remote;
use cairn_types::{
    CatalogEntry, Config, ContentHash, EncryptionConfig, LogEntry, MachineConfig, MachineId,
    PathKey, RemoteConfig,
};
use ed25519_dalek::SigningKey;
use tracing::{debug, info, warn};

use crate::EngineError;
use crate::backup::backup_content;
use crate::restore as restore_module;
use crate::sync::push_pending_as_segment;

/// Counters reported by [`Engine::run_pass`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassSummary {
    /// Roots successfully scanned this pass.
    pub roots_scanned: u32,
    /// Regular files seen during the walks.
    pub files_seen: u64,
    /// Total bytes seen during the walks.
    pub bytes_seen: u64,
    /// Observed events emitted by the scanner (new or changed files).
    pub new_observations: u64,
    /// Vanished events emitted by the scanner.
    pub vanished: u64,
    /// Distinct contents newly backed up (not already `backed_up`).
    pub contents_backed_up: u32,
    /// Chunks uploaded (across all backups in this pass).
    pub chunks_uploaded: u32,
    /// Post-transform bytes uploaded.
    pub bytes_uploaded: u64,
    /// Log entries pushed as part of this pass.
    pub entries_pushed: u32,
}

/// What [`Engine::check`] reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    /// Segments successfully verified from the local machine's prefix.
    pub local_segments_verified: u32,
    /// Per-segment-path string of any corruption found.
    pub corruption_found: Vec<String>,
}

/// The orchestrator.
///
/// One engine per machine. Owns the signing key (through the log), the
/// local catalog database, the in-memory projection, the remote client,
/// the CDC chunker, and the chunk transform.
pub struct Engine {
    config: Config,
    catalog: Catalog,
    log: MachineLog,
    projection: Projection,
    remote: Remote,
    chunker: CdcChunker,
    transform: Box<dyn ChunkTransform>,
}

impl Engine {
    /// Open an engine from a [`Config`] and a catalog database path.
    ///
    /// - Loads or generates the ed25519 signing key (config.machine.key_path).
    /// - Opens / creates the redb catalog at `catalog_path`.
    /// - Restores the local chain state (`next_seq`, `tip`, `last_hlc`,
    ///   `last_pushed_seq`) from the catalog's meta table.
    /// - Rebuilds an in-memory [`Projection`] from the catalog
    ///   (best-effort: live locations + chain tips; tombstones from
    ///   prior runs are not replayed, which is acceptable because future
    ///   tombstones are reapplied idempotently when foreign segments
    ///   re-arrive via `pull_from`).
    /// - Builds the [`Remote`] backend (Memory / LocalFilesystem / R2).
    /// - Builds a [`CdcChunker`] from `config.chunking.avg_size`.
    /// - Builds a [`ChunkTransform`]: [`Identity`] unless
    ///   `config.encryption.enabled` is true, in which case the
    ///   passphrase is read from the `CAIRN_PASSPHRASE` env var and
    ///   combined with the salt at `config.encryption.salt_path`.
    pub fn open(config: Config, catalog_path: &Path) -> Result<Self, EngineError> {
        let key = load_or_generate_key(&config.machine)?;
        let catalog = Catalog::open(catalog_path)?;

        let state = catalog.local_chain_state()?;
        let log = if state.next_seq == 0 && state.tip == [0u8; 32] {
            MachineLog::fresh(key)
        } else {
            MachineLog::from_state(key, state.next_seq, state.tip, state.last_hlc)
        };

        let projection = rebuild_projection_from_catalog(&catalog, &log)?;
        let remote = build_remote(&config.remote)?;
        let chunker = CdcChunker::from_avg_size(config.chunking.avg_size);
        let transform = build_transform(&config.encryption)?;

        Ok(Self {
            config,
            catalog,
            log,
            projection,
            remote,
            chunker,
            transform,
        })
    }

    /// Construct directly from pre-built pieces — intended for tests
    /// where we want a deterministic signing key and explicit backend
    /// choices without going through the config dance.
    pub fn from_parts(
        config: Config,
        catalog: Catalog,
        signing_key: SigningKey,
        remote: Remote,
        transform: Box<dyn ChunkTransform>,
    ) -> Result<Self, EngineError> {
        let state = catalog.local_chain_state()?;
        let log = if state.next_seq == 0 && state.tip == [0u8; 32] {
            MachineLog::fresh(signing_key)
        } else {
            MachineLog::from_state(signing_key, state.next_seq, state.tip, state.last_hlc)
        };
        let projection = rebuild_projection_from_catalog(&catalog, &log)?;
        let chunker = CdcChunker::from_avg_size(config.chunking.avg_size);
        Ok(Self {
            config,
            catalog,
            log,
            projection,
            remote,
            chunker,
            transform,
        })
    }

    /// Identity of this machine.
    pub fn machine(&self) -> MachineId {
        self.log.machine()
    }

    /// Borrow the projection (intended for query code paths).
    pub fn projection(&self) -> &Projection {
        &self.projection
    }

    /// Borrow the catalog (intended for query code paths).
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Borrow the remote (intended for diagnostics / sync helpers).
    pub fn remote(&self) -> &Remote {
        &self.remote
    }

    /// Run a single full pass over every configured root.
    ///
    /// Steps, in order:
    /// 1. For each root in `config.scan_roots`: load the per-root catalog
    ///    slice, scan, append each event to the log, fold into the
    ///    projection. Accumulate catalog changes.
    /// 2. Apply the accumulated catalog changes + the fresh projection
    ///    in one redb transaction.
    /// 3. For each observed content that is not yet `backed_up`,
    ///    [`backup_content`] it to the remote, then append a `Backed`
    ///    entry to the log + fold it in.
    /// 4. Re-apply the (now Backed-flag-updated) projection.
    /// 5. If there are any pending entries (seq > catalog.last_pushed_seq),
    ///    push them as a single segment under `log/<machine>/`.
    pub async fn run_pass(&mut self) -> Result<PassSummary, EngineError> {
        let mut summary = PassSummary::default();

        let scan_config = cairn_scan::ScanConfig {
            excludes: self.config.excludes.clone(),
            ..cairn_scan::ScanConfig::default()
        };
        let scanner = cairn_scan::Scanner::new(scan_config);

        let mut catalog_changes: Vec<CatalogChange> = Vec::new();
        let mut observed_contents: HashMap<ContentHash, PathBuf> = HashMap::new();
        // Every entry we append this pass — drained at the end for push.
        let mut pending: Vec<LogEntry> = Vec::new();

        for root in self.config.scan_roots.clone() {
            let prev_entries = self
                .catalog
                .iter_catalog_under(&PathKey::from_path(&root))?;
            let prev: HashMap<PathKey, CatalogEntry> = prev_entries
                .into_iter()
                .map(|e| (e.path.clone(), e))
                .collect();

            let events = scanner.scan_root(&root, &prev).map_err(map_scan_error)?;
            summary.roots_scanned += 1;

            for event in events {
                match event {
                    cairn_scan::ScanEvent::Observed {
                        content,
                        path,
                        size,
                        mtime,
                        file_id,
                    } => {
                        summary.new_observations += 1;
                        let entry = self.log.append_observed(content, path.clone(), size, mtime);
                        self.projection.fold_entry(&entry);
                        catalog_changes.push(CatalogChange::Upsert(CatalogEntry {
                            path: path.clone(),
                            content,
                            size,
                            mtime,
                            file_id,
                            last_scan: entry.hlc,
                        }));
                        observed_contents
                            .entry(content)
                            .or_insert_with(|| path.to_path_buf());
                        pending.push(entry);
                    }
                    cairn_scan::ScanEvent::Vanished { path, last_content } => {
                        summary.vanished += 1;
                        let entry = self.log.append_vanished(path.clone(), last_content);
                        self.projection.fold_entry(&entry);
                        catalog_changes.push(CatalogChange::Delete(path));
                        pending.push(entry);
                    }
                    cairn_scan::ScanEvent::PassCompleted {
                        root,
                        files_seen,
                        bytes_seen,
                    } => {
                        summary.files_seen += files_seen;
                        summary.bytes_seen += bytes_seen;
                        let entry = self.log.append_pass_completed(root, files_seen, bytes_seen);
                        self.projection.fold_entry(&entry);
                        pending.push(entry);
                    }
                }
            }
        }

        self.commit_pass(catalog_changes)?;

        // Back up not-yet-backed contents.
        for (content, fs_path) in &observed_contents {
            let already_backed = self
                .projection
                .content_index
                .get(content)
                .map(|r| r.backed_up)
                .unwrap_or(false);
            if already_backed {
                continue;
            }
            match backup_content(
                *content,
                fs_path,
                &self.remote,
                &self.chunker,
                &*self.transform,
                self.log.current_hlc(),
            )
            .await
            {
                Ok(bsummary) => {
                    summary.contents_backed_up += 1;
                    summary.chunks_uploaded += bsummary.chunks_uploaded;
                    summary.bytes_uploaded += bsummary.bytes_uploaded;
                    let backed = self.log.append_backed(*content);
                    self.projection.fold_entry(&backed);
                    pending.push(backed);
                }
                Err(err) => {
                    warn!(content = %content, path = %fs_path.display(), error = %err, "backup failed; will retry next pass");
                }
            }
        }

        self.commit_pass(Vec::new())?;

        if !pending.is_empty() {
            let push_summary =
                push_pending_as_segment(&self.log, &self.catalog, &self.remote, pending).await?;
            summary.entries_pushed = push_summary.entries_pushed;
        }

        info!(
            roots = summary.roots_scanned,
            files = summary.files_seen,
            new = summary.new_observations,
            vanished = summary.vanished,
            backed_up = summary.contents_backed_up,
            chunks = summary.chunks_uploaded,
            pushed = summary.entries_pushed,
            "run_pass completed"
        );
        Ok(summary)
    }

    /// Restore a content's plaintext into `out_path`. Verifies the
    /// reassembled bytes' hash against the requested content before
    /// writing.
    pub async fn restore(&self, content: ContentHash, out_path: &Path) -> Result<(), EngineError> {
        restore_module::restore(content, out_path, &self.remote, &*self.transform).await
    }

    /// Verify the local machine's pushed segments end-to-end: chain
    /// continuity, per-entry hash + signature. Reports the path of any
    /// segment that failed to verify.
    pub async fn check(&self) -> Result<CheckReport, EngineError> {
        let mut report = CheckReport::default();
        let segments = self.remote.list_segments(self.log.machine()).await?;
        let mut known_tip: Option<[u8; 32]> = None;
        for seg_key in segments {
            let bytes = match self.remote.get_segment(&seg_key).await {
                Ok(b) => b,
                Err(e) => {
                    report
                        .corruption_found
                        .push(format!("{} (fetch failed): {e}", seg_key.path));
                    continue;
                }
            };
            let segment = match Segment::from_bytes(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    report
                        .corruption_found
                        .push(format!("{} (deserialize failed): {e}", seg_key.path));
                    continue;
                }
            };
            match segment.verify(known_tip) {
                Ok(()) => {
                    report.local_segments_verified += 1;
                    known_tip = Some(segment.tip_hash);
                }
                Err(e) => {
                    report
                        .corruption_found
                        .push(format!("{}: {e}", seg_key.path));
                    // Stop walking the chain after the first break — we
                    // can no longer trust subsequent tip values.
                    break;
                }
            }
        }
        Ok(report)
    }

    fn commit_pass(&mut self, catalog_changes: Vec<CatalogChange>) -> Result<(), EngineError> {
        let last_pushed_seq = self.catalog.local_chain_state()?.last_pushed_seq;
        self.catalog.apply_pass(&PassUpdates {
            catalog_changes,
            projection: self.projection.clone(),
            local_chain: LocalChainState {
                next_seq: self.log.next_seq(),
                tip: self.log.current_tip(),
                last_hlc: self.log.current_hlc(),
                last_pushed_seq,
            },
        })?;
        Ok(())
    }
}

fn map_scan_error(e: cairn_scan::ScanError) -> EngineError {
    EngineError::Remote(cairn_remote::RemoteError::Backend(e.to_string()))
}

fn build_remote(remote_cfg: &RemoteConfig) -> Result<Remote, EngineError> {
    match remote_cfg {
        RemoteConfig::Memory => Ok(Remote::memory()),
        RemoteConfig::LocalFilesystem { path } => Ok(Remote::local_filesystem(path)?),
        RemoteConfig::R2 {
            endpoint,
            bucket,
            access_key_id_env,
            secret_access_key_env,
        } => {
            let access = std::env::var(access_key_id_env).map_err(|_| {
                cairn_remote::RemoteError::Backend(format!("env var {access_key_id_env} not set"))
            })?;
            let secret = std::env::var(secret_access_key_env).map_err(|_| {
                cairn_remote::RemoteError::Backend(format!(
                    "env var {secret_access_key_env} not set"
                ))
            })?;
            Ok(Remote::r2(endpoint, bucket, &access, &secret)?)
        }
    }
}

fn build_transform(cfg: &EncryptionConfig) -> Result<Box<dyn ChunkTransform>, EngineError> {
    if !cfg.enabled {
        return Ok(Box::new(Identity));
    }
    let salt_path = cfg.salt_path.as_ref().ok_or_else(|| {
        cairn_cas::CasError::Transform("encryption.salt_path missing".to_string())
    })?;
    let salt = std::fs::read(salt_path)?;
    let passphrase = std::env::var("CAIRN_PASSPHRASE").map_err(|_| {
        cairn_cas::CasError::Transform("CAIRN_PASSPHRASE env var not set".to_string())
    })?;
    let enc = Encrypt::from_passphrase(&passphrase, &salt)?;
    Ok(Box::new(enc))
}

fn load_or_generate_key(cfg: &MachineConfig) -> Result<SigningKey, EngineError> {
    let path = match &cfg.key_path {
        Some(p) => p.clone(),
        None => {
            // Without a configured key path the engine has no place to
            // persist a key — we generate a session key and warn.
            warn!("machine.key_path is not configured; generating an ephemeral key");
            return Ok(SigningKey::from_bytes(&random_seed()));
        }
    };
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(EngineError::Cas(cairn_cas::CasError::Transform(format!(
                "machine key file at {} is {} bytes, expected 32",
                path.display(),
                bytes.len()
            ))));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    } else {
        let seed = random_seed();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, seed)?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

fn random_seed() -> [u8; 32] {
    // 32 high-entropy bytes from rand's OsRng-equivalent.
    rand::random()
}

fn rebuild_projection_from_catalog(
    catalog: &Catalog,
    log: &MachineLog,
) -> Result<Projection, EngineError> {
    let mut projection = Projection::default();

    // 1) Content records from the catalog table.
    for rec in catalog.all_content()? {
        // Insert the record; live_locations are already inside.
        let live_locations = rec.live_locations.clone();
        let content = rec.content;
        let backed_up = rec.backed_up;
        projection.content_index.insert(content, rec);
        // 2) Derive Live LocationFold entries for the live locations.
        for loc in live_locations {
            projection.location_state.insert(
                loc,
                cairn_log::LocationFold {
                    last_hlc: 0,
                    state: LocationState::Live(content),
                },
            );
        }
        let _ = backed_up;
    }

    // 3) Chain tips from sync_state (foreign) + local chain state.
    for (m, seq) in catalog.all_sync_states()? {
        projection.chain_tips.insert(
            m,
            ChainTip {
                seq,
                hash: [0u8; 32], // hash not persisted; defensive value
            },
        );
    }
    let local_state = catalog.local_chain_state()?;
    if local_state.next_seq > 0 {
        projection.chain_tips.insert(
            log.machine(),
            ChainTip {
                seq: local_state.next_seq.saturating_sub(1),
                hash: local_state.tip,
            },
        );
    }
    debug!(
        contents = projection.content_index.len(),
        locations = projection.location_state.len(),
        "rebuilt projection from catalog"
    );
    Ok(projection)
}
