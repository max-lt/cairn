//! object_store-backed remote client.
//!
//! Cairn's "remote" is whatever object store the user points at: Cloudflare
//! R2 in production, a local filesystem directory for offline testing, or
//! an in-memory store for unit tests. The [`Remote`] type hides those
//! choices behind a small surface scoped to Cairn's four kinds of objects:
//!
//! - **Chunks**: content-addressed bytes at `chunks/<chunk_id_hex>`.
//! - **Manifests**: per-file storage recipes at `manifests/<content_hash_hex>`.
//! - **Log segments**: per-machine append-only ranges at
//!   `log/<machine_id_hex>/<seq_start:020>.seg`.
//! - **Snapshots**: serialized projections at `snapshots/<state_hash_hex>`.
//!
//! Every read of a chunk **re-hashes** the returned bytes and rejects them
//! with [`RemoteError::ChunkIntegrity`] if they do not match the requested
//! [`ChunkId`]. This is the verify-on-read discipline: corrupted bytes are
//! treated as missing, never silently served.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use cairn_types::{ChunkId, ContentHash, MachineId};
use object_store::{ObjectStore, PutMode, PutPayload, path::Path as OsPath};
use tokio::sync::Mutex;
use tracing::debug;

const CHUNK_PREFIX: &str = "chunks";
const MANIFEST_PREFIX: &str = "manifests";
const LOG_PREFIX: &str = "log";
const SNAPSHOT_PREFIX: &str = "snapshots";

/// Errors produced by [`Remote`] operations.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    /// An object_store backend operation failed.
    #[error("object_store error: {0}")]
    Backend(String),
    /// A chunk's bytes did not hash to the requested [`ChunkId`].
    #[error("chunk integrity: bytes do not hash to chunk id {chunk_id}")]
    ChunkIntegrity {
        /// The expected [`ChunkId`].
        chunk_id: ChunkId,
    },
    /// A requested object was not found in the backend.
    #[error("object not found: {key}")]
    NotFound {
        /// The object key that was missing.
        key: String,
    },
    /// A segment object key did not match the expected name format.
    #[error("malformed segment key: {key}")]
    MalformedSegmentKey {
        /// The offending key.
        key: String,
    },
}

fn backend<E: std::fmt::Display, T>(r: Result<T, E>) -> Result<T, RemoteError> {
    r.map_err(|e| RemoteError::Backend(e.to_string()))
}

/// A pointer to a log segment stored in the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentKey {
    /// The machine whose chain this segment belongs to.
    pub machine: MachineId,
    /// First sequence number in the segment (inclusive).
    pub seq_start: u64,
    /// Full object_store key, e.g. `log/<hex>/<seq:020>.seg`.
    pub path: String,
}

/// The remote object-store client.
pub struct Remote {
    store: Arc<dyn ObjectStore>,
    /// Some backends (notably the in-memory and local-FS ones) do not
    /// support conditional `if_absent` puts, and chunk uploads from the
    /// same process can race against themselves. We serialize the
    /// head-then-put dance behind this mutex for safety; the critical
    /// section is short.
    write_gate: Mutex<()>,
}

impl Remote {
    /// In-memory backend (volatile; for tests).
    pub fn memory() -> Self {
        Self {
            store: Arc::new(object_store::memory::InMemory::new()),
            write_gate: Mutex::new(()),
        }
    }

    /// Local-filesystem backend, hosting objects under `root`. The
    /// directory must already exist.
    pub fn local_filesystem(root: &Path) -> Result<Self, RemoteError> {
        let store = backend(object_store::local::LocalFileSystem::new_with_prefix(root))?;
        Ok(Self {
            store: Arc::new(store),
            write_gate: Mutex::new(()),
        })
    }

    /// Cloudflare R2 (reached via the S3-compatible backend).
    pub fn r2(
        endpoint: &str,
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Self, RemoteError> {
        let store = backend(
            object_store::aws::AmazonS3Builder::new()
                .with_endpoint(endpoint)
                .with_bucket_name(bucket)
                .with_access_key_id(access_key_id)
                .with_secret_access_key(secret_access_key)
                // R2 is region-agnostic but the AWS SDK still expects one;
                // "auto" works for R2.
                .with_region("auto")
                .build(),
        )?;
        Ok(Self {
            store: Arc::new(store),
            write_gate: Mutex::new(()),
        })
    }

    /// Wrap an already-constructed `ObjectStore` (useful for tests that
    /// want to inject a custom backend).
    pub fn with_store(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            write_gate: Mutex::new(()),
        }
    }

    // ----- Chunks --------------------------------------------------------

    /// Object key for a chunk.
    pub fn chunk_path(id: ChunkId) -> String {
        format!("{CHUNK_PREFIX}/{id}")
    }

    /// True if a chunk with this id exists in the remote.
    pub async fn has_chunk(&self, id: ChunkId) -> Result<bool, RemoteError> {
        head_exists(&*self.store, &Self::chunk_path(id)).await
    }

    /// Upload chunk bytes if they are not already present. Repeated calls
    /// with the same id are no-ops.
    pub async fn put_chunk_if_absent(&self, id: ChunkId, bytes: Bytes) -> Result<(), RemoteError> {
        let path = Self::chunk_path(id);
        put_if_absent(&self.write_gate, &*self.store, &path, bytes).await
    }

    /// Fetch chunk bytes and re-hash them against `id`. Returns
    /// [`RemoteError::ChunkIntegrity`] on mismatch.
    pub async fn get_chunk(&self, id: ChunkId) -> Result<Bytes, RemoteError> {
        let path = Self::chunk_path(id);
        let bytes = fetch(&*self.store, &path).await?;
        let computed = ChunkId::from_data(&bytes);
        if computed != id {
            return Err(RemoteError::ChunkIntegrity { chunk_id: id });
        }
        Ok(bytes)
    }

    // ----- Manifests -----------------------------------------------------

    /// Object key for a manifest.
    pub fn manifest_path(content: ContentHash) -> String {
        format!("{MANIFEST_PREFIX}/{content}")
    }

    /// Upload a manifest's bytes if not already present.
    pub async fn put_manifest_if_absent(
        &self,
        content: ContentHash,
        bytes: Bytes,
    ) -> Result<(), RemoteError> {
        let path = Self::manifest_path(content);
        put_if_absent(&self.write_gate, &*self.store, &path, bytes).await
    }

    /// Fetch a manifest's raw bytes (caller deserializes + version-checks).
    pub async fn get_manifest(&self, content: ContentHash) -> Result<Bytes, RemoteError> {
        let path = Self::manifest_path(content);
        fetch(&*self.store, &path).await
    }

    // ----- Log segments --------------------------------------------------

    /// Object key for a segment by `(machine, seq_start)`.
    pub fn segment_path(machine: MachineId, seq_start: u64) -> String {
        format!("{LOG_PREFIX}/{machine}/{seq_start:020}.seg")
    }

    /// Write a segment under this machine's `log/<machine>/` prefix and
    /// return the resulting [`SegmentKey`].
    pub async fn put_segment(
        &self,
        machine: MachineId,
        seq_start: u64,
        bytes: Bytes,
    ) -> Result<SegmentKey, RemoteError> {
        let path = Self::segment_path(machine, seq_start);
        let os_path = parse_os_path(&path)?;
        backend(
            self.store
                .put_opts(&os_path, PutPayload::from(bytes), PutMode::Overwrite.into())
                .await,
        )?;
        debug!(key = %path, "put segment");
        Ok(SegmentKey {
            machine,
            seq_start,
            path,
        })
    }

    /// List every segment for a machine, sorted by `seq_start` ascending.
    pub async fn list_segments(&self, machine: MachineId) -> Result<Vec<SegmentKey>, RemoteError> {
        let prefix = format!("{LOG_PREFIX}/{machine}/");
        let os_prefix = parse_os_path(&prefix)?;
        let mut stream = self.store.list(Some(&os_prefix));
        let mut out = Vec::new();
        use futures_util::StreamExt;
        while let Some(item) = stream.next().await {
            let meta = backend(item)?;
            let key = meta.location.to_string();
            let parsed = parse_segment_key(&key)?;
            // The list filter is by prefix, but be defensive: only return
            // segments whose parsed machine matches.
            if parsed.machine == machine {
                out.push(parsed);
            }
        }
        out.sort_by_key(|s| s.seq_start);
        Ok(out)
    }

    /// Fetch a segment's raw bytes by its [`SegmentKey`].
    pub async fn get_segment(&self, key: &SegmentKey) -> Result<Bytes, RemoteError> {
        fetch(&*self.store, &key.path).await
    }

    /// Discover every machine that has ever pushed a segment to this remote.
    pub async fn list_machines(&self) -> Result<Vec<MachineId>, RemoteError> {
        let prefix = parse_os_path(&format!("{LOG_PREFIX}/"))?;
        let mut stream = self.store.list(Some(&prefix));
        use futures_util::StreamExt;
        let mut machines = std::collections::BTreeSet::new();
        while let Some(item) = stream.next().await {
            let meta = backend(item)?;
            let key = meta.location.to_string();
            if let Some(rest) = key
                .strip_prefix(LOG_PREFIX)
                .and_then(|s| s.strip_prefix('/'))
                && let Some((hex, _)) = rest.split_once('/')
                && let Some(bytes) = decode_hex_32(hex)
            {
                machines.insert(MachineId::from(bytes));
            }
        }
        Ok(machines.into_iter().collect())
    }

    // ----- Snapshots -----------------------------------------------------

    /// Object key for a snapshot.
    pub fn snapshot_path(state_hash: [u8; 32]) -> String {
        let mut s = String::with_capacity(SNAPSHOT_PREFIX.len() + 1 + 64);
        s.push_str(SNAPSHOT_PREFIX);
        s.push('/');
        for b in state_hash {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Upload snapshot bytes (overwrites any existing object at the key,
    /// which is fine because snapshots are content-addressed).
    pub async fn put_snapshot(
        &self,
        state_hash: [u8; 32],
        bytes: Bytes,
    ) -> Result<(), RemoteError> {
        let path = Self::snapshot_path(state_hash);
        let os_path = parse_os_path(&path)?;
        backend(self.store.put(&os_path, PutPayload::from(bytes)).await)?;
        Ok(())
    }

    /// Fetch snapshot bytes.
    pub async fn get_snapshot(&self, state_hash: [u8; 32]) -> Result<Bytes, RemoteError> {
        let path = Self::snapshot_path(state_hash);
        fetch(&*self.store, &path).await
    }
}

async fn head_exists(store: &dyn ObjectStore, key: &str) -> Result<bool, RemoteError> {
    let os_path = parse_os_path(key)?;
    match store.head(&os_path).await {
        Ok(_) => Ok(true),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(RemoteError::Backend(e.to_string())),
    }
}

async fn put_if_absent(
    gate: &Mutex<()>,
    store: &dyn ObjectStore,
    key: &str,
    bytes: Bytes,
) -> Result<(), RemoteError> {
    let _guard = gate.lock().await;
    if head_exists(store, key).await? {
        debug!(key, "put_if_absent: already present, skipping");
        return Ok(());
    }
    let os_path = parse_os_path(key)?;
    backend(store.put(&os_path, PutPayload::from(bytes)).await)?;
    debug!(key, "put_if_absent: uploaded");
    Ok(())
}

async fn fetch(store: &dyn ObjectStore, key: &str) -> Result<Bytes, RemoteError> {
    let os_path = parse_os_path(key)?;
    match store.get(&os_path).await {
        Ok(result) => {
            let bytes = backend(result.bytes().await)?;
            Ok(bytes)
        }
        Err(object_store::Error::NotFound { .. }) => Err(RemoteError::NotFound {
            key: key.to_string(),
        }),
        Err(e) => Err(RemoteError::Backend(e.to_string())),
    }
}

fn parse_os_path(key: &str) -> Result<OsPath, RemoteError> {
    OsPath::parse(key).map_err(|e| RemoteError::Backend(e.to_string()))
}

fn parse_segment_key(key: &str) -> Result<SegmentKey, RemoteError> {
    // Expect: log/<machine_hex>/<seq_start:020>.seg
    let rest = key
        .strip_prefix(LOG_PREFIX)
        .and_then(|s| s.strip_prefix('/'));
    let rest = match rest {
        Some(r) => r,
        None => {
            return Err(RemoteError::MalformedSegmentKey {
                key: key.to_string(),
            });
        }
    };
    let (machine_hex, file) =
        rest.split_once('/')
            .ok_or_else(|| RemoteError::MalformedSegmentKey {
                key: key.to_string(),
            })?;
    let seq_str = file
        .strip_suffix(".seg")
        .ok_or_else(|| RemoteError::MalformedSegmentKey {
            key: key.to_string(),
        })?;
    let seq_start: u64 = seq_str
        .parse()
        .map_err(|_| RemoteError::MalformedSegmentKey {
            key: key.to_string(),
        })?;
    let machine_bytes =
        decode_hex_32(machine_hex).ok_or_else(|| RemoteError::MalformedSegmentKey {
            key: key.to_string(),
        })?;
    Ok(SegmentKey {
        machine: MachineId::from(machine_bytes),
        seq_start,
        path: key.to_string(),
    })
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(bytes[i * 2])? << 4) | hex_nibble(bytes[i * 2 + 1])?;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_types::{ChunkId, ContentHash, MachineId};

    fn machine(seed: u8) -> MachineId {
        MachineId::from([seed; 32])
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn chunk_round_trip_in_memory() {
        rt().block_on(async {
            let remote = Remote::memory();
            let bytes = Bytes::from_static(b"chunk-bytes");
            let id = ChunkId::from_data(&bytes);
            assert!(!remote.has_chunk(id).await.unwrap());
            remote.put_chunk_if_absent(id, bytes.clone()).await.unwrap();
            assert!(remote.has_chunk(id).await.unwrap());
            let got = remote.get_chunk(id).await.unwrap();
            assert_eq!(got, bytes);
        });
    }

    #[test]
    fn put_chunk_if_absent_is_idempotent() {
        rt().block_on(async {
            let remote = Remote::memory();
            let bytes = Bytes::from_static(b"once-and-only-once");
            let id = ChunkId::from_data(&bytes);
            remote.put_chunk_if_absent(id, bytes.clone()).await.unwrap();
            // Second call must not error and must not duplicate.
            remote.put_chunk_if_absent(id, bytes.clone()).await.unwrap();
            assert!(remote.has_chunk(id).await.unwrap());
            assert_eq!(remote.get_chunk(id).await.unwrap(), bytes);
        });
    }

    #[test]
    fn get_chunk_rejects_corrupted_bytes() {
        rt().block_on(async {
            let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
            let remote = Remote::with_store(store.clone());
            let id = ChunkId::from_data(b"the right bytes");
            // Inject WRONG bytes under the chunk's key.
            let key = Remote::chunk_path(id);
            let os_path = parse_os_path(&key).unwrap();
            store
                .put(
                    &os_path,
                    PutPayload::from(Bytes::from_static(b"different bytes")),
                )
                .await
                .unwrap();

            // get_chunk re-hashes; bytes don't match → integrity error.
            let err = remote.get_chunk(id).await.unwrap_err();
            assert!(matches!(err, RemoteError::ChunkIntegrity { .. }));
        });
    }

    #[test]
    fn manifest_round_trip() {
        rt().block_on(async {
            let remote = Remote::memory();
            let content = ContentHash::from_data(b"file content");
            let manifest_bytes = Bytes::from_static(b"manifest-postcard-bytes");
            remote
                .put_manifest_if_absent(content, manifest_bytes.clone())
                .await
                .unwrap();
            let got = remote.get_manifest(content).await.unwrap();
            assert_eq!(got, manifest_bytes);
        });
    }

    #[test]
    fn snapshot_round_trip() {
        rt().block_on(async {
            let remote = Remote::memory();
            let hash = [7u8; 32];
            let bytes = Bytes::from_static(b"snapshot-bytes");
            remote.put_snapshot(hash, bytes.clone()).await.unwrap();
            let got = remote.get_snapshot(hash).await.unwrap();
            assert_eq!(got, bytes);
        });
    }

    #[test]
    fn list_segments_returns_in_sequence_order() {
        rt().block_on(async {
            let remote = Remote::memory();
            let m = machine(1);
            // Write out of order to exercise the sort.
            remote
                .put_segment(m, 42, Bytes::from_static(b"42"))
                .await
                .unwrap();
            remote
                .put_segment(m, 0, Bytes::from_static(b"0"))
                .await
                .unwrap();
            remote
                .put_segment(m, 7, Bytes::from_static(b"7"))
                .await
                .unwrap();
            let segs = remote.list_segments(m).await.unwrap();
            let seqs: Vec<u64> = segs.iter().map(|s| s.seq_start).collect();
            assert_eq!(seqs, vec![0, 7, 42]);
        });
    }

    #[test]
    fn list_segments_filters_by_machine() {
        rt().block_on(async {
            let remote = Remote::memory();
            let m1 = machine(1);
            let m2 = machine(2);
            remote
                .put_segment(m1, 0, Bytes::from_static(b"m1-0"))
                .await
                .unwrap();
            remote
                .put_segment(m2, 0, Bytes::from_static(b"m2-0"))
                .await
                .unwrap();
            let s1 = remote.list_segments(m1).await.unwrap();
            assert_eq!(s1.len(), 1);
            assert_eq!(s1[0].machine, m1);
        });
    }

    #[test]
    fn get_segment_round_trip() {
        rt().block_on(async {
            let remote = Remote::memory();
            let m = machine(1);
            let payload = Bytes::from_static(b"segment-postcard-bytes");
            let key = remote.put_segment(m, 5, payload.clone()).await.unwrap();
            let got = remote.get_segment(&key).await.unwrap();
            assert_eq!(got, payload);
        });
    }

    #[test]
    fn not_found_for_missing_chunk() {
        rt().block_on(async {
            let remote = Remote::memory();
            let id = ChunkId::from_data(b"never uploaded");
            let err = remote.get_chunk(id).await.unwrap_err();
            assert!(matches!(err, RemoteError::NotFound { .. }));
        });
    }

    #[test]
    fn round_trip_on_local_filesystem() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let remote = Remote::local_filesystem(dir.path()).unwrap();
            let bytes = Bytes::from_static(b"local-fs-chunk");
            let id = ChunkId::from_data(&bytes);
            remote.put_chunk_if_absent(id, bytes.clone()).await.unwrap();
            assert!(remote.has_chunk(id).await.unwrap());
            assert_eq!(remote.get_chunk(id).await.unwrap(), bytes);
        });
    }

    #[test]
    fn parse_segment_key_round_trip() {
        let m = machine(0xab);
        let key = Remote::segment_path(m, 12345);
        let parsed = parse_segment_key(&key).unwrap();
        assert_eq!(parsed.machine, m);
        assert_eq!(parsed.seq_start, 12345);
        assert_eq!(parsed.path, key);
    }

    #[test]
    fn parse_segment_key_rejects_bad_input() {
        assert!(parse_segment_key("not-a-segment-key").is_err());
        assert!(parse_segment_key("log/abc/0.seg").is_err());
        assert!(parse_segment_key("log/").is_err());
    }
}
