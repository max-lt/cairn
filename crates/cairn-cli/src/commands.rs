//! CLI subcommand handlers.
//!
//! Each `run_*` function loads the config, opens an [`Engine`], and
//! performs the requested operation. They print to stdout with simple,
//! human-friendly formatting; callers that want machine-readable output
//! can re-export the underlying engine types directly.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use cairn_engine::{Engine, dry_run_retention, gc_confirm};
use cairn_log::LocationState;
use cairn_types::{Config, ContentHash, PathKey};

/// Decode either a 64-char hex content hash or, otherwise, look the path
/// up in the catalog's reverse index to find the content currently at
/// that path.
fn resolve_target_to_content(engine: &Engine, target: &str) -> Result<ContentHash> {
    if let Some(hash) = parse_hex_content_hash(target) {
        return Ok(hash);
    }
    let path = PathKey::from_path(Path::new(target));
    match engine.catalog().resolve_path(&path)? {
        Some(hash) => Ok(hash),
        None => Err(anyhow!(
            "no content found for path {target:?} (not in catalog or already vanished)"
        )),
    }
}

fn parse_hex_content_hash(s: &str) -> Option<ContentHash> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(ContentHash::from(out))
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn load_config(path: &Path) -> Result<Config> {
    Config::load_from(path).with_context(|| format!("loading config from {}", path.display()))
}

fn open_engine(config_path: &Path, catalog_path: &Path) -> Result<Engine> {
    let config = load_config(config_path)?;
    Engine::open(config, catalog_path).context("opening engine")
}

pub async fn run_scan(config_path: &Path, catalog_path: &Path) -> Result<()> {
    let mut engine = open_engine(config_path, catalog_path)?;
    let summary = engine.run_pass().await.context("run_pass failed")?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "Scan complete:")?;
    writeln!(out, "  roots scanned:        {}", summary.roots_scanned)?;
    writeln!(out, "  files seen:           {}", summary.files_seen)?;
    writeln!(out, "  bytes seen:           {}", summary.bytes_seen)?;
    writeln!(out, "  new observations:     {}", summary.new_observations)?;
    writeln!(out, "  vanished:             {}", summary.vanished)?;
    writeln!(
        out,
        "  contents backed up:   {}",
        summary.contents_backed_up
    )?;
    writeln!(out, "  chunks uploaded:      {}", summary.chunks_uploaded)?;
    writeln!(out, "  bytes uploaded:       {}", summary.bytes_uploaded)?;
    writeln!(out, "  log entries pushed:   {}", summary.entries_pushed)?;
    Ok(())
}

pub async fn run_status(config_path: &Path, catalog_path: &Path) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let p = engine.projection();
    let dups = p.duplicates().count();
    let orphans = p.orphans().count();
    let total_contents = p.content_index.len();
    let live_locations: usize = p
        .content_index
        .values()
        .map(|r| r.live_locations.len())
        .sum();
    let total_bytes: u64 = p
        .content_index
        .values()
        .filter(|r| r.backed_up)
        .map(|r| r.size)
        .sum();
    let mut out = std::io::stdout().lock();
    writeln!(out, "Cairn status (machine {})", engine.machine())?;
    writeln!(out, "  contents indexed:     {total_contents}")?;
    writeln!(out, "  live locations:       {live_locations}")?;
    writeln!(out, "  duplicates:           {dups}")?;
    writeln!(out, "  orphans (backed up):  {orphans}")?;
    writeln!(out, "  total backed bytes:   {total_bytes}")?;
    if !p.pass_stats.is_empty() {
        writeln!(out, "  last passes:")?;
        for (root, stats) in &p.pass_stats {
            writeln!(
                out,
                "    {}  files={}, bytes={}",
                root, stats.files_seen, stats.bytes_seen
            )?;
        }
    }
    Ok(())
}

pub async fn run_dupes(config_path: &Path, catalog_path: &Path) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let mut out = std::io::stdout().lock();
    let mut any = false;
    for rec in engine.projection().duplicates() {
        any = true;
        writeln!(out, "{} ({} bytes)", rec.content, rec.size)?;
        for loc in &rec.live_locations {
            writeln!(out, "  {} @ {}", loc.machine, loc.path)?;
        }
    }
    if !any {
        writeln!(out, "(no duplicates)")?;
    }
    Ok(())
}

pub async fn run_orphans(config_path: &Path, catalog_path: &Path) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let mut out = std::io::stdout().lock();
    let mut any = false;
    for rec in engine.projection().orphans() {
        any = true;
        writeln!(out, "{} ({} bytes)", rec.content, rec.size)?;
    }
    if !any {
        writeln!(out, "(no orphans)")?;
    }
    Ok(())
}

pub async fn run_locate(config_path: &Path, catalog_path: &Path, target: &str) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let content = resolve_target_to_content(&engine, target)?;
    let mut out = std::io::stdout().lock();
    let p = engine.projection();
    writeln!(out, "content {content}")?;
    if let Some(rec) = p.content_index.get(&content) {
        writeln!(out, "  size: {} bytes", rec.size)?;
        writeln!(out, "  backed_up: {}", rec.backed_up)?;
    }
    writeln!(out, "  locations:")?;
    let mut any = false;
    for (loc, fold) in p.all_locations_of(content) {
        any = true;
        let state = match &fold.state {
            LocationState::Live(_) => "live",
            LocationState::Tombstoned(_) => "tombstoned",
        };
        writeln!(
            out,
            "    [{state}] {} @ {} (hlc={})",
            loc.machine, loc.path, fold.last_hlc
        )?;
    }
    if !any {
        writeln!(out, "    (no locations recorded)")?;
    }
    Ok(())
}

pub async fn run_restore(
    config_path: &Path,
    catalog_path: &Path,
    target: &str,
    out_path: &Path,
) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let content = resolve_target_to_content(&engine, target)?;
    engine
        .restore(content, out_path)
        .await
        .with_context(|| format!("restoring content {content} to {}", out_path.display()))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "restored {content} → {}", out_path.display())?;
    Ok(())
}

pub async fn run_check(config_path: &Path, catalog_path: &Path) -> Result<()> {
    let engine = open_engine(config_path, catalog_path)?;
    let report = engine.check().await.context("check failed")?;
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "verified {} segment(s) for this machine",
        report.local_segments_verified
    )?;
    if report.corruption_found.is_empty() {
        writeln!(out, "no corruption found")?;
    } else {
        writeln!(out, "corruption:")?;
        for s in &report.corruption_found {
            writeln!(out, "  {s}")?;
        }
    }
    Ok(())
}

pub async fn run_gc(
    config_path: &Path,
    catalog_path: &Path,
    retain_after_secs: Option<u64>,
    confirm: bool,
) -> Result<()> {
    let config = load_config(config_path)?;
    let engine = Engine::open(config.clone(), catalog_path).context("opening engine")?;
    let retain = retain_after_secs
        .or(config.retention.retain_after_secs)
        .ok_or_else(|| {
            anyhow!("no retention.retain_after_secs configured or passed via --retain-after-secs")
        })?;

    let now_hlc = engine
        .projection()
        .chain_tips
        .values()
        .map(|t| t.seq)
        .max()
        .unwrap_or(0);
    // We use the current wall-clock HLC as "now" since chain_tips don't
    // store HLCs. Better: use HybridClock::current() from the engine; we
    // don't expose that today, so fall back to system time in nanos.
    let now_hlc = now_hlc.max(wall_clock_nanos());

    let plan = dry_run_retention(engine.projection(), now_hlc, retain);
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{} retention candidate(s) ({}s threshold):",
        plan.candidates.len(),
        retain
    )?;
    for c in &plan.candidates {
        writeln!(out, "  {} (age {} s)", c.content, c.age_ns / 1_000_000_000)?;
    }
    if !confirm {
        writeln!(out, "(dry-run; pass --confirm to delete remote manifests)")?;
        return Ok(());
    }
    let contents: Vec<_> = plan.candidates.iter().map(|c| c.content).collect();
    let deleted = gc_confirm(&contents, engine.remote()).await?;
    writeln!(out, "deleted manifests for {} content(s)", deleted.len())?;
    Ok(())
}

fn wall_clock_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_types::Config;

    #[test]
    fn parse_hex_content_hash_accepts_lowercase() {
        let s = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";
        let h = parse_hex_content_hash(s).unwrap();
        assert_eq!(h.to_string(), s);
    }

    #[test]
    fn parse_hex_content_hash_rejects_wrong_length() {
        assert!(parse_hex_content_hash("abcd").is_none());
        assert!(parse_hex_content_hash(&"f".repeat(63)).is_none());
    }

    #[test]
    fn parse_hex_content_hash_rejects_non_hex() {
        assert!(parse_hex_content_hash(&"z".repeat(64)).is_none());
    }

    #[test]
    fn config_round_trips_through_toml() {
        // Validates the TOML parsing that the CLI relies on.
        let toml = r#"
            scan_roots = ["/home/user/docs"]
            excludes = ["**/node_modules"]

            [chunking]
            avg_size = 1048576

            [machine]
            key_path = "/etc/cairn/key"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.scan_roots.len(), 1);
        assert_eq!(cfg.excludes, vec!["**/node_modules".to_string()]);
        assert_eq!(cfg.chunking.avg_size, 1_048_576);
        assert_eq!(
            cfg.machine.key_path,
            Some(std::path::PathBuf::from("/etc/cairn/key"))
        );
    }
}
