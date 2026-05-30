//! [`Config`]: TOML-backed configuration for a Cairn machine.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::TypesError;

/// Default target average chunk size in bytes (1 MiB).
///
/// FastCDC's min/max are derived from this at a fixed 1:4:16 ratio in
/// [`cairn-cas`](../../cairn_cas/index.html). **CDC parameters must not
/// change after first deployment**: doing so would shift chunk boundaries
/// and silently destroy deduplication of pre-existing content.
pub const DEFAULT_CHUNK_AVG_SIZE: u32 = 1 << 20;

/// Top-level Cairn configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Roots to scan. Each is scanned independently; paths under different
    /// roots are tracked as distinct [`Location`](crate::Location)s.
    #[serde(default)]
    pub scan_roots: Vec<PathBuf>,
    /// Additional `.gitignore`-style exclude patterns.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// Where the remote object store lives, and how to authenticate.
    #[serde(default)]
    pub remote: RemoteConfig,
    /// Chunking parameters. Frozen at first deployment.
    #[serde(default)]
    pub chunking: ChunkingConfig,
    /// Client-side encryption configuration (off by default).
    #[serde(default)]
    pub encryption: EncryptionConfig,
    /// Per-machine identity configuration.
    #[serde(default)]
    pub machine: MachineConfig,
    /// Retention policy for remote orphans.
    #[serde(default)]
    pub retention: RetentionConfig,
}

impl Config {
    /// Load a `Config` from a TOML file path.
    pub fn load_from(path: &Path) -> Result<Self, TypesError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Serialize this `Config` to a TOML string.
    pub fn to_toml(&self) -> Result<String, TypesError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

/// Where the remote object store lives, and how to authenticate.
///
/// The `Memory` and `LocalFilesystem` variants exist to support tests and
/// offline usage; production deployments use `R2`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum RemoteConfig {
    /// In-memory store. Volatile, used for tests.
    #[default]
    Memory,
    /// Local filesystem `object_store` backend.
    LocalFilesystem {
        /// Directory hosting the object hierarchy.
        path: PathBuf,
    },
    /// Cloudflare R2 (reached via the S3-compatible backend).
    R2 {
        /// R2 endpoint URL.
        endpoint: String,
        /// Bucket name.
        bucket: String,
        /// Name of an environment variable holding the access key id.
        access_key_id_env: String,
        /// Name of an environment variable holding the secret access key.
        secret_access_key_env: String,
    },
}

/// CDC chunking parameters. **Frozen at first deployment**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkingConfig {
    /// Target average chunk size in bytes. Min and max are derived at a
    /// fixed 1:4:16 ratio inside [`cairn-cas`](../../cairn_cas/index.html).
    pub avg_size: u32,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            avg_size: DEFAULT_CHUNK_AVG_SIZE,
        }
    }
}

/// Client-side encryption configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Whether to encrypt chunks before upload.
    pub enabled: bool,
    /// Path to the file holding (or to be created with) the KDF salt.
    pub salt_path: Option<PathBuf>,
}

/// Per-machine identity configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Path to the file holding (or to be created with) the ed25519 signing
    /// key for this machine.
    pub key_path: Option<PathBuf>,
}

/// Retention policy for remote orphans.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Seconds since the last live location vanished before a content blob
    /// becomes a deletion candidate. `None` disables retention reporting.
    /// Cairn *never* deletes remote blobs without an explicit operator
    /// confirmation step (see `cairn gc --confirm`).
    pub retain_after_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip_via_toml() {
        let c = Config::default();
        let s = c.to_toml().unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn parses_minimal_toml_with_defaults() {
        let s = r#"
            scan_roots = ["/home/user/docs"]
        "#;
        let c: Config = toml::from_str(s).unwrap();
        assert_eq!(c.scan_roots, vec![PathBuf::from("/home/user/docs")]);
        assert_eq!(c.excludes, Vec::<String>::new());
        assert_eq!(c.chunking.avg_size, DEFAULT_CHUNK_AVG_SIZE);
        assert_eq!(c.remote, RemoteConfig::Memory);
        assert!(!c.encryption.enabled);
        assert!(c.retention.retain_after_secs.is_none());
    }

    #[test]
    fn parses_r2_remote() {
        let s = r#"
            [remote]
            backend = "r2"
            endpoint = "https://example.r2.cloudflarestorage.com"
            bucket = "cairn-prod"
            access_key_id_env = "R2_ACCESS_KEY_ID"
            secret_access_key_env = "R2_SECRET_ACCESS_KEY"
        "#;
        let c: Config = toml::from_str(s).unwrap();
        match c.remote {
            RemoteConfig::R2 {
                endpoint,
                bucket,
                access_key_id_env,
                secret_access_key_env,
            } => {
                assert!(endpoint.contains("r2.cloudflarestorage.com"));
                assert_eq!(bucket, "cairn-prod");
                assert_eq!(access_key_id_env, "R2_ACCESS_KEY_ID");
                assert_eq!(secret_access_key_env, "R2_SECRET_ACCESS_KEY");
            }
            _ => panic!("expected R2 backend"),
        }
    }

    #[test]
    fn parses_local_filesystem_remote() {
        let s = r#"
            [remote]
            backend = "local_filesystem"
            path = "/var/cairn/remote"
        "#;
        let c: Config = toml::from_str(s).unwrap();
        match c.remote {
            RemoteConfig::LocalFilesystem { path } => {
                assert_eq!(path, PathBuf::from("/var/cairn/remote"));
            }
            _ => panic!("expected LocalFilesystem backend"),
        }
    }

    #[test]
    fn parses_chunking_encryption_retention_sections() {
        let s = r#"
            [chunking]
            avg_size = 524288

            [encryption]
            enabled = true
            salt_path = "/etc/cairn/salt"

            [retention]
            retain_after_secs = 2592000

            [machine]
            key_path = "/etc/cairn/key"
        "#;
        let c: Config = toml::from_str(s).unwrap();
        assert_eq!(c.chunking.avg_size, 524_288);
        assert!(c.encryption.enabled);
        assert_eq!(
            c.encryption.salt_path,
            Some(PathBuf::from("/etc/cairn/salt"))
        );
        assert_eq!(c.retention.retain_after_secs, Some(2_592_000));
        assert_eq!(c.machine.key_path, Some(PathBuf::from("/etc/cairn/key")));
    }

    #[test]
    fn load_from_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cairn.toml");
        let original = Config {
            scan_roots: vec![PathBuf::from("/x"), PathBuf::from("/y")],
            excludes: vec!["**/node_modules".to_string(), "**/.git".to_string()],
            ..Config::default()
        };
        std::fs::write(&path, original.to_toml().unwrap()).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(original, loaded);
    }

    #[test]
    fn load_from_missing_file_returns_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.toml");
        let err = Config::load_from(&path).unwrap_err();
        assert!(matches!(err, TypesError::Io(_)));
    }

    #[test]
    fn load_from_malformed_toml_returns_toml_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is = not = valid TOML\n").unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(matches!(err, TypesError::TomlDe(_)));
    }
}
