//! [`PathKey`]: portable, lossless path representation for Cairn's inventory.
//!
//! Paths are stored as UTF-8 [`String`]s. For valid-UTF-8 paths (the vast
//! majority on all platforms), the stored string IS the path — no escapes,
//! no transformations. For paths containing bytes that are not valid UTF-8
//! (only possible on Unix), the entire path is hex-encoded after a single
//! leading NUL byte. NUL is rejected as a filename byte by every supported
//! OS, so it is unambiguous as a discriminator.
//!
//! Normalization (case-folding on Windows/macOS, Unicode form on macOS) is
//! intentionally **not** done here. That decision needs platform-aware
//! context — same path on the same OS may compare differently between
//! Volumes — and lives in [`cairn-scan`](../../cairn_scan/index.html), which
//! has that context. Catalog comparisons and range scans use the stored
//! string's byte order; that is sufficient for prefix-based queries.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Marker character signaling that the rest of the string is hex-encoded
/// raw bytes (used only when the source path is not valid UTF-8 on Unix).
const ESCAPE_MARKER: char = '\0';

/// A portable, serde-friendly path representation.
///
/// See the [module docs](self) for the encoding contract.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PathKey(String);

impl PathKey {
    /// Create a `PathKey` from raw bytes (the Unix way: paths are bytes).
    ///
    /// Valid UTF-8 byte sequences pass through unchanged. Invalid sequences
    /// cause the whole path to be hex-encoded after a leading NUL marker.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(s) if !s.starts_with(ESCAPE_MARKER) => Self(s.to_string()),
            _ => Self(escape_bytes(bytes)),
        }
    }

    /// Create a `PathKey` from a [`Path`].
    ///
    /// On Unix this is byte-exact lossless (uses `OsStrExt::as_bytes`). On
    /// non-Unix platforms it routes through the lossy UTF-8 conversion
    /// before re-encoding; in practice all paths handled on those platforms
    /// are valid UTF-16 / WTF-8 and the conversion is lossless.
    pub fn from_path(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::from_bytes(path.as_os_str().as_bytes())
        }
        #[cfg(not(unix))]
        {
            match path.to_str() {
                Some(s) if !s.starts_with(ESCAPE_MARKER) => Self(s.to_string()),
                _ => Self::from_bytes(path.to_string_lossy().as_bytes()),
            }
        }
    }

    /// Build a `PathKey` directly from an owned `String`.
    ///
    /// Intended for round-tripping a value previously obtained from another
    /// `PathKey`; user-supplied paths should go through [`Self::from_bytes`]
    /// or [`Self::from_path`].
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// The stored string (potentially containing the NUL+hex escape).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstruct the raw bytes the `PathKey` was built from.
    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(rest) = self.0.strip_prefix(ESCAPE_MARKER) {
            decode_hex(rest)
        } else {
            self.0.as_bytes().to_vec()
        }
    }

    /// Reconstruct a [`PathBuf`]. Lossless on Unix; on other platforms the
    /// path is reconstructed from the stored UTF-8 string.
    pub fn to_path_buf(&self) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(self.to_bytes()))
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(self.0.clone())
        }
    }

    /// Byte-level `starts_with` against another `PathKey`, suitable for
    /// catalog range scans over a scan root.
    pub fn starts_with(&self, prefix: &PathKey) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// True when this `PathKey` holds an escaped (non-UTF-8) byte sequence.
    pub fn is_escaped(&self) -> bool {
        self.0.starts_with(ESCAPE_MARKER)
    }
}

impl std::fmt::Display for PathKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(rest) = self.0.strip_prefix(ESCAPE_MARKER) {
            write!(f, "<bytes:{rest}>")
        } else {
            f.write_str(&self.0)
        }
    }
}

fn escape_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(1 + bytes.len() * 2);
    s.push(ESCAPE_MARKER);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        out.push((unhex(chunk[0]) << 4) | unhex(chunk[1]));
    }
    out
}

fn hex_digit(n: u8) -> char {
    debug_assert!(n < 16);
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_passes_through_unchanged() {
        let p = PathKey::from_bytes(b"/home/user/foo.txt");
        assert_eq!(p.as_str(), "/home/user/foo.txt");
        assert!(!p.is_escaped());
    }

    #[test]
    fn utf8_with_unicode_passes_through() {
        let p = PathKey::from_bytes("hé/Ω/файл.txt".as_bytes());
        assert_eq!(p.as_str(), "hé/Ω/файл.txt");
    }

    #[test]
    #[allow(invalid_from_utf8)] // intentional: assert the literal IS invalid UTF-8
    fn non_utf8_bytes_roundtrip_losslessly() {
        let raw: &[u8] = b"/home/\xc3\x28/bad.txt"; // 0xC3 0x28 is invalid UTF-8
        assert!(std::str::from_utf8(raw).is_err());
        let p = PathKey::from_bytes(raw);
        assert!(p.is_escaped());
        assert_eq!(p.to_bytes(), raw);
    }

    #[test]
    fn escaped_display_does_not_leak_raw_bytes() {
        let p = PathKey::from_bytes(b"\xff\xfe");
        let displayed = format!("{p}");
        assert!(displayed.starts_with("<bytes:"));
        assert!(displayed.ends_with('>'));
    }

    #[test]
    fn pathbuf_roundtrip_unix() {
        let p = PathKey::from_path(Path::new("/etc/hosts"));
        assert_eq!(p.to_path_buf(), PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn starts_with_prefix_works() {
        let parent = PathKey::from_bytes(b"/home/user/");
        let child = PathKey::from_bytes(b"/home/user/sub/file.txt");
        let sibling = PathKey::from_bytes(b"/home/other/file.txt");
        assert!(child.starts_with(&parent));
        assert!(!sibling.starts_with(&parent));
    }

    #[test]
    fn postcard_roundtrip_utf8_and_non_utf8() {
        let cases = [
            PathKey::from_bytes(b"/tmp/example.txt"),
            PathKey::from_bytes(b"\x80\x81bad/\xc3\x28path"),
            PathKey::from_bytes(b""),
        ];
        for original in cases {
            let bytes = postcard::to_allocvec(&original).unwrap();
            let decoded: PathKey = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(original, decoded);
            assert_eq!(original.to_bytes(), decoded.to_bytes());
        }
    }

    #[test]
    fn ordering_is_lexicographic_on_stored_string() {
        let a = PathKey::from_bytes(b"/a");
        let b = PathKey::from_bytes(b"/b");
        assert!(a < b);
    }

    #[test]
    fn from_string_with_leading_nul_is_treated_as_escape() {
        // from_string is the raw constructor; if the input starts with NUL it
        // must be a (machine-generated) hex escape — decode accordingly.
        let p = PathKey::from_string("\0deadbeef".to_string());
        assert!(p.is_escaped());
        assert_eq!(p.to_bytes(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn empty_bytes_yields_empty_unescaped_key() {
        let p = PathKey::from_bytes(b"");
        assert_eq!(p.as_str(), "");
        assert!(!p.is_escaped());
        assert_eq!(p.to_bytes(), Vec::<u8>::new());
    }

    #[test]
    fn upper_and_lowercase_hex_decode_to_same_bytes() {
        // The decoder accepts either case — handy for human-edited tests.
        let lower = PathKey::from_string("\0deadbeef".to_string());
        let upper = PathKey::from_string("\0DEADBEEF".to_string());
        assert_eq!(lower.to_bytes(), upper.to_bytes());
    }
}
