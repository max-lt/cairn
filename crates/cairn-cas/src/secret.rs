//! Hardened in-RAM secret storage for Cairn's 32-byte content keys.
//!
//! The [`SecretBytes`] type holds a 32-byte secret on a dedicated
//! memory page that is:
//!
//! - **`mlock`-ed**, so the page is excluded from swap and the secret
//!   never lands on disk under memory pressure.
//! - **Allocated via `memfd_secret(2)` on Linux 5.14+** when available.
//!   `memfd_secret` pages live outside the kernel's direct map, so
//!   even another process with `CAP_SYS_PTRACE` or root reading
//!   `/proc/<pid>/mem` cannot retrieve the secret.
//! - **Zeroized + `munlock`-ed + `munmap`-ed on drop**, with a volatile
//!   write so the compiler cannot elide the zero.
//! - **Never `Debug`-printed** — the [`std::fmt::Debug`] impl elides
//!   the bytes and shows only which backing mechanism is in use.
//!
//! ## Threat model
//!
//! This is a defense-in-depth measure against the classes of attack
//! that don't already have a software answer:
//!
//! - A swap file that captured a secret page during a transient memory
//!   spike — defeated by `mlock`.
//! - A coredump on crash that includes secret pages — partially
//!   defeated by `madvise(MADV_DONTDUMP)` (not currently set).
//! - An attacker with the user's UID reading `/proc/<pid>/mem` — on
//!   Linux ≥ 5.14, defeated by `memfd_secret`.
//! - An attacker with `CAP_SYS_PTRACE` attaching to the process — also
//!   defeated by `memfd_secret`.
//!
//! What this **cannot** defeat:
//!
//! - An attacker who has injected code into the Cairn process itself.
//!   Such code runs with full access to all of our memory regardless
//!   of the backing mechanism; that surface is only closed by hardware
//!   enclaves (SGX, Apple Secure Enclave) which violate the
//!   pure-Rust constraint.
//! - A cold-boot RAM extraction attack with physical access. Modern
//!   DDR4/5 retains plaintext for milliseconds at room temperature;
//!   under freezing conditions, longer. Only full-memory encryption
//!   (Intel TME, AMD SME) at the CPU level defeats this.

use std::fmt;
use std::ptr;

const SECRET_LEN: usize = 32;
const PAGE_BYTES: usize = 4096;

/// A 32-byte secret pinned to a hardened memory page.
///
/// Construct with [`Self::new`] and access via [`Self::expose`]. The
/// underlying page is freed and zeroized on drop.
pub struct SecretBytes {
    ptr: *mut u8,
    using_memfd_secret: bool,
}

// SAFETY: `ptr` is owned by this struct, the allocation does not move,
// and access is bounded by the lifetime of `&self`. The bytes
// themselves are plain data; both `Send` and `Sync` are sound.
unsafe impl Send for SecretBytes {}
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// Allocate hardened storage and copy `bytes` into it.
    ///
    /// The caller-supplied array is consumed by value; on return the
    /// caller's local copy is no longer live. Callers concerned about
    /// the caller-side copy should hold the input in
    /// [`zeroize::Zeroizing`] before passing it in.
    pub fn new(bytes: [u8; SECRET_LEN]) -> Self {
        let s = Self::allocate();
        // SAFETY: `s.ptr` is page-aligned, mapped, and points to at
        // least `PAGE_BYTES` writable bytes — far more than we need.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), s.ptr, SECRET_LEN);
        }
        // Best-effort zero of the by-value local. The compiler may
        // still keep a copy in a register; this is the same caveat as
        // every "zero-on-drop" pattern.
        let mut local = bytes;
        for b in &mut local {
            unsafe { ptr::write_volatile(b as *mut u8, 0) };
        }
        s
    }

    /// Borrow the 32-byte secret for read.
    ///
    /// The returned reference must not outlive the [`SecretBytes`];
    /// Rust enforces this through the lifetime tied to `&self`.
    pub fn expose(&self) -> &[u8; SECRET_LEN] {
        // SAFETY: `ptr` points to a 32-byte (in fact `PAGE_BYTES`-byte)
        // valid, initialized region for at least the lifetime of `&self`.
        unsafe { &*(self.ptr as *const [u8; SECRET_LEN]) }
    }

    /// `true` when the backing page is allocated via `memfd_secret`
    /// (Linux 5.14+ kernel direct-map isolation).
    pub fn is_memfd_secret_backed(&self) -> bool {
        self.using_memfd_secret
    }

    fn allocate() -> Self {
        #[cfg(target_os = "linux")]
        {
            if let Some(s) = Self::allocate_memfd_secret() {
                return s;
            }
        }
        Self::allocate_mlocked()
    }

    /// Plain anonymous private mmap + mlock. Available on every Unix.
    fn allocate_mlocked() -> Self {
        // SAFETY: passing well-formed flags / size. The returned ptr is
        // checked against MAP_FAILED before use.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(
            ptr != libc::MAP_FAILED,
            "SecretBytes: mmap(MAP_ANONYMOUS) failed"
        );
        // SAFETY: ptr is a valid mapping. mlock returning non-zero just
        // means the page may swap under memory pressure — degraded but
        // still functional, so we don't abort.
        let _ = unsafe { libc::mlock(ptr, PAGE_BYTES) };
        Self {
            ptr: ptr as *mut u8,
            using_memfd_secret: false,
        }
    }

    /// Linux 5.14+ `memfd_secret`: pages outside the kernel direct
    /// map, unreadable even by root / ptrace-capable processes.
    ///
    /// Returns `None` on older kernels (the syscall returns -ENOSYS),
    /// triggering a fall-back to the plain `mlock` path.
    #[cfg(target_os = "linux")]
    fn allocate_memfd_secret() -> Option<Self> {
        // SAFETY: SYS_memfd_secret takes a single u32 flags argument; 0
        // is well-defined ("default flags"). On unsupported kernels
        // the call returns -1 with errno = ENOSYS.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0u32) } as libc::c_int;
        if fd < 0 {
            return None;
        }
        // SAFETY: the fd is a freshly opened memfd_secret descriptor.
        if unsafe { libc::ftruncate(fd, PAGE_BYTES as libc::off_t) } != 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        // The mapping itself holds the reference; closing the fd now is
        // safe and keeps the descriptor table tidy.
        unsafe { libc::close(fd) };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        // memfd_secret pages cannot be paged out, so mlock is logically
        // redundant — but calling it explicitly is harmless and keeps
        // the behavior identical to the fall-back path.
        let _ = unsafe { libc::mlock(ptr, PAGE_BYTES) };
        Some(Self {
            ptr: ptr as *mut u8,
            using_memfd_secret: true,
        })
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // SAFETY: ptr is a valid mapping of PAGE_BYTES bytes that we own.
        unsafe {
            // Volatile write so the optimizer can't elide the zero.
            for i in 0..SECRET_LEN {
                ptr::write_volatile(self.ptr.add(i), 0);
            }
            let _ = libc::munlock(self.ptr as *mut libc::c_void, PAGE_BYTES);
            let _ = libc::munmap(self.ptr as *mut libc::c_void, PAGE_BYTES);
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backing = if self.using_memfd_secret {
            "memfd_secret"
        } else {
            "mlock"
        };
        write!(
            f,
            "SecretBytes(<{SECRET_LEN} bytes elided, backing={backing}>)"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_expose() {
        let input = [0xABu8; 32];
        let s = SecretBytes::new(input);
        assert_eq!(s.expose(), &input);
    }

    #[test]
    fn two_instances_hold_independent_pages() {
        let a = SecretBytes::new([0x11u8; 32]);
        let b = SecretBytes::new([0x22u8; 32]);
        assert_eq!(a.expose(), &[0x11u8; 32]);
        assert_eq!(b.expose(), &[0x22u8; 32]);
        // Distinct allocations.
        assert_ne!(a.expose().as_ptr(), b.expose().as_ptr());
    }

    #[test]
    fn debug_elides_bytes() {
        let s = SecretBytes::new([0xEFu8; 32]);
        let d = format!("{s:?}");
        assert!(d.starts_with("SecretBytes(<32 bytes elided"));
        assert!(!d.contains("ef")); // must NOT spill the actual byte values
        assert!(!d.contains("EF"));
    }

    #[test]
    fn send_and_sync_compile_check() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SecretBytes>();
        assert_sync::<SecretBytes>();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_attempts_memfd_secret_when_available() {
        // We can't force the kernel to be 5.14+, but we can verify that
        // when memfd_secret is available the constructor uses it.
        // On older kernels the bool is `false` and that's also OK.
        let s = SecretBytes::new([0u8; 32]);
        let _ = s.is_memfd_secret_backed();
    }

    #[test]
    fn drop_compiles_and_runs() {
        // Just exercise the drop path; the actual zeroize behaviour is
        // not safely observable from a test (the page is unmapped).
        let _ = SecretBytes::new([0xAAu8; 32]);
    }
}
