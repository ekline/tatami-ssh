//! Bounded reads of explicitly named files (host layer).
//!
//! Protocol and key packages take bytes; this module is where paths become
//! bytes. Every read is bounded before allocation: the size is taken from
//! the **opened** file's metadata (no separate check-then-open race) and
//! the read itself stops one byte past the limit, so a file growing while
//! being read is still refused.
//!
//! Private keys additionally require, on Unix, a regular file that is not
//! accessible to group or others (`mode & 0o077 == 0`, OpenSSH's own rule
//! for host keys), checked on the opened handle; the contents land in
//! zeroizing storage. On non-Unix platforms no permission check is
//! performed; this is stated rather than emulated.

use alloc::vec::Vec;
use core::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

/// Why a file could not be read.
#[derive(Debug)]
pub enum FileError {
    /// Opening, inspecting or reading failed.
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        error: io::Error,
    },
    /// The file is larger than the caller's bound.
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The bound in bytes.
        limit: usize,
    },
    /// Not a regular file.
    NotRegularFile {
        /// The file.
        path: PathBuf,
    },
    /// A private key readable or writable by group or others.
    InsecurePermissions {
        /// The file.
        path: PathBuf,
        /// Permission bits found.
        mode: u32,
    },
}

impl FileError {
    /// Stable code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            FileError::Io { .. } => "io_error",
            FileError::TooLarge { .. } => "file_too_large",
            FileError::NotRegularFile { .. } => "not_a_regular_file",
            FileError::InsecurePermissions { .. } => "insecure_permissions",
        }
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::Io { path, error } => write!(f, "{}: {error}", path.display()),
            FileError::TooLarge { path, limit } => {
                write!(f, "{}: larger than {limit} bytes", path.display())
            }
            FileError::NotRegularFile { path } => {
                write!(f, "{}: not a regular file", path.display())
            }
            FileError::InsecurePermissions { path, mode } => write!(
                f,
                "{}: permissions {mode:04o} allow group/other access; a private key must be 0600 or stricter",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FileError {}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> FileError + '_ {
    move |error| FileError::Io {
        path: path.to_path_buf(),
        error,
    }
}

fn open_regular(path: &Path, limit: usize) -> Result<(File, std::fs::Metadata), FileError> {
    let file = File::open(path).map_err(io_err(path))?;
    let meta = file.metadata().map_err(io_err(path))?;
    if !meta.is_file() {
        return Err(FileError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if meta.len() > limit as u64 {
        return Err(FileError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok((file, meta))
}

fn read_into(path: &Path, file: File, limit: usize, buf: &mut Vec<u8>) -> Result<(), FileError> {
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    file.take(cap).read_to_end(buf).map_err(io_err(path))?;
    if buf.len() > limit {
        return Err(FileError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(())
}

/// Reads at most `limit` bytes of a regular file (for example an explicitly
/// named `known_hosts` file).
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, FileError> {
    let (file, meta) = open_regular(path, limit)?;
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0).min(limit));
    read_into(path, file, limit, &mut buf)?;
    Ok(buf)
}

/// Reads a private key file of at most `limit` bytes into zeroizing
/// storage, refusing group/other-accessible files on Unix.
#[cfg(feature = "quic-diag")]
pub fn read_private_key(
    path: &Path,
    limit: usize,
) -> Result<tatami_ssh_keys::openssh_key::Zeroizing<Vec<u8>>, FileError> {
    let (file, meta) = open_regular(path, limit)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(FileError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    // Reserve past the bound up front so the buffer never reallocates (a
    // reallocation would leave an unzeroized copy behind); `read_to_end`
    // probes with a small extra reservation only when the buffer is full.
    let mut buf = tatami_ssh_keys::openssh_key::Zeroizing::new(Vec::with_capacity(limit + 64));
    let _ = meta;
    read_into(path, file, limit, &mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(alloc::format!(
            "tatami-files-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bounded_reads() {
        let dir = temp("bounded");
        let p = dir.join("f");
        std::fs::write(&p, b"12345").unwrap();
        assert_eq!(read_bounded(&p, 5).unwrap(), b"12345");
        assert!(matches!(
            read_bounded(&p, 4),
            Err(FileError::TooLarge { limit: 4, .. })
        ));
        assert!(matches!(
            read_bounded(&dir, 10),
            Err(FileError::NotRegularFile { .. })
        ));
        assert!(matches!(
            read_bounded(&dir.join("missing"), 10),
            Err(FileError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(unix, feature = "quic-diag"))]
    #[test]
    fn private_keys_need_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("private");
        let p = dir.join("key");
        std::fs::write(&p, b"secret").unwrap();
        for (mode, ok) in [(0o600, true), (0o400, true), (0o640, false), (0o604, false)] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let r = read_private_key(&p, 100);
            assert_eq!(r.is_ok(), ok, "mode {mode:o}");
            if !ok {
                assert!(matches!(
                    r,
                    Err(FileError::InsecurePermissions { mode: m, .. }) if m == mode
                ));
            }
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_key(&p, 100).unwrap().as_slice(), b"secret");
        assert!(matches!(
            read_private_key(&p, 3),
            Err(FileError::TooLarge { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
