//! File identity pinning against check-then-use races (TOCTOU) on imports.
//!
//! A file is opened once without following symlinks (and without blocking
//! on FIFOs), checked through the open descriptor, and identified by
//! (device, inode). Later steps verify they are still looking at that same
//! inode, so swapping the path for another file or a symlink in between is
//! detected instead of acted upon.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
}

impl FileIdentity {
    pub fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
        }
    }

    /// Same inode on the same device.
    pub fn same_file(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// Same inode, and neither size nor modification time changed.
    pub fn unchanged(&self, other: &Self) -> bool {
        self == other
    }
}

/// Opens `path` read-only with O_NOFOLLOW | O_NONBLOCK and checks the open
/// descriptor: a regular file with exactly one link (a hard link could
/// expose a file from outside the incoming folder).
pub fn open_regular(path: &Path) -> io::Result<(File, FileIdentity)> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .map_err(|e| {
            if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                io::Error::other("symlinks are refused")
            } else {
                e
            }
        })?;
    let m = file.metadata()?;
    if !m.file_type().is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    if m.nlink() != 1 {
        return Err(io::Error::other("hard-linked files are refused"));
    }
    Ok((file, FileIdentity::of(&m)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.iso");
        std::fs::write(&f, b"x").unwrap();
        let (_, id) = open_regular(&f).unwrap();
        assert_eq!(id.len, 1);

        std::os::unix::fs::symlink(&f, dir.path().join("link")).unwrap();
        assert!(open_regular(&dir.path().join("link")).is_err(), "symlink");

        std::fs::hard_link(&f, dir.path().join("hard")).unwrap();
        assert!(open_regular(&f).is_err(), "hard link (nlink 2)");

        assert!(open_regular(dir.path()).is_err(), "directory");

        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(
            open_regular(&fifo).is_err(),
            "FIFO refused without blocking"
        );
    }

    #[test]
    fn identity_detects_swaps_and_changes() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::write(&a, b"one").unwrap();
        let (_, before) = open_regular(&a).unwrap();
        // Replace the path with a different file.
        let b = dir.path().join("b");
        std::fs::write(&b, b"two").unwrap();
        std::fs::rename(&b, &a).unwrap();
        let (_, after) = open_regular(&a).unwrap();
        assert!(!before.same_file(&after));
        // Modify in place.
        let c = dir.path().join("c");
        std::fs::write(&c, b"x").unwrap();
        let (_, c1) = open_regular(&c).unwrap();
        std::fs::write(&c, b"xyz").unwrap();
        let (_, c2) = open_regular(&c).unwrap();
        assert!(c1.same_file(&c2) && !c1.unchanged(&c2));
    }
}
