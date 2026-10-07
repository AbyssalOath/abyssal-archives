//! Metadata stripping: STUB. OFF by default (STRIP_METADATA=false) and the
//! registry contains no strippers yet, so every file is stored byte-for-byte.
//!
//! Pipeline when a stripper applies: strip -> hash + size -> store, so the
//! published checksums always describe the stored (stripped) bytes.
//!
//! Disk images, archives and executables are NEVER passed to a stripper,
//! whatever it claims to support: modifying them breaks upstream checksums
//! and signatures and can break boot structures. See docs/SANITIZE.md.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    #[error("metadata stripping failed: {0}")]
    Failed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A metadata remover for one family of formats (e.g. JPEG/PNG EXIF, PDF
/// document info).
pub trait MetadataStripper: Send + Sync {
    /// Short name for logs.
    fn name(&self) -> &'static str;

    /// True if this stripper handles the file, judged by its (sanitized)
    /// filename and, when known, its MIME type.
    fn supports(&self, filename: &str, mime: Option<&str>) -> bool;

    /// Writes a copy of `input_path` without metadata to `output_path`.
    /// Must not modify the input.
    fn strip(&self, input_path: &Path, output_path: &Path) -> Result<(), SanitizeError>;
}

/// Extensions that are never modified, regardless of any stripper.
const NEVER_MODIFY_EXT: &[&str] = &[
    "iso", "img", "bin", "raw", "dmg", "vhd", "vhdx", "vmdk", "qcow2", "ova", "wim", "esd", "exe",
    "msi", "dll", "so", "elf", "appimage", "deb", "rpm", "apk", "pkg", "snap", "flatpak", "zip",
    "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzma", "cab", "efi", "sig", "asc",
    "gpg", "torrent",
];

/// True for files that must pass through byte-for-byte unchanged.
pub fn is_never_modified(filename: &str, mime: Option<&str>) -> bool {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    // No extension: unknown content, leave it alone.
    ext.is_empty()
        || NEVER_MODIFY_EXT.contains(&ext.as_str())
        || mime.is_some_and(|m| {
            let m = m.to_ascii_lowercase();
            m == "application/octet-stream"
                || m.starts_with("application/x-iso9660")
                || m.contains("executable")
                || m.contains("compressed")
                || m.contains("zip")
                || m.contains("x-tar")
        })
}

/// The installed strippers. Currently empty.
#[derive(Default)]
pub struct StripperRegistry {
    strippers: Vec<Box<dyn MetadataStripper>>,
}

impl StripperRegistry {
    /// The registry used by the app: no implementations yet.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with(stripper: Box<dyn MetadataStripper>) -> Self {
        Self {
            strippers: vec![stripper],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.strippers.is_empty()
    }

    /// The stripper to use for a file, if stripping is allowed for it.
    pub fn find(&self, filename: &str, mime: Option<&str>) -> Option<&dyn MetadataStripper> {
        if is_never_modified(filename, mime) {
            return None;
        }
        self.strippers
            .iter()
            .find(|s| s.supports(filename, mime))
            .map(|s| s.as_ref())
    }

    /// Runs a stripper over `input` when `enabled` (STRIP_METADATA) and one
    /// supports the file. Returns the path of the stripped copy (created in
    /// `work_dir`), or None when the input is to be stored unchanged.
    pub fn maybe_strip(
        &self,
        enabled: bool,
        filename: &str,
        mime: Option<&str>,
        input: &Path,
        work_dir: &Path,
    ) -> Result<Option<PathBuf>, SanitizeError> {
        if !enabled {
            return Ok(None);
        }
        let Some(stripper) = self.find(filename, mime) else {
            return Ok(None);
        };
        let output = work_dir.join(format!(".strip-{}", uuid::Uuid::new_v4()));
        if let Err(e) = stripper.strip(input, &output) {
            let _ = std::fs::remove_file(&output);
            return Err(e);
        }
        tracing::info!(
            stripper = stripper.name(),
            file = filename,
            "metadata stripped"
        );
        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claims to support everything; "strips" by uppercasing.
    struct Greedy;
    impl MetadataStripper for Greedy {
        fn name(&self) -> &'static str {
            "greedy"
        }
        fn supports(&self, _: &str, _: Option<&str>) -> bool {
            true
        }
        fn strip(&self, input: &Path, output: &Path) -> Result<(), SanitizeError> {
            let data = std::fs::read(input)?;
            std::fs::write(output, data.to_ascii_uppercase())?;
            Ok(())
        }
    }

    #[test]
    fn binaries_are_never_modified() {
        for name in [
            "distro.iso",
            "disk.IMG",
            "fw.bin",
            "setup.exe",
            "src.tar.gz",
            "noext",
        ] {
            assert!(is_never_modified(name, None), "{name}");
        }
        assert!(is_never_modified(
            "photo.jpg",
            Some("application/octet-stream")
        ));
        assert!(!is_never_modified("photo.jpg", Some("image/jpeg")));
        assert!(!is_never_modified("doc.pdf", None));
        let r = StripperRegistry::with(Box::new(Greedy));
        assert!(r.find("distro.iso", None).is_none());
        assert!(r.find("photo.jpg", Some("image/jpeg")).is_some());
    }

    #[test]
    fn app_registry_is_empty_and_passes_through() {
        let r = StripperRegistry::new();
        assert!(r.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("photo.jpg");
        std::fs::write(&input, b"exif").unwrap();
        assert!(
            r.maybe_strip(true, "photo.jpg", None, &input, dir.path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn disabled_means_untouched_even_with_a_stripper() {
        let r = StripperRegistry::with(Box::new(Greedy));
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"keep me").unwrap();
        assert!(
            r.maybe_strip(false, "notes.txt", None, &input, dir.path())
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(&input).unwrap(), b"keep me");
    }

    #[test]
    fn enabled_stripper_writes_a_separate_output() {
        let r = StripperRegistry::with(Box::new(Greedy));
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"keep me").unwrap();
        let out = r
            .maybe_strip(true, "notes.txt", Some("text/plain"), &input, dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"KEEP ME");
        assert_eq!(std::fs::read(&input).unwrap(), b"keep me");
        // ISOs pass through even when enabled.
        let iso = dir.path().join("distro.iso");
        std::fs::write(&iso, b"iso").unwrap();
        assert!(
            r.maybe_strip(true, "distro.iso", None, &iso, dir.path())
                .unwrap()
                .is_none()
        );
    }
}
