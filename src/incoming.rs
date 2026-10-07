//! The incoming folder (INCOMING_PATH): large files are copied there out of
//! band (rsync/scp/SMB) and then imported by the admin. This module lists
//! import candidates and validates a submitted relative path before anything
//! touches it.

use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Directory depth scanned below INCOMING_PATH (1 = files directly inside).
pub const MAX_DEPTH: usize = 3;

/// Suffixes used by copy tools for unfinished transfers.
const PARTIAL_SUFFIXES: [&str; 4] = [".part", ".partial", ".tmp", ".crdownload"];

#[derive(Debug, Clone)]
pub struct Candidate {
    /// Path relative to INCOMING_PATH, `/`-separated.
    pub rel_path: String,
    pub size: u64,
    pub modified: SystemTime,
    /// False while the file is younger than IMPORT_MIN_AGE_SECS
    /// (probably still being copied).
    pub settled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum IncomingError {
    #[error("invalid path: {0}")]
    Invalid(&'static str),
    #[error("file not found in the incoming folder")]
    NotFound,
    #[error("file was modified too recently; it may still be being copied")]
    TooNew,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// True for names that may be imported: not hidden (rsync temp files start
/// with '.') and not an unfinished-transfer suffix.
pub fn is_candidate_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.starts_with('.') && !PARTIAL_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

fn is_settled(modified: SystemTime, now: SystemTime, min_age: Duration) -> bool {
    // A modification time in the future counts as "too new".
    now.duration_since(modified).is_ok_and(|age| age >= min_age)
}

/// Lists import candidates under `root` (regular files only; symlinks,
/// hidden entries and partial transfers skipped), sorted by path.
pub fn scan(root: &Path, min_age: Duration, now: SystemTime) -> io::Result<Vec<Candidate>> {
    let mut out = Vec::new();
    scan_dir(root, "", 1, min_age, now, &mut out)?;
    out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(out)
}

fn scan_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    min_age: Duration,
    now: SystemTime,
    out: &mut Vec<Candidate>,
) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue; // non-UTF-8 names cannot round-trip through a form
        };
        if !is_candidate_name(&name) {
            continue;
        }
        // DirEntry::file_type does not follow symlinks.
        let ft = entry.file_type()?;
        let rel = format!("{prefix}{name}");
        if ft.is_dir() {
            if depth < MAX_DEPTH {
                // Unreadable subdirectories are skipped, not fatal.
                let _ = scan_dir(
                    &entry.path(),
                    &format!("{rel}/"),
                    depth + 1,
                    min_age,
                    now,
                    out,
                );
            }
        } else if ft.is_file() {
            let meta = entry.metadata()?;
            let modified = meta.modified()?;
            out.push(Candidate {
                rel_path: rel,
                size: meta.len(),
                modified,
                settled: is_settled(modified, now, min_age),
            });
        }
    }
    Ok(())
}

/// Validates a path submitted by the admin form and returns the canonical
/// absolute path of the file to import.
///
/// The path must be relative, contain only normal components (no `..`, no
/// hidden components), stay within MAX_DEPTH, name a regular file that is
/// not a symlink, and still resolve inside the canonical `root` after all
/// symlinks in parent directories are followed.
pub fn resolve(
    root: &Path,
    rel: &str,
    min_age: Duration,
    now: SystemTime,
) -> Result<PathBuf, IncomingError> {
    if rel.is_empty() || rel.contains('\0') || rel.contains('\\') {
        return Err(IncomingError::Invalid("empty or malformed path"));
    }
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() || rel.starts_with('/') {
        return Err(IncomingError::Invalid("absolute paths are not allowed"));
    }
    let mut depth = 0;
    for c in rel_path.components() {
        match c {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or(IncomingError::Invalid("non UTF-8 path"))?;
                if !is_candidate_name(part) {
                    return Err(IncomingError::Invalid(
                        "hidden or partial files cannot be imported",
                    ));
                }
                depth += 1;
            }
            _ => return Err(IncomingError::Invalid("path must not contain '..' or '.'")),
        }
    }
    if depth > MAX_DEPTH {
        return Err(IncomingError::Invalid("path is nested too deeply"));
    }

    let joined = root.join(rel_path);
    let meta = match std::fs::symlink_metadata(&joined) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(IncomingError::NotFound),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(IncomingError::Invalid("symlinks cannot be imported"));
    }
    if !meta.file_type().is_file() {
        return Err(IncomingError::Invalid("not a regular file"));
    }

    let canon_root = root.canonicalize()?;
    let canon = joined.canonicalize()?;
    if !canon.starts_with(&canon_root) {
        return Err(IncomingError::Invalid("path escapes the incoming folder"));
    }
    if !is_settled(meta.modified()?, now, min_age) {
        return Err(IncomingError::TooNew);
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const NO_AGE: Duration = Duration::ZERO;

    fn setup() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incoming");
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::write(root.join("top.iso"), b"1234").unwrap();
        fs::write(root.join("a/b/deep.img"), b"x").unwrap();
        fs::write(root.join("a/b/c/too-deep.iso"), b"x").unwrap();
        fs::write(root.join(".rsync-temp.iso.Ab12"), b"x").unwrap();
        fs::write(root.join("big.iso.part"), b"x").unwrap();
        fs::write(root.join("dl.CRDOWNLOAD"), b"x").unwrap();
        fs::create_dir_all(root.join(".rsync-partial")).unwrap();
        fs::write(root.join(".rsync-partial/x.iso"), b"x").unwrap();
        fs::write(dir.path().join("secret.txt"), b"outside").unwrap();
        dir
    }

    fn root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("incoming")
    }

    #[test]
    fn scan_lists_only_candidates() {
        let dir = setup();
        let names: Vec<_> = scan(&root(&dir), NO_AGE, SystemTime::now())
            .unwrap()
            .into_iter()
            .map(|c| c.rel_path)
            .collect();
        assert_eq!(names, vec!["a/b/deep.img", "top.iso"]);
    }

    #[test]
    fn scan_marks_recent_files_unsettled() {
        let dir = setup();
        let list = scan(&root(&dir), Duration::from_secs(3600), SystemTime::now()).unwrap();
        assert!(list.iter().all(|c| !c.settled));
        let later = SystemTime::now() + Duration::from_secs(7200);
        let list = scan(&root(&dir), Duration::from_secs(3600), later).unwrap();
        assert!(list.iter().all(|c| c.settled));
    }

    #[test]
    fn resolve_accepts_valid_paths() {
        let dir = setup();
        let r = root(&dir);
        let p = resolve(&r, "top.iso", NO_AGE, SystemTime::now()).unwrap();
        assert_eq!(p, r.canonicalize().unwrap().join("top.iso"));
        assert!(resolve(&r, "a/b/deep.img", NO_AGE, SystemTime::now()).is_ok());
    }

    #[test]
    fn resolve_rejects_traversal_and_absolute_paths() {
        let dir = setup();
        let r = root(&dir);
        let now = SystemTime::now();
        for bad in [
            "../secret.txt",
            "a/../../secret.txt",
            "./top.iso",
            "/etc/passwd",
            &dir.path().join("secret.txt").display().to_string(),
            "a\\..\\..\\secret.txt",
            "",
            "top.iso\0",
            "a/b/c/too-deep.iso",
        ] {
            assert!(
                matches!(
                    resolve(&r, bad, NO_AGE, now),
                    Err(IncomingError::Invalid(_))
                ),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn resolve_rejects_hidden_partial_and_missing() {
        let dir = setup();
        let r = root(&dir);
        let now = SystemTime::now();
        assert!(matches!(
            resolve(&r, ".rsync-temp.iso.Ab12", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        assert!(matches!(
            resolve(&r, ".rsync-partial/x.iso", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        assert!(matches!(
            resolve(&r, "big.iso.part", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        assert!(matches!(
            resolve(&r, "a", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        assert!(matches!(
            resolve(&r, "nope.iso", NO_AGE, now),
            Err(IncomingError::NotFound)
        ));
    }

    #[test]
    fn resolve_rejects_too_new_files() {
        let dir = setup();
        let r = root(&dir);
        assert!(matches!(
            resolve(&r, "top.iso", Duration::from_secs(3600), SystemTime::now()),
            Err(IncomingError::TooNew)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_symlinks_out_of_the_folder() {
        use std::os::unix::fs::symlink;
        let dir = setup();
        let r = root(&dir);
        let now = SystemTime::now();
        // A symlinked file pointing outside.
        symlink(dir.path().join("secret.txt"), r.join("link.txt")).unwrap();
        assert!(matches!(
            resolve(&r, "link.txt", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        // A symlinked directory pointing outside.
        symlink(dir.path(), r.join("escape")).unwrap();
        assert!(matches!(
            resolve(&r, "escape/secret.txt", NO_AGE, now),
            Err(IncomingError::Invalid(_))
        ));
        // Neither shows up in the scan.
        let names: Vec<_> = scan(&r, NO_AGE, now)
            .unwrap()
            .into_iter()
            .map(|c| c.rel_path)
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n.contains("link") || n.contains("escape"))
        );
    }
}
