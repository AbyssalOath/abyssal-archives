//! Local filesystem backend (also used for host-mounted network shares).
//!
//! Layout: `<root>/<first two key chars>/<key>`, with in-progress writes in
//! `<root>/.tmp/<key>.part` so a half-written object is never visible. Keys
//! must be lowercase hyphenated UUIDs, which makes path traversal impossible.
//! Directories are created 0700 and objects stored 0600 (owner only).

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use std::os::unix::fs::PermissionsExt;

use super::{ByteReader, ByteStream, StorageBackend, StorageError};
use crate::fsid::{FileIdentity, open_regular};

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Creates `dir` (and parents) as owner-only directories.
async fn make_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
        .await
}

pub struct LocalFs {
    root: PathBuf,
    /// When false, imports always copy (lets tests exercise the fallback).
    allow_rename: bool,
}

impl LocalFs {
    /// Uses `root`, creating it (and its temp dir) if needed.
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        std::os::unix::fs::DirBuilderExt::mode(
            std::fs::DirBuilder::new().recursive(true),
            DIR_MODE,
        )
        .create(root.join(".tmp"))?;
        // Best effort: the root may be a mount point owned by someone else.
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(DIR_MODE));
        Ok(Self {
            root,
            allow_rename: true,
        })
    }

    #[cfg(test)]
    fn copy_only(mut self) -> Self {
        self.allow_rename = false;
        self
    }

    fn path_for(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_key(key)?;
        Ok(self.root.join(&key[..2]).join(key))
    }

    fn temp_path(&self, key: &str) -> PathBuf {
        self.root.join(".tmp").join(format!("{key}.part"))
    }

    /// Copies the already opened, identity-checked `src_file` into place
    /// via the temp dir, verifies the size, then removes the source path if
    /// it still names the same file.
    async fn copy_in(
        &self,
        key: &str,
        src: &Path,
        src_file: std::fs::File,
        expect: FileIdentity,
        dest: &Path,
    ) -> Result<u64, StorageError> {
        let tmp = self.temp_path(key);
        let result = async {
            let mut from = fs::File::from_std(src_file);
            let mut to = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .await?;
            let copied = tokio::io::copy(&mut from, &mut to).await?;
            to.sync_all().await?;
            drop(to);
            if copied != expect.len {
                return Err(StorageError::SizeMismatch {
                    expected: expect.len,
                    actual: copied,
                });
            }
            fs::rename(&tmp, dest).await?;
            Ok(copied)
        }
        .await;
        match result {
            Ok(n) => {
                // The copy is safely stored. Remove the source only if the
                // path still names the file we copied; failing to remove it
                // just leaves a duplicate behind, so log rather than fail.
                let still_same = fs::symlink_metadata(src)
                    .await
                    .is_ok_and(|m| FileIdentity::of(&m).same_file(&expect));
                if !still_same {
                    tracing::warn!("import source was replaced after copying; left in place");
                } else if let Err(e) = fs::remove_file(src).await {
                    tracing::warn!(error = %e, "imported file copied but source could not be removed");
                }
                Ok(n)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp).await;
                Err(e)
            }
        }
    }
}

/// Accepts only canonical lowercase hyphenated UUIDs.
fn validate_key(key: &str) -> Result<(), StorageError> {
    match uuid::Uuid::parse_str(key) {
        Ok(u) if u.hyphenated().to_string() == key => Ok(()),
        _ => Err(StorageError::InvalidKey),
    }
}

fn not_found_to_none<T>(r: io::Result<T>) -> Result<Option<T>, StorageError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[async_trait]
impl StorageBackend for LocalFs {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn put(&self, key: &str, mut data: ByteStream<'_>) -> Result<u64, StorageError> {
        let dest = self.path_for(key)?;
        let tmp = self.temp_path(key);
        let result = async {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .await?;
            let mut total = 0u64;
            while let Some(chunk) = data.next().await {
                let chunk = chunk?;
                file.write_all(&chunk).await?;
                total += chunk.len() as u64;
            }
            file.sync_all().await?;
            drop(file);
            make_dir(dest.parent().expect("key path has a parent")).await?;
            fs::rename(&tmp, &dest).await?;
            Ok(total)
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_file(&tmp).await;
        }
        result
    }

    async fn import_from_path(
        &self,
        key: &str,
        src: &Path,
        expect: FileIdentity,
    ) -> Result<u64, StorageError> {
        let dest = self.path_for(key)?;
        // Open without following symlinks and check the descriptor: it must
        // be the very file that was validated and hashed.
        let src_owned = src.to_path_buf();
        let (file, ident) = tokio::task::spawn_blocking(move || open_regular(&src_owned))
            .await
            .map_err(io::Error::other)?
            .map_err(|_| StorageError::NotARegularFile)?;
        if !ident.unchanged(&expect) {
            return Err(StorageError::Changed);
        }
        make_dir(dest.parent().expect("key path has a parent")).await?;

        if self.allow_rename {
            match fs::rename(src, &dest).await {
                Ok(()) => {
                    // The renamed entry must still be that inode (a swap
                    // between the check above and the rename is caught here).
                    let m = fs::symlink_metadata(&dest).await?;
                    if !m.file_type().is_file() || !FileIdentity::of(&m).same_file(&expect) {
                        let _ = fs::remove_file(&dest).await;
                        return Err(StorageError::Changed);
                    }
                    fs::set_permissions(&dest, std::fs::Permissions::from_mode(FILE_MODE)).await?;
                    return Ok(expect.len);
                }
                // Different filesystem (or a different mount point of the same
                // one): fall back to copying from the open descriptor.
                Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.copy_in(key, src, file, expect, &dest).await
    }

    async fn open(&self, key: &str, offset: u64, len: u64) -> Result<ByteReader, StorageError> {
        let path = self.path_for(key)?;
        let mut file =
            not_found_to_none(fs::File::open(&path).await)?.ok_or(StorageError::NotFound)?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).await?;
        }
        Ok(Box::pin(file.take(len)))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.path_for(key)?;
        not_found_to_none(fs::remove_file(&path).await)?;
        Ok(())
    }

    async fn size(&self, key: &str) -> Result<Option<u64>, StorageError> {
        let path = self.path_for(key)?;
        Ok(not_found_to_none(fs::metadata(&path).await)?.map(|m| m.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::new_key;
    use bytes::Bytes;

    fn ident(path: &Path) -> FileIdentity {
        crate::fsid::open_regular(path).unwrap().1
    }

    fn any_ident() -> FileIdentity {
        FileIdentity {
            dev: 0,
            ino: 0,
            len: 0,
            mtime: 0,
            mtime_nsec: 0,
        }
    }

    #[tokio::test]
    async fn import_detects_swapped_or_modified_source() {
        let dir = tempfile::tempdir().unwrap();
        for copy in [false, true] {
            let fs = if copy {
                LocalFs::new(dir.path().join("s2")).unwrap().copy_only()
            } else {
                LocalFs::new(dir.path().join("s1")).unwrap()
            };
            // Validated file A, then the path is replaced by file B.
            let src = dir.path().join("swap.iso");
            std::fs::write(&src, b"validated").unwrap();
            let validated = ident(&src);
            let other = dir.path().join("other.iso");
            std::fs::write(&other, b"malicious").unwrap();
            std::fs::rename(&other, &src).unwrap();
            let key = new_key();
            assert!(matches!(
                fs.import_from_path(&key, &src, validated).await,
                Err(StorageError::Changed)
            ));
            assert_eq!(fs.size(&key).await.unwrap(), None, "nothing stored");
            assert!(src.exists(), "source left alone");
            // Modified in place after validation.
            let validated = ident(&src);
            std::fs::write(&src, b"malicious, longer").unwrap();
            assert!(matches!(
                fs.import_from_path(&new_key(), &src, validated).await,
                Err(StorageError::Changed)
            ));
            // Replaced by a symlink to a secret elsewhere.
            let secret = dir.path().join("secret");
            std::fs::write(&secret, b"secret").unwrap();
            std::fs::remove_file(&src).unwrap();
            std::os::unix::fs::symlink(&secret, &src).unwrap();
            assert!(
                fs.import_from_path(&new_key(), &src, ident(&secret))
                    .await
                    .is_err()
            );
            std::fs::remove_file(&src).unwrap();
        }
    }

    #[tokio::test]
    async fn stored_objects_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path().join("s")).unwrap();
        let src = dir.path().join("a.iso");
        std::fs::write(&src, b"x").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key = new_key();
        fs.import_from_path(&key, &src, ident(&src)).await.unwrap();
        let stored = dir.path().join("s").join(&key[..2]).join(&key);
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(stored.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let key2 = new_key();
        let chunks = vec![Ok(bytes::Bytes::from_static(b"up"))];
        fs.put(&key2, Box::pin(futures_util::stream::iter(chunks)))
            .await
            .unwrap();
        let stored2 = dir.path().join("s").join(&key2[..2]).join(&key2);
        assert_eq!(
            std::fs::metadata(stored2).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    async fn read_all(fs: &LocalFs, key: &str, offset: u64, len: u64) -> Vec<u8> {
        let mut out = Vec::new();
        fs.open(key, offset, len)
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        out
    }

    #[tokio::test]
    async fn put_open_range_size_delete() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path()).unwrap();
        let key = new_key();
        let chunks = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let n = fs
            .put(&key, Box::pin(futures_util::stream::iter(chunks)))
            .await
            .unwrap();
        assert_eq!(n, 11);
        assert_eq!(fs.size(&key).await.unwrap(), Some(11));
        assert!(fs.exists(&key).await.unwrap());
        assert_eq!(read_all(&fs, &key, 0, 11).await, b"hello world");
        assert_eq!(read_all(&fs, &key, 6, 3).await, b"wor");
        fs.delete(&key).await.unwrap();
        assert_eq!(fs.size(&key).await.unwrap(), None);
        fs.delete(&key).await.unwrap(); // idempotent
        assert!(matches!(
            fs.open(&key, 0, 1).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn failed_put_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path()).unwrap();
        let key = new_key();
        let chunks = vec![
            Ok(Bytes::from_static(b"partial")),
            Err(io::Error::other("client went away")),
        ];
        assert!(
            fs.put(&key, Box::pin(futures_util::stream::iter(chunks)))
                .await
                .is_err()
        );
        assert_eq!(fs.size(&key).await.unwrap(), None);
        assert_eq!(
            std::fs::read_dir(dir.path().join(".tmp")).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn rejects_non_uuid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path()).unwrap();
        for key in [
            "../etc/passwd",
            "",
            "abc",
            "/tmp/x",
            &new_key().to_uppercase(),
        ] {
            assert!(
                matches!(fs.size(key).await, Err(StorageError::InvalidKey)),
                "{key}"
            );
        }
    }

    #[tokio::test]
    async fn import_renames_on_same_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path().join("storage")).unwrap();
        let src = dir.path().join("incoming.iso");
        std::fs::write(&src, b"iso bytes").unwrap();
        let key = new_key();
        let id = ident(&src);
        assert_eq!(fs.import_from_path(&key, &src, id).await.unwrap(), 9);
        assert!(!src.exists());
        assert_eq!(read_all(&fs, &key, 0, 9).await, b"iso bytes");
    }

    #[tokio::test]
    async fn import_copy_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path().join("storage"))
            .unwrap()
            .copy_only();
        let src = dir.path().join("incoming.iso");
        let data = vec![7u8; 3 * 1024 * 1024 + 5];
        std::fs::write(&src, &data).unwrap();
        let key = new_key();
        assert_eq!(
            fs.import_from_path(&key, &src, ident(&src)).await.unwrap(),
            data.len() as u64
        );
        assert!(!src.exists(), "source removed after a verified copy");
        assert_eq!(read_all(&fs, &key, 0, data.len() as u64).await, data);
        assert_eq!(
            std::fs::read_dir(dir.path().join("storage/.tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn import_rejects_missing_and_non_files() {
        let dir = tempfile::tempdir().unwrap();
        let fs = LocalFs::new(dir.path().join("storage")).unwrap();
        assert!(
            fs.import_from_path(&new_key(), &dir.path().join("nope"), any_ident())
                .await
                .is_err()
        );
        assert!(matches!(
            fs.import_from_path(&new_key(), dir.path(), any_ident())
                .await,
            Err(StorageError::NotARegularFile)
        ));
        #[cfg(unix)]
        {
            let target = dir.path().join("real");
            std::fs::write(&target, b"x").unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(matches!(
                fs.import_from_path(&new_key(), &link, ident(&target)).await,
                Err(StorageError::NotARegularFile)
            ));
            assert!(target.exists());
        }
    }
}
