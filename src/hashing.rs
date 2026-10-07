//! SHA-256 and SHA-512 computed together in one streaming pass: every chunk
//! is read once and fed to both hashers, and files are never loaded whole.

use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::fsid::{FileIdentity, open_regular};

const CHUNK: usize = 1024 * 1024;

/// Size and hex digests of some content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub size: u64,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Default)]
pub struct MultiHasher {
    sha256: Sha256,
    sha512: Sha512,
    size: u64,
}

impl MultiHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.sha256.update(chunk);
        self.sha512.update(chunk);
        self.size += chunk.len() as u64;
    }

    pub fn finish(self) -> Digests {
        Digests {
            size: self.size,
            sha256: hex::encode(self.sha256.finalize()),
            sha512: hex::encode(self.sha512.finalize()),
        }
    }
}

/// Hashes a local file (blocking; call from `spawn_blocking`) through a
/// descriptor opened without following symlinks; refuses anything but a
/// single-link regular file. Fails if the file changes while being read.
/// Returns the digests and the identity of the file that was read.
pub fn hash_file(path: &Path) -> io::Result<(Digests, FileIdentity)> {
    let (mut file, before) = open_regular(path)?;
    let mut hasher = MultiHasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let after = FileIdentity::of(&file.metadata()?);
    let digests = hasher.finish();
    if !before.unchanged(&after) || digests.size != before.len {
        return Err(io::Error::other("the file changed while it was being read"));
    }
    Ok((digests, before))
}

/// Hashes everything an async reader yields (e.g. a stored object).
pub async fn hash_reader<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Digests> {
    let mut hasher = MultiHasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn known_vectors_in_any_chunking() {
        let mut h = MultiHasher::new();
        h.update(b"abc");
        let one = h.finish();
        assert_eq!(one.sha256, ABC_SHA256);
        assert_eq!(one.sha512, ABC_SHA512);
        assert_eq!(one.size, 3);

        let mut h = MultiHasher::new();
        for b in b"abc" {
            h.update(&[*b]);
        }
        assert_eq!(h.finish(), one);
    }

    #[tokio::test]
    async fn file_and_reader_agree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data: Vec<u8> = (0..(CHUNK * 2 + 17)).map(|i| (i % 253) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let (from_file, id) = hash_file(&path).unwrap();
        assert_eq!(id.len, data.len() as u64);
        let from_reader = hash_reader(&data[..]).await.unwrap();
        assert_eq!(from_file, from_reader);
        assert_eq!(from_file.size, data.len() as u64);
        assert_eq!(from_file.sha256, hex::encode(Sha256::digest(&data)));
        assert_eq!(from_file.sha512, hex::encode(Sha512::digest(&data)));
    }

    #[test]
    fn refuses_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real"), b"x").unwrap();
        std::fs::hard_link(dir.path().join("real"), dir.path().join("hard")).unwrap();
        assert!(hash_file(&dir.path().join("hard")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        assert!(hash_file(&dir.path().join("link")).is_err());
    }
}
