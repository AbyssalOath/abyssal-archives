//! SMB backend stub. Compiled and selectable (STORAGE_BACKEND=smb) so the
//! wiring exists, but every operation fails. The practical route today is to
//! mount the share on the host (CIFS) and use the local backend; see
//! docs/STORAGE.md. The SMB_* variables are documented but not read yet.

use std::path::Path;

use async_trait::async_trait;

use super::{ByteReader, ByteStream, StorageBackend, StorageError};
use crate::fsid::FileIdentity;

const MSG: &str = "SMB storage backend is not implemented yet; mount the share on the host \
                   and use STORAGE_BACKEND=local (see docs/STORAGE.md)";

pub struct SmbShare;

#[async_trait]
impl StorageBackend for SmbShare {
    fn name(&self) -> &'static str {
        "smb"
    }

    async fn put(&self, _key: &str, _data: ByteStream<'_>) -> Result<u64, StorageError> {
        Err(StorageError::NotImplemented(MSG))
    }

    async fn import_from_path(
        &self,
        _key: &str,
        _src: &Path,
        _expect: FileIdentity,
    ) -> Result<u64, StorageError> {
        Err(StorageError::NotImplemented(MSG))
    }

    async fn open(&self, _key: &str, _offset: u64, _len: u64) -> Result<ByteReader, StorageError> {
        Err(StorageError::NotImplemented(MSG))
    }

    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        Err(StorageError::NotImplemented(MSG))
    }

    async fn size(&self, _key: &str) -> Result<Option<u64>, StorageError> {
        Err(StorageError::NotImplemented(MSG))
    }
}
