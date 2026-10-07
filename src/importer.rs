//! Imports from the incoming folder (INCOMING_PATH) into a release: one
//! file, one subfolder or everything, recorded as a batch with a result per
//! file (docs/IMPORT.md). The web "Import" buttons and the `filehost import`
//! command both go through [`queue`] and [`run`].
//!
//! * A file's path in the release is its path relative to the incoming
//!   folder (`sources/a.tar.gz`), through [`util::release_path`].
//! * A path is never overwritten. If the release already has a ready file
//!   there with the same size, the incoming file is hashed and, when the
//!   SHA-256 matches, counted as "skipped" (so reruns are safe); anything
//!   else at that path is refused. An earlier *failed* attempt at the same
//!   path is replaced.
//! * The whole batch is refused up front when its new files would cut into
//!   STORAGE_MIN_FREE_BYTES; each file is checked again right before it is
//!   copied.
//! * Files are processed one at a time (IMPORT_CONCURRENCY job slots, shared
//!   with hash recomputes), streamed, never loaded into memory, and stored
//!   byte-for-byte unless a metadata stripper applies (none exist; see
//!   docs/SANITIZE.md).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::db::models::{FileRow, item, status};
use crate::db::queries::{self, NewFile, is_unique_violation};
use crate::fsid::{FileIdentity, open_regular};
use crate::hashing::{Digests, hash_file};
use crate::incoming::{self, MAX_DEPTH};
use crate::state::AppState;
use crate::storage::{StorageBackend, new_key};
use crate::util::{human_size, release_path};

/// What to import.
pub enum Selection {
    /// One file, relative to the incoming folder.
    File(String),
    /// Every file under a folder relative to the incoming folder ("" = all).
    Folder(String),
}

/// A queued batch, ready for [`run`].
pub struct QueuedBatch {
    pub batch_id: i64,
    jobs: Vec<Job>,
    /// (path, reason) for files refused while queueing (already recorded).
    pub refused: Vec<(String, String)>,
}

impl QueuedBatch {
    /// Files that will be imported or checked for skipping.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

struct Job {
    item_id: i64,
    path: String,
    src: PathBuf,
    identity: FileIdentity,
    kind: JobKind,
    _guard: InFlightGuard,
}

enum JobKind {
    /// A new file row (status 'importing') was reserved at this path.
    Import {
        file_id: i64,
        key: String,
        filename: String,
        backend: Arc<dyn StorageBackend>,
    },
    /// A ready file of the same size is already there: hash and compare.
    VerifySkip { existing: Box<FileRow> },
}

/// One finished file, for progress output.
pub struct ItemReport<'a> {
    /// 1-based position and batch size.
    pub index: usize,
    pub total: usize,
    pub path: &'a str,
    /// [`item::DONE`], [`item::SKIPPED`] or [`item::FAILED`].
    pub status: &'static str,
    pub message: &'a str,
    pub size: u64,
}

/// Removes an in-flight marker when the job ends (even on panic).
struct InFlightGuard {
    set: Arc<Mutex<std::collections::HashSet<PathBuf>>>,
    path: PathBuf,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.path);
        }
    }
}

/// Normalizes a folder selection: no leading/trailing slashes, "." = all.
fn folder_prefix(folder: &str) -> String {
    let f = folder.trim().trim_matches('/');
    if f == "." {
        String::new()
    } else {
        f.to_string()
    }
}

/// What is already at a planned file's path in the release.
enum Existing {
    Nothing,
    /// A ready file of the same size: hash and compare (skip if equal).
    Ready(FileRow),
    /// An earlier failed attempt: removed, then imported afresh.
    Failed(FileRow),
}

/// A validated file waiting to be queued.
struct Planned {
    rel: String,
    path: String,
    src: PathBuf,
    identity: FileIdentity,
    existing: Existing,
    guard: InFlightGuard,
}

/// Validates the selection and records a batch: one item per file (refused
/// ones as failed, with the reason). Nothing is copied yet. Errors (nothing
/// recorded) when there is nothing to import or the new files would cut
/// into the free-space reserve.
pub async fn queue(
    st: &AppState,
    release_id: i64,
    user_id: Option<i64>,
    source: &str,
    selection: Selection,
) -> Result<QueuedBatch, String> {
    let root = st.config.incoming_path.clone();
    let min_age = Duration::from_secs(st.config.import_min_age_secs);
    let (folder, rels): (String, Vec<String>) = match selection {
        Selection::File(rel) => (String::new(), vec![rel]),
        Selection::Folder(folder) => {
            let prefix = folder_prefix(&folder);
            let scan_root = root.clone();
            let all = tokio::task::spawn_blocking(move || {
                incoming::scan(&scan_root, min_age, SystemTime::now())
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("Cannot read the incoming folder: {e}"))?;
            let rels = all
                .into_iter()
                .filter(|c| prefix.is_empty() || c.rel_path.starts_with(&format!("{prefix}/")))
                .map(|c| c.rel_path)
                .collect();
            (prefix, rels)
        }
    };
    if rels.is_empty() {
        return Err(if folder.is_empty() {
            "There are no files to import in the incoming folder.".into()
        } else {
            format!("There are no files to import in {folder}/.")
        });
    }

    // Validate everything first; nothing is written until the space check.
    let mut planned = Vec::new();
    let mut refused: Vec<(String, String)> = Vec::new();
    for rel in rels {
        match plan_one(st, release_id, &root, &rel, min_age).await {
            Ok(p) => planned.push(p),
            Err(msg) => refused.push((rel, msg)),
        }
    }
    let new_bytes: u64 = planned
        .iter()
        .filter(|p| !matches!(p.existing, Existing::Ready(_)))
        .map(|p| p.identity.len)
        .sum();
    crate::limits::check_free_space(
        &st.config.storage_path,
        new_bytes,
        st.config.security.storage_min_free_bytes,
    )
    .map_err(|e| format!("Import refused before copying anything. {e}"))?;

    let db_err = |e: sqlx::Error| e.to_string();
    let batch_id = queries::create_batch(&st.db, release_id, user_id, source, &folder)
        .await
        .map_err(db_err)?;
    for (rel, msg) in &refused {
        queries::add_item(&st.db, batch_id, rel, 0, item::FAILED, Some(msg), None)
            .await
            .map_err(db_err)?;
    }
    let mut jobs = Vec::new();
    for p in planned {
        let size = p.identity.len as i64;
        let kind = match p.existing {
            Existing::Ready(existing) => JobKind::VerifySkip {
                existing: Box::new(existing),
            },
            Existing::Nothing | Existing::Failed(_) => {
                if let Existing::Failed(f) = &p.existing {
                    queries::delete_file(&st.db, f.id).await.map_err(db_err)?;
                    if let Ok(b) = st.storage.get(&f.storage_backend) {
                        let _ = b.delete(&f.storage_key).await;
                    }
                }
                let backend = st.storage.active();
                let key = new_key();
                let filename = p.path.rsplit('/').next().unwrap_or(&p.path).to_string();
                let inserted = queries::insert_file(
                    &st.db,
                    &NewFile {
                        release_id,
                        filename: &filename,
                        path: &p.path,
                        size_bytes: size,
                        sha256: "",
                        sha512: None,
                        storage_backend: backend.name(),
                        storage_key: &key,
                        status: status::IMPORTING,
                    },
                )
                .await;
                match inserted {
                    Ok(file_id) => JobKind::Import {
                        file_id,
                        key,
                        filename,
                        backend,
                    },
                    Err(e) if is_unique_violation(&e) => {
                        let msg = format!("{} already exists in this release", p.path);
                        queries::add_item(
                            &st.db,
                            batch_id,
                            &p.path,
                            size,
                            item::FAILED,
                            Some(&msg),
                            None,
                        )
                        .await
                        .map_err(db_err)?;
                        refused.push((p.rel, msg));
                        continue;
                    }
                    Err(e) => return Err(e.to_string()),
                }
            }
        };
        let file_id = match &kind {
            JobKind::Import { file_id, .. } => Some(*file_id),
            JobKind::VerifySkip { .. } => None,
        };
        let item_id =
            queries::add_item(&st.db, batch_id, &p.path, size, item::QUEUED, None, file_id)
                .await
                .map_err(db_err)?;
        jobs.push(Job {
            item_id,
            path: p.path,
            src: p.src,
            identity: p.identity,
            kind,
            _guard: p.guard,
        });
    }
    if jobs.is_empty() {
        queries::finish_batch(&st.db, batch_id)
            .await
            .map_err(db_err)?;
    }
    tracing::info!(
        batch_id,
        release_id,
        files = jobs.len(),
        refused = refused.len(),
        "import batch queued"
    );
    Ok(QueuedBatch {
        batch_id,
        jobs,
        refused,
    })
}

/// Checks one incoming file; the error is the reason shown for it.
async fn plan_one(
    st: &AppState,
    release_id: i64,
    root: &Path,
    rel: &str,
    min_age: Duration,
) -> Result<Planned, String> {
    let (root_c, rel_c) = (root.to_path_buf(), rel.to_string());
    let src = tokio::task::spawn_blocking(move || {
        incoming::resolve(&root_c, &rel_c, min_age, SystemTime::now())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let path = release_path(rel, MAX_DEPTH)?;
    // Open it now (no symlinks, FIFOs or hard links) and pin its identity;
    // the job only proceeds with this exact, unmodified inode.
    let open_path = src.clone();
    let identity = tokio::task::spawn_blocking(move || open_regular(&open_path))
        .await
        .map_err(|e| e.to_string())?
        .map(|(_, id)| id)
        .map_err(|e| format!("cannot import this file: {e}"))?;
    if !st.imports_in_flight.lock().unwrap().insert(src.clone()) {
        return Err("this file is already being imported".into());
    }
    let guard = InFlightGuard {
        set: st.imports_in_flight.clone(),
        path: src.clone(),
    };
    let existing = match queries::file_at_path(&st.db, release_id, &path)
        .await
        .map_err(|e| e.to_string())?
    {
        None => Existing::Nothing,
        Some(f) if f.status == status::READY && f.size_bytes as u64 == identity.len => {
            Existing::Ready(f)
        }
        Some(f) if f.status == status::READY => {
            return Err(format!(
                "{path} already exists in this release with a different size ({} here, {} in the release). \
                 Files are never overwritten: delete it from the release first to replace it.",
                human_size(identity.len),
                human_size(f.size_bytes as u64)
            ));
        }
        // An earlier attempt that never became a file: replaced.
        Some(f) if f.status == status::FAILED => Existing::Failed(f),
        Some(_) => return Err(format!("{path} is being imported or rehashed right now")),
    };
    Ok(Planned {
        rel: rel.to_string(),
        path,
        src,
        identity,
        existing,
        guard,
    })
}

/// Processes a queued batch one file at a time and marks it finished.
/// `on_item` is called after every file (the CLI prints progress with it).
pub async fn run(st: AppState, batch: QueuedBatch, mut on_item: impl FnMut(ItemReport<'_>)) {
    let total = batch.jobs.len();
    for (n, job) in batch.jobs.into_iter().enumerate() {
        // Queue behind IMPORT_CONCURRENCY other hashing jobs.
        let _slot = st.job_slots.clone().acquire_owned().await;
        if let Err(e) = queries::set_item(&st.db, job.item_id, item::IMPORTING, None, None).await {
            tracing::error!(item_id = job.item_id, error = %e, "could not update import item");
        }
        let size = job.identity.len;
        let (state, message) = run_job(&st, &job).await;
        if let Err(e) = queries::set_item(&st.db, job.item_id, state, Some(&message), None).await {
            tracing::error!(item_id = job.item_id, error = %e, "could not record import result");
        }
        on_item(ItemReport {
            index: n + 1,
            total,
            path: &job.path,
            status: state,
            message: &message,
            size,
        });
    }
    if let Err(e) = queries::finish_batch(&st.db, batch.batch_id).await {
        tracing::error!(batch_id = batch.batch_id, error = %e, "could not finish import batch");
    }
    // New files of a published release can go to R2.
    crate::r2::wake(&st);
    tracing::info!(batch_id = batch.batch_id, "import batch finished");
}

/// Imports or skip-checks one file: (item status, message).
async fn run_job(st: &AppState, job: &Job) -> (&'static str, String) {
    match &job.kind {
        JobKind::VerifySkip { existing } => verify_skip(job, existing).await,
        JobKind::Import {
            file_id,
            key,
            filename,
            backend,
        } => {
            let id = *file_id;
            let result = match crate::limits::check_free_space(
                &st.config.storage_path,
                job.identity.len,
                st.config.security.storage_min_free_bytes,
            ) {
                Err(msg) => Err(msg),
                Ok(()) => {
                    // Stripped copies (if any) go next to the source: same
                    // filesystem, hidden from the scan by the leading dot.
                    let work_dir = job.src.parent().map(Path::to_path_buf).unwrap_or_default();
                    strip_hash_store(
                        st,
                        backend,
                        key,
                        &job.src,
                        Some(job.identity),
                        filename,
                        None,
                        &work_dir,
                    )
                    .await
                }
            };
            match result {
                Ok(d) => {
                    match queries::finish_import(&st.db, id, d.size as i64, &d.sha256, &d.sha512)
                        .await
                    {
                        Ok(true) => {
                            tracing::info!(file_id = id, size = d.size, "import finished");
                            (item::DONE, format!("imported, SHA-256 {}", d.sha256))
                        }
                        Ok(false) => {
                            // The row was deleted meanwhile; drop the orphan.
                            let _ = backend.delete(key).await;
                            (
                                item::FAILED,
                                "the file was deleted from the release during the import".into(),
                            )
                        }
                        Err(e) => (item::FAILED, format!("could not record the import: {e}")),
                    }
                }
                Err(msg) => {
                    tracing::warn!(file_id = id, error = %msg, "import failed");
                    if let Err(e) = queries::mark_failed(&st.db, id, &msg).await {
                        tracing::error!(file_id = id, error = %e, "could not mark import failed");
                    }
                    (item::FAILED, msg)
                }
            }
        }
    }
}

/// Hashes the incoming file; the same SHA-256 as the file already at that
/// path means it was imported before: skipped, and the duplicate removed
/// from the incoming folder (as an import would have).
async fn verify_skip(job: &Job, existing: &FileRow) -> (&'static str, String) {
    let src = job.src.clone();
    let hashed = tokio::task::spawn_blocking(move || hash_file(&src)).await;
    let (digests, ident) = match hashed {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return (item::FAILED, format!("reading the file failed: {e}")),
        Err(e) => return (item::FAILED, e.to_string()),
    };
    if !ident.unchanged(&job.identity) {
        return (
            item::FAILED,
            "the file changed after the import was requested".into(),
        );
    }
    if digests.sha256 != existing.sha256 {
        return (
            item::FAILED,
            format!(
                "{} already exists in this release with different content (same size, other SHA-256). \
                 Files are never overwritten: delete it from the release first to replace it.",
                job.path
            ),
        );
    }
    if let Err(e) = tokio::fs::remove_file(&job.src).await {
        tracing::warn!(error = %e, "could not remove an already imported incoming file");
    }
    (
        item::SKIPPED,
        "already imported (same SHA-256); removed from the incoming folder".into(),
    )
}

/// strip (only if STRIP_METADATA and a stripper supports the file) ->
/// hash + size (SHA-256 and SHA-512 in one pass) -> move into storage.
///
/// `src` is a local file (an incoming file, or a spooled upload); stripped
/// copies are written to `work_dir`. Returns the digests of the bytes that
/// were stored. Without a stripper the file is stored byte-for-byte.
///
/// `validated` pins the file checked when the import was requested: the
/// file hashed must be that same, unmodified inode, and storage only moves
/// the inode that was hashed (no swap between check, hash and move).
#[allow(clippy::too_many_arguments)]
pub async fn strip_hash_store(
    st: &AppState,
    backend: &Arc<dyn StorageBackend>,
    key: &str,
    src: &Path,
    validated: Option<FileIdentity>,
    filename: &str,
    mime: Option<&str>,
    work_dir: &Path,
) -> Result<Digests, String> {
    let registry = st.strippers.clone();
    let enabled = st.config.strip_metadata;
    let (src_c, name_c, mime_c, work_c) = (
        src.to_path_buf(),
        filename.to_string(),
        mime.map(str::to_string),
        work_dir.to_path_buf(),
    );
    let stripped = tokio::task::spawn_blocking(move || {
        registry.maybe_strip(enabled, &name_c, mime_c.as_deref(), &src_c, &work_c)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let to_store = stripped.clone().unwrap_or_else(|| src.to_path_buf());

    let result = async {
        let hash_path = to_store.clone();
        let (digests, hashed) = tokio::task::spawn_blocking(move || hash_file(&hash_path))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("reading the file failed: {e}"))?;
        if let Some(v) = validated
            && stripped.is_none()
            && !hashed.unchanged(&v)
        {
            return Err("the file was replaced or modified after the import was requested".into());
        }
        let stored = backend
            .import_from_path(key, &to_store, hashed)
            .await
            .map_err(|e| format!("moving into storage failed: {e}"))?;
        if stored != digests.size {
            let _ = backend.delete(key).await;
            return Err(
                "the file changed while it was being imported; copy it again and retry".into(),
            );
        }
        Ok(digests)
    }
    .await;

    if let Some(stripped) = stripped {
        // Left over only on failure (on success it was moved into storage).
        let _ = tokio::fs::remove_file(&stripped).await;
        if result.is_ok() {
            // The stripped copy replaced the original.
            let _ = tokio::fs::remove_file(src).await;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_selection_is_normalized() {
        assert_eq!(folder_prefix(""), "");
        assert_eq!(folder_prefix("."), "");
        assert_eq!(folder_prefix("/sources/"), "sources");
        assert_eq!(folder_prefix("a/b"), "a/b");
    }
}
