//! "Verify storage integrity": re-hashes every ready file from storage and
//! compares size, SHA-256 and SHA-512 with the recorded values, to detect
//! bit rot or tampering. Runs in the background, one at a time, sharing the
//! hashing job slots with imports. Results are kept in memory (shown on the
//! admin dashboard) and logged; nothing is changed automatically.

use chrono::{DateTime, Utc};

use crate::db::queries;
use crate::hashing::hash_reader;
use crate::state::AppState;

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub running: bool,
    pub started: Option<DateTime<Utc>>,
    pub finished: Option<DateTime<Utc>>,
    pub checked: u64,
    pub total: u64,
    /// (file id, filename, problem)
    pub problems: Vec<(i64, String, String)>,
}

/// Starts a run unless one is already running. Returns false if it was.
pub fn start(st: &AppState) -> bool {
    {
        let mut r = st.integrity.lock().unwrap();
        if r.running {
            return false;
        }
        *r = Report {
            running: true,
            started: Some(Utc::now()),
            ..Default::default()
        };
    }
    let st = st.clone();
    tokio::spawn(async move {
        let _slot = st.job_slots.clone().acquire_owned().await;
        let problems = run(&st).await;
        let mut r = st.integrity.lock().unwrap();
        r.running = false;
        r.finished = Some(Utc::now());
        if problems.is_empty() {
            tracing::info!(checked = r.checked, "storage integrity check passed");
        } else {
            tracing::warn!(
                checked = r.checked,
                problems = problems.len(),
                "storage integrity check found problems"
            );
        }
        r.problems = problems;
    });
    true
}

async fn run(st: &AppState) -> Vec<(i64, String, String)> {
    let files = match queries::all_ready_files(&st.db).await {
        Ok(f) => f,
        Err(e) => return vec![(0, String::new(), format!("could not list files: {e}"))],
    };
    st.integrity.lock().unwrap().total = files.len() as u64;
    let mut problems = Vec::new();
    for f in files {
        let problem = async {
            let backend = st
                .storage
                .get(&f.storage_backend)
                .map_err(|e| e.to_string())?;
            let size = backend
                .size(&f.storage_key)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("stored file is missing")?;
            if size != f.size_bytes as u64 {
                return Err(format!("size is {size} bytes, recorded {}", f.size_bytes));
            }
            let reader = backend
                .open(&f.storage_key, 0, size)
                .await
                .map_err(|e| e.to_string())?;
            let d = hash_reader(reader).await.map_err(|e| e.to_string())?;
            if d.sha256 != f.sha256 {
                return Err("SHA-256 does not match the recorded value".into());
            }
            if f.sha512.as_deref().is_some_and(|h| h != d.sha512) {
                return Err("SHA-512 does not match the recorded value".into());
            }
            Ok::<(), String>(())
        }
        .await;
        if let Err(p) = problem {
            tracing::warn!(file_id = f.id, problem = %p, "integrity problem");
            problems.push((f.id, f.filename.clone(), p));
        }
        st.integrity.lock().unwrap().checked += 1;
    }
    problems
}
