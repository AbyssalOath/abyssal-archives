//! Shared application state, cloned cheaply into every handler.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use sqlx::MySqlPool;

use crate::checksums::Algo;
use crate::config::Config;
use crate::db::{self, queries};
use crate::ratelimit::{LoginLimiter, RequestLimiter, SignupLimiter};
use crate::sanitize::StripperRegistry;
use crate::settings::{self, SiteSettings};
use crate::storage::StorageRegistry;
use crate::util;

#[derive(Clone)]
pub struct AppState {
    pub db: MySqlPool,
    pub config: Arc<Config>,
    site: Arc<RwLock<SiteSettings>>,
    pub storage: Arc<StorageRegistry>,
    pub login_limiter: Arc<LoginLimiter>,
    /// Account requests per IP (/register).
    pub signup_limiter: Arc<SignupLimiter>,
    /// Concurrent downloads (DOWNLOAD_MAX_CONCURRENT / _PER_IP).
    pub downloads: Arc<crate::limits::Limiter>,
    /// Background hashing jobs (imports, recomputes, integrity checks)
    /// allowed to run at once (IMPORT_CONCURRENCY); others queue.
    pub job_slots: Arc<tokio::sync::Semaphore>,
    /// Last / running storage integrity check.
    pub integrity: Arc<Mutex<crate::integrity::Report>>,
    /// Per-IP request budget (RATE_LIMIT_PER_MINUTE).
    pub request_limiter: Arc<RequestLimiter>,
    /// Canonical incoming paths with an import in flight (no double imports).
    pub imports_in_flight: Arc<Mutex<HashSet<PathBuf>>>,
    /// Mirror ids with a Verify running (shown in the admin, no duplicates).
    pub verifying: Arc<Mutex<HashSet<i64>>>,
    /// Metadata strippers (none yet; see src/sanitize.rs).
    pub strippers: Arc<StripperRegistry>,
    /// Short content hash of the stylesheet, used for cache busting.
    pub css_version: Arc<str>,
}

impl AppState {
    /// Connects to the database, migrates, syncs settings and opens storage.
    pub async fn init(config: Config) -> anyhow::Result<Self> {
        let db = db::connect_and_migrate(&config.database_url).await?;
        let (failed, rehashed) = queries::recover_interrupted_jobs(&db).await?;
        if failed > 0 {
            tracing::warn!(
                count = failed,
                "marked imports interrupted by restart as failed"
            );
        }
        if rehashed > 0 {
            tracing::warn!(
                count = rehashed,
                "hash recomputes interrupted by restart; files left as they were"
            );
        }
        let site = settings::sync_from_env(&db, &config).await?;
        let storage = StorageRegistry::from_config(&config).map_err(|e| {
            anyhow::anyhow!(
                "cannot use STORAGE_PATH {}: {e}",
                config.storage_path.display()
            )
        })?;
        if !config.incoming_path.is_dir() {
            tracing::warn!(path = %config.incoming_path.display(), "INCOMING_PATH does not exist; imports are unavailable until it does");
        }
        let rate_limit = config.security.rate_limit_per_minute;
        let sec = config.security.clone();
        spawn_session_cleanup(db.clone(), config.security.session_idle.as_secs());
        Ok(Self {
            db,
            config: Arc::new(config),
            site: Arc::new(RwLock::new(site)),
            storage: Arc::new(storage),
            login_limiter: Arc::new(LoginLimiter::default()),
            signup_limiter: Arc::new(SignupLimiter::default()),
            request_limiter: Arc::new(RequestLimiter::new(rate_limit)),
            // Downloads are counted per real client (behind a proxy too), so
            // nothing is exempt here.
            downloads: Arc::new(crate::limits::Limiter::new(
                sec.download_max_concurrent,
                sec.download_max_per_ip,
                Vec::new(),
            )),
            job_slots: Arc::new(tokio::sync::Semaphore::new(sec.import_concurrency)),
            integrity: Arc::new(Mutex::new(crate::integrity::Report::default())),
            imports_in_flight: Arc::new(Mutex::new(HashSet::new())),
            strippers: Arc::new(StripperRegistry::new()),
            verifying: Arc::new(Mutex::new(HashSet::new())),
            css_version: util::sha256_hex(crate::routes::public::STYLE_CSS.as_bytes())[..12].into(),
        })
    }

    pub fn site(&self) -> SiteSettings {
        self.site.read().unwrap().clone()
    }

    pub fn set_site(&self, s: SiteSettings) {
        *self.site.write().unwrap() = s;
    }

    /// The one helper every template link goes through:
    /// `{DOWNLOAD_BASE_URL}/download/{id}`, or `/download/{id}` when blank.
    pub fn download_url(&self, file_id: i64) -> String {
        util::build_download_url(&self.site.read().unwrap().download_base_url, file_id)
    }

    /// Per-file checksum link, e.g. `/download/7/sha256`.
    pub fn checksum_url(&self, file_id: i64, algo: Algo) -> String {
        let suffix = match algo {
            Algo::Sha256 => "sha256",
            Algo::Sha512 => "sha512",
        };
        format!("{}/{suffix}", self.download_url(file_id))
    }

    /// Absolute URL for a torrent's BEP 19 web seed (needs DOWNLOAD_BASE_URL
    /// or PUBLIC_URL to be set).
    pub fn download_url_for_torrent(&self, file_id: i64) -> Option<String> {
        util::build_torrent_web_seed_url(
            &self.site.read().unwrap().download_base_url,
            self.config.public_url.as_deref(),
            file_id,
        )
    }
}

/// Purges expired and idle sessions every 10 minutes.
fn spawn_session_cleanup(db: MySqlPool, idle_secs: u64) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            match queries::delete_expired_sessions(&db, idle_secs).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(count = n, "expired sessions purged"),
                Err(e) => tracing::warn!(error = %e, "session cleanup failed"),
            }
        }
    });
}
