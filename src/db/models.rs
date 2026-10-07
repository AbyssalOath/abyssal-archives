//! Row types returned by queries.

use chrono::{NaiveDate, NaiveDateTime};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Project {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub summary: String,
    pub description_md: String,
    pub owner_id: Option<i64>,
    pub created_at: NaiveDateTime,
    /// See [`review`]; only approved projects are public.
    pub review_status: String,
    pub review_note: Option<String>,
}

/// A project as listed on the home page.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectListItem {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub summary: String,
    pub latest_version: Option<String>,
}

/// Review states of projects and releases (member content).
pub mod review {
    pub const APPROVED: &str = "approved";
    pub const PENDING: &str = "pending";
    pub const REJECTED: &str = "rejected";
}

/// User account states.
pub mod account {
    pub const ACTIVE: &str = "active";
    pub const PENDING: &str = "pending";
    pub const DISABLED: &str = "disabled";
}

/// A project as listed in the admin / member workspace.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkspaceProject {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub review_status: String,
    pub review_note: Option<String>,
    /// None for projects without an owner (deleted account).
    pub owner: Option<String>,
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Release {
    pub id: i64,
    pub project_id: i64,
    pub version: String,
    pub notes_md: String,
    pub released_at: NaiveDate,
    /// Detached ASCII-armored signature of SHA256SUMS (made off-server).
    pub sums_signature: Option<String>,
    /// SHA-256 of the SHA256SUMS content the signature was made for.
    pub sums_signed_sha256: Option<String>,
    pub sums_signed_at: Option<NaiveDateTime>,
    /// See [`review`]; only approved releases (of approved projects) are public.
    pub review_status: String,
    pub review_note: Option<String>,
}

/// File status values (the `files.status` ENUM).
pub mod status {
    pub const IMPORTING: &str = "importing";
    /// Hashes being recomputed ("Recompute hashes" in the admin).
    pub const HASHING: &str = "hashing";
    pub const READY: &str = "ready";
    pub const FAILED: &str = "failed";
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FileRow {
    pub id: i64,
    pub release_id: i64,
    pub filename: String,
    pub size_bytes: i64,
    pub sha256: String,
    /// None for rows created before SHA-512 existed (until recomputed).
    pub sha512: Option<String>,
    pub storage_backend: String,
    pub storage_key: String,
    pub download_count: i64,
    pub status: String,
    pub error_message: Option<String>,
    pub torrent_infohash: Option<String>,
    pub created_at: NaiveDateTime,
}

/// The user behind a valid (unexpired, not idle) session.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionUser {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub csrf_token: String,
    /// 1 while the second factor has not been entered yet.
    pub mfa_pending: i8,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserAuth {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub totp_enabled: i8,
    /// See [`account`].
    pub status: String,
}

/// A user as listed on /admin/users.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub status: String,
    pub signup_note: Option<String>,
    pub upload_limit_bytes: Option<i64>,
    pub storage_quota_bytes: Option<i64>,
    pub created_at: NaiveDateTime,
    pub projects: i64,
    /// Bytes stored in the user's projects (any file status).
    pub used_bytes: i64,
}

/// A member's request for a higher upload limit / storage quota.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LimitRequest {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub upload_limit_bytes: Option<i64>,
    pub storage_quota_bytes: Option<i64>,
    pub reason: String,
    /// "pending", "approved" or "denied".
    pub status: String,
    pub admin_note: Option<String>,
    pub created_at: NaiveDateTime,
}

/// Pending member content awaiting review.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReviewItem {
    /// Project id, or release id for releases.
    pub id: i64,
    pub project_id: i64,
    pub project_name: String,
    /// Empty for projects.
    pub version: String,
    pub owner: Option<String>,
    pub created_at: NaiveDateTime,
}

/// TOTP state of a user.
#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct UserTotp {
    pub totp_secret_enc: Option<Vec<u8>>,
    pub totp_enabled: i8,
    pub totp_last_step: Option<i64>,
}

#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct Stats {
    pub projects: i64,
    pub releases: i64,
    pub files: i64,
    pub bytes: i64,
    pub downloads: i64,
}

/// An admin-curated mirror of a file (`file_mirrors`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Mirror {
    pub id: i64,
    pub file_id: i64,
    pub url: String,
    pub label: String,
    /// "http" or "torrent".
    pub kind: String,
    /// "pending", "approved", "rejected" or "failed".
    pub status: String,
    /// "admin", "discovered" or "federated".
    pub source: String,
    pub last_checked_at: Option<NaiveDateTime>,
    pub last_error: Option<String>,
    pub created_at: NaiveDateTime,
}
