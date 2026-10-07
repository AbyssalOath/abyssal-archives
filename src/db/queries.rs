//! All SQL lives here, grouped by table.

// Only the fixed FILE_COLUMNS constant is ever formatted into SQL; all
// values are bound parameters.
use sqlx::{AssertSqlSafe, MySqlPool, Result};

use super::models::*;

const RELEASE_COLUMNS: &str = "r.id, r.project_id, r.version, r.notes_md, r.released_at, \
     r.sums_signature, r.sums_signed_sha256, r.sums_signed_at, r.recommended_file_id, \
     r.review_status, r.review_note";

const FILE_COLUMNS: &str = "id, release_id, filename, path, size_bytes, sha256, sha512, storage_backend, \
     storage_key, download_count, status, error_message, torrent_infohash, created_at";

/// True if the error is a unique-key violation (duplicate slug/version).
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
}

// ---- site_settings -------------------------------------------------------

pub async fn all_settings(db: &MySqlPool) -> Result<Vec<(String, String)>> {
    sqlx::query_as("SELECT `key`, `value` FROM site_settings")
        .fetch_all(db)
        .await
}

pub async fn set_setting(db: &MySqlPool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO site_settings (`key`, `value`) VALUES (?, ?) \
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn insert_setting_if_missing(db: &MySqlPool, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT IGNORE INTO site_settings (`key`, `value`) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_setting(db: &MySqlPool, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM site_settings WHERE `key` = ?")
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}

// ---- users ---------------------------------------------------------------

pub async fn count_users(db: &MySqlPool) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
}

/// Creates the administrator only if no user exists yet; returns its id, or
/// None if someone got there first.
pub async fn create_first_admin(db: &MySqlPool, username: &str, hash: &str) -> Result<Option<i64>> {
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, role) \
         SELECT ?, ?, 'admin' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM users)",
    )
    .bind(username)
    .bind(hash)
    .execute(db)
    .await?;
    Ok((res.rows_affected() == 1).then(|| res.last_insert_id() as i64))
}

pub async fn find_user(db: &MySqlPool, username: &str) -> Result<Option<UserAuth>> {
    sqlx::query_as(
        "SELECT id, username, password_hash, role, totp_enabled, status FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(db)
    .await
}

pub async fn get_user(db: &MySqlPool, id: i64) -> Result<Option<UserAuth>> {
    sqlx::query_as(
        "SELECT id, username, password_hash, role, totp_enabled, status FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

pub async fn update_password(db: &MySqlPool, id: i64, hash: &str) -> Result<()> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(hash)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Creates a member account ('active' when an admin creates it, 'pending'
/// from /register). Fails with a unique violation if the name is taken.
pub async fn create_member(
    db: &MySqlPool,
    username: &str,
    hash: &str,
    status: &str,
    signup_note: Option<&str>,
) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, role, status, signup_note) \
         VALUES (?, ?, 'member', ?, ?)",
    )
    .bind(username)
    .bind(hash)
    .bind(status)
    .bind(signup_note)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

pub async fn count_pending_users(db: &MySqlPool) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 'pending'")
        .fetch_one(db)
        .await
}

const USER_ROW: &str = "SELECT u.id, u.username, u.role, u.status, u.signup_note, \
     u.upload_limit_bytes, u.storage_quota_bytes, u.created_at, \
     (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id) AS projects, \
     (SELECT CAST(COALESCE(SUM(f.size_bytes), 0) AS SIGNED) FROM files f \
        JOIN releases r ON r.id = f.release_id JOIN projects p ON p.id = r.project_id \
        WHERE p.owner_id = u.id) AS used_bytes \
     FROM users u";

/// Every account, administrators first, then by name.
pub async fn list_users(db: &MySqlPool) -> Result<Vec<UserRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{USER_ROW} ORDER BY u.role = 'admin' DESC, u.username"
    )))
    .fetch_all(db)
    .await
}

pub async fn get_user_row(db: &MySqlPool, id: i64) -> Result<Option<UserRow>> {
    sqlx::query_as(AssertSqlSafe(format!("{USER_ROW} WHERE u.id = ?")))
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Changes a member's status (never an administrator's). True if changed.
pub async fn set_member_status(db: &MySqlPool, id: i64, status: &str) -> Result<bool> {
    let res = sqlx::query("UPDATE users SET status = ? WHERE id = ? AND role = 'member'")
        .bind(status)
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Per-member overrides; None = the site-wide default.
pub async fn set_member_limits(
    db: &MySqlPool,
    id: i64,
    upload_limit: Option<i64>,
    quota: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "UPDATE users SET upload_limit_bytes = ?, storage_quota_bytes = ? WHERE id = ? AND role = 'member'",
    )
    .bind(upload_limit)
    .bind(quota)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Deletes a member and everything they own; returns the stored objects to
/// remove. Only pending requests are deleted when `only_pending`.
pub async fn delete_member(
    db: &MySqlPool,
    id: i64,
    only_pending: bool,
) -> Result<Option<Vec<(String, String)>>> {
    let mut tx = db.begin().await?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM users WHERE id = ? AND role = 'member' FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match status {
        None => return Ok(None),
        Some(s) if only_pending && s != "pending" => return Ok(None),
        Some(_) => {}
    }
    let objects: Vec<(String, String)> = sqlx::query_as(
        "SELECT f.storage_backend, f.storage_key FROM files f \
         JOIN releases r ON r.id = f.release_id JOIN projects p ON p.id = r.project_id \
         WHERE p.owner_id = ?",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM projects WHERE owner_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(objects))
}

/// (upload limit, storage quota) overrides of a user.
pub async fn user_limits(db: &MySqlPool, id: i64) -> Result<(Option<i64>, Option<i64>)> {
    Ok(
        sqlx::query_as("SELECT upload_limit_bytes, storage_quota_bytes FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?
            .unwrap_or((None, None)),
    )
}

/// Bytes stored in a user's projects (any file status).
pub async fn used_bytes(db: &MySqlPool, user_id: i64) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(f.size_bytes), 0) AS SIGNED) FROM files f \
         JOIN releases r ON r.id = f.release_id JOIN projects p ON p.id = r.project_id \
         WHERE p.owner_id = ?",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
}

// ---- limit_requests ----------------------------------------------------------

const LIMIT_REQUEST: &str = "SELECT l.id, l.user_id, u.username, l.upload_limit_bytes, \
     l.storage_quota_bytes, l.reason, l.status, l.admin_note, l.created_at \
     FROM limit_requests l JOIN users u ON u.id = l.user_id";

pub async fn create_limit_request(
    db: &MySqlPool,
    user_id: i64,
    upload_limit: Option<i64>,
    quota: Option<i64>,
    reason: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO limit_requests (user_id, upload_limit_bytes, storage_quota_bytes, reason) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(upload_limit)
    .bind(quota)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

/// A user's most recent requests, newest first.
pub async fn limit_requests_for_user(db: &MySqlPool, user_id: i64) -> Result<Vec<LimitRequest>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{LIMIT_REQUEST} WHERE l.user_id = ? ORDER BY l.id DESC LIMIT 10"
    )))
    .bind(user_id)
    .fetch_all(db)
    .await
}

pub async fn pending_limit_requests(db: &MySqlPool) -> Result<Vec<LimitRequest>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{LIMIT_REQUEST} WHERE l.status = 'pending' ORDER BY l.id"
    )))
    .fetch_all(db)
    .await
}

pub async fn get_limit_request(db: &MySqlPool, id: i64) -> Result<Option<LimitRequest>> {
    sqlx::query_as(AssertSqlSafe(format!("{LIMIT_REQUEST} WHERE l.id = ?")))
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Approves (applying the granted values) or denies a pending request.
/// False if it was already decided.
pub async fn decide_limit_request(
    db: &MySqlPool,
    id: i64,
    approve: bool,
    granted: (Option<i64>, Option<i64>),
    note: Option<&str>,
) -> Result<bool> {
    let mut tx = db.begin().await?;
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM limit_requests WHERE id = ? AND status = 'pending' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE limit_requests SET status = ?, admin_note = ?, decided_at = NOW(), \
         upload_limit_bytes = COALESCE(?, upload_limit_bytes), \
         storage_quota_bytes = COALESCE(?, storage_quota_bytes) WHERE id = ?",
    )
    .bind(if approve { "approved" } else { "denied" })
    .bind(note)
    .bind(granted.0)
    .bind(granted.1)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if approve {
        sqlx::query(
            "UPDATE users SET upload_limit_bytes = COALESCE(?, upload_limit_bytes), \
             storage_quota_bytes = COALESCE(?, storage_quota_bytes) WHERE id = ? AND role = 'member'",
        )
        .bind(granted.0)
        .bind(granted.1)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// (pending accounts, projects + releases awaiting review, pending limit
/// requests) for the admin dashboard.
pub async fn pending_counts(db: &MySqlPool) -> Result<(i64, i64, i64)> {
    sqlx::query_as(
        "SELECT \
           (SELECT COUNT(*) FROM users WHERE status = 'pending'), \
           (SELECT COUNT(*) FROM projects WHERE review_status = 'pending') + \
           (SELECT COUNT(*) FROM releases WHERE review_status = 'pending'), \
           (SELECT COUNT(*) FROM limit_requests WHERE status = 'pending')",
    )
    .fetch_one(db)
    .await
}

// ---- TOTP and recovery codes ------------------------------------------------

pub async fn get_totp(db: &MySqlPool, user_id: i64) -> Result<UserTotp> {
    Ok(sqlx::query_as(
        "SELECT totp_secret_enc, totp_enabled, totp_last_step FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .unwrap_or_default())
}

/// Stores a new, not yet confirmed secret (2FA stays off until confirmed).
pub async fn set_pending_totp(db: &MySqlPool, user_id: i64, sealed: &[u8]) -> Result<()> {
    sqlx::query("UPDATE users SET totp_secret_enc = ?, totp_enabled = 0, totp_last_step = NULL WHERE id = ?")
        .bind(sealed)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn enable_totp(db: &MySqlPool, user_id: i64) -> Result<()> {
    sqlx::query("UPDATE users SET totp_enabled = 1 WHERE id = ? AND totp_secret_enc IS NOT NULL")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Records the time step of an accepted code. Atomic: false if that step
/// (or a later one) was already used, i.e. a replay.
pub async fn claim_totp_step(db: &MySqlPool, user_id: i64, step: i64) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
    )
    .bind(step)
    .bind(user_id)
    .bind(step)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn replace_recovery_codes(db: &MySqlPool, user_id: i64, hashes: &[String]) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for h in hashes {
        sqlx::query("INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)")
            .bind(user_id)
            .bind(h)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

/// Consumes a recovery code; false if unknown or already used.
pub async fn use_recovery_code(db: &MySqlPool, user_id: i64, hash: &str) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE user_recovery_codes SET used_at = NOW() WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(hash)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn unused_recovery_codes(db: &MySqlPool, user_id: i64) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
}

/// Turns 2FA off and forgets the secret and recovery codes. `username`
/// None = every user (the CLI recovery command).
pub async fn reset_totp(db: &MySqlPool, username: Option<&str>) -> Result<u64> {
    let ids: Vec<i64> = match username {
        Some(u) => {
            sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
                .bind(u)
                .fetch_all(db)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT id FROM users")
                .fetch_all(db)
                .await?
        }
    };
    for id in &ids {
        sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_step = NULL WHERE id = ?")
            .bind(id)
            .execute(db)
            .await?;
        sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = ?")
            .bind(id)
            .execute(db)
            .await?;
        delete_user_sessions(db, *id, None).await?;
    }
    Ok(ids.len() as u64)
}

// ---- sessions ------------------------------------------------------------

/// A new session that expires `absolute_secs` from now at the latest.
pub async fn create_session(
    db: &MySqlPool,
    id_hash: &str,
    user_id: i64,
    csrf: &str,
    absolute_secs: u64,
    mfa_pending: bool,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, csrf_token, expires_at, last_seen_at, mfa_pending) \
         VALUES (?, ?, ?, NOW() + INTERVAL ? SECOND, NOW(), ?)",
    )
    .bind(id_hash)
    .bind(user_id)
    .bind(csrf)
    .bind(absolute_secs)
    .bind(i8::from(mfa_pending))
    .execute(db)
    .await?;
    Ok(())
}

/// The session's user, unless it is past its absolute expiry or has been
/// idle for `idle_secs`.
pub async fn find_session(
    db: &MySqlPool,
    id_hash: &str,
    idle_secs: u64,
) -> Result<Option<SessionUser>> {
    sqlx::query_as(
        "SELECT u.id AS user_id, u.username, u.role, s.csrf_token, s.mfa_pending \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.id = ? AND s.expires_at > NOW() AND s.last_seen_at > NOW() - INTERVAL ? SECOND \
         AND u.status = 'active'",
    )
    .bind(id_hash)
    .bind(idle_secs)
    .fetch_optional(db)
    .await
}

/// Marks activity (at most once a minute, to keep writes low).
pub async fn touch_session(db: &MySqlPool, id_hash: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET last_seen_at = NOW() WHERE id = ? AND last_seen_at < NOW() - INTERVAL 60 SECOND")
        .bind(id_hash)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_session(db: &MySqlPool, id_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id_hash)
        .execute(db)
        .await?;
    Ok(())
}

/// Ends all of a user's sessions, optionally keeping one.
pub async fn delete_user_sessions(db: &MySqlPool, user_id: i64, keep: Option<&str>) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id <> ?")
        .bind(user_id)
        .bind(keep.unwrap_or(""))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(db: &MySqlPool, idle_secs: u64) -> Result<u64> {
    let res = sqlx::query("DELETE FROM sessions WHERE expires_at <= NOW() OR last_seen_at <= NOW() - INTERVAL ? SECOND")
        .bind(idle_secs)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

// ---- projects ------------------------------------------------------------

/// Public home page: approved projects, latest approved release.
pub async fn list_projects(db: &MySqlPool) -> Result<Vec<ProjectListItem>> {
    sqlx::query_as(
        "SELECT p.id, p.slug, p.name, p.summary, \
           (SELECT r.version FROM releases r WHERE r.project_id = p.id \
            AND r.review_status = 'approved' \
            ORDER BY r.released_at DESC, r.id DESC LIMIT 1) AS latest_version \
         FROM projects p WHERE p.review_status = 'approved' ORDER BY p.name",
    )
    .fetch_all(db)
    .await
}

/// Admin / member workspace: every project, or only `owner`'s.
pub async fn workspace_projects(
    db: &MySqlPool,
    owner: Option<i64>,
) -> Result<Vec<WorkspaceProject>> {
    sqlx::query_as(
        "SELECT p.id, p.slug, p.name, p.review_status, p.review_note, u.username AS owner, \
           (SELECT r.version FROM releases r WHERE r.project_id = p.id \
            ORDER BY r.released_at DESC, r.id DESC LIMIT 1) AS latest_version \
         FROM projects p LEFT JOIN users u ON u.id = p.owner_id \
         WHERE ? IS NULL OR p.owner_id = ? ORDER BY p.name",
    )
    .bind(owner)
    .bind(owner)
    .fetch_all(db)
    .await
}

/// Member content awaiting review: projects, then releases (oldest first).
pub async fn pending_reviews(db: &MySqlPool) -> Result<(Vec<ReviewItem>, Vec<ReviewItem>)> {
    let projects = sqlx::query_as(
        "SELECT p.id, p.id AS project_id, p.name AS project_name, '' AS version, \
         u.username AS owner, p.created_at FROM projects p LEFT JOIN users u ON u.id = p.owner_id \
         WHERE p.review_status = 'pending' ORDER BY p.id",
    )
    .fetch_all(db)
    .await?;
    let releases = sqlx::query_as(
        "SELECT r.id, p.id AS project_id, p.name AS project_name, r.version, \
         u.username AS owner, r.created_at FROM releases r JOIN projects p ON p.id = r.project_id \
         LEFT JOIN users u ON u.id = p.owner_id \
         WHERE r.review_status = 'pending' ORDER BY r.id",
    )
    .fetch_all(db)
    .await?;
    Ok((projects, releases))
}

pub async fn get_project(db: &MySqlPool, id: i64) -> Result<Option<Project>> {
    sqlx::query_as("SELECT * FROM projects WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// An approved (public) project.
pub async fn get_project_by_slug(db: &MySqlPool, slug: &str) -> Result<Option<Project>> {
    sqlx::query_as("SELECT * FROM projects WHERE slug = ? AND review_status = 'approved'")
        .bind(slug)
        .fetch_optional(db)
        .await
}

pub struct ProjectInput<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    pub summary: &'a str,
    pub description_md: &'a str,
}

pub async fn create_project(
    db: &MySqlPool,
    p: &ProjectInput<'_>,
    owner_id: i64,
    review_status: &str,
) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO projects (slug, name, summary, description_md, owner_id, review_status) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(p.slug)
    .bind(p.name)
    .bind(p.summary)
    .bind(p.description_md)
    .bind(owner_id)
    .bind(review_status)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

/// Saves a project; `review` Some(status) also resets its review (a member
/// edit going back for review).
pub async fn update_project(
    db: &MySqlPool,
    id: i64,
    p: &ProjectInput<'_>,
    review: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE projects SET slug = ?, name = ?, summary = ?, description_md = ?, \
         review_status = COALESCE(?, review_status), \
         review_note = IF(? IS NULL, review_note, NULL) WHERE id = ?",
    )
    .bind(p.slug)
    .bind(p.name)
    .bind(p.summary)
    .bind(p.description_md)
    .bind(review)
    .bind(review)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_project_review(
    db: &MySqlPool,
    id: i64,
    status: &str,
    note: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE projects SET review_status = ?, review_note = ? WHERE id = ?")
        .bind(status)
        .bind(note)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_project(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM projects WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// ---- releases ------------------------------------------------------------

/// Every release of a project (workspace).
pub async fn list_releases(db: &MySqlPool, project_id: i64) -> Result<Vec<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r \
         WHERE r.project_id = ? ORDER BY r.released_at DESC, r.id DESC"
    )))
    .bind(project_id)
    .fetch_all(db)
    .await
}

/// Approved releases of a project (public page).
pub async fn list_public_releases(db: &MySqlPool, project_id: i64) -> Result<Vec<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r WHERE r.project_id = ? \
         AND r.review_status = 'approved' ORDER BY r.released_at DESC, r.id DESC"
    )))
    .bind(project_id)
    .fetch_all(db)
    .await
}

/// A release by project slug and version, any review state (admin tools).
pub async fn find_release(db: &MySqlPool, slug: &str, version: &str) -> Result<Option<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r \
         JOIN projects p ON p.id = r.project_id WHERE p.slug = ? AND r.version = ?"
    )))
    .bind(slug)
    .bind(version)
    .fetch_optional(db)
    .await
}

/// A public (approved, of an approved project) release.
pub async fn get_release_by_slug_version(
    db: &MySqlPool,
    slug: &str,
    version: &str,
) -> Result<Option<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r \
         JOIN projects p ON p.id = r.project_id WHERE p.slug = ? AND r.version = ? \
         AND p.review_status = 'approved' AND r.review_status = 'approved'"
    )))
    .bind(slug)
    .bind(version)
    .fetch_optional(db)
    .await
}

pub async fn get_release(db: &MySqlPool, id: i64) -> Result<Option<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r WHERE r.id = ?"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

pub async fn create_release(
    db: &MySqlPool,
    project_id: i64,
    version: &str,
    notes_md: &str,
    released_at: chrono::NaiveDate,
    review_status: &str,
) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO releases (project_id, version, notes_md, released_at, review_status) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(project_id)
    .bind(version)
    .bind(notes_md)
    .bind(released_at)
    .bind(review_status)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

pub async fn update_release(
    db: &MySqlPool,
    id: i64,
    version: &str,
    notes_md: &str,
    released_at: chrono::NaiveDate,
    review: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE releases SET version = ?, notes_md = ?, released_at = ?, \
         review_status = COALESCE(?, review_status), \
         review_note = IF(? IS NULL, review_note, NULL) WHERE id = ?",
    )
    .bind(version)
    .bind(notes_md)
    .bind(released_at)
    .bind(review)
    .bind(review)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_release_review(
    db: &MySqlPool,
    id: i64,
    status: &str,
    note: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE releases SET review_status = ?, review_note = ? WHERE id = ?")
        .bind(status)
        .bind(note)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// The newest published release of a published project (by release date,
/// then creation).
pub async fn latest_public_release(db: &MySqlPool, slug: &str) -> Result<Option<Release>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RELEASE_COLUMNS} FROM releases r JOIN projects p ON p.id = r.project_id \
         WHERE p.slug = ? AND p.review_status = 'approved' AND r.review_status = 'approved' \
         ORDER BY r.released_at DESC, r.id DESC LIMIT 1"
    )))
    .bind(slug)
    .fetch_optional(db)
    .await
}

/// Marks (or with None clears) the release's recommended file; the file
/// must belong to the release.
pub async fn set_recommended(db: &MySqlPool, release_id: i64, file_id: Option<i64>) -> Result<()> {
    sqlx::query(
        "UPDATE releases SET recommended_file_id = ? WHERE id = ? \
         AND (? IS NULL OR EXISTS (SELECT 1 FROM files WHERE id = ? AND release_id = ?))",
    )
    .bind(file_id)
    .bind(release_id)
    .bind(file_id)
    .bind(file_id)
    .bind(release_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Stores (or with None clears) a release's SHA256SUMS signature.
pub async fn set_release_signature(
    db: &MySqlPool,
    id: i64,
    sig: Option<(&str, &str)>,
) -> Result<()> {
    sqlx::query(
        "UPDATE releases SET sums_signature = ?, sums_signed_sha256 = ?, \
         sums_signed_at = IF(? IS NULL, NULL, NOW()) WHERE id = ?",
    )
    .bind(sig.map(|s| s.0))
    .bind(sig.map(|s| s.1))
    .bind(sig.map(|s| s.0))
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_release(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM releases WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// ---- files ---------------------------------------------------------------

/// Ready files of every approved release of a project (public page).
pub async fn ready_files_for_project(db: &MySqlPool, project_id: i64) -> Result<Vec<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE status = 'ready' AND release_id IN \
         (SELECT id FROM releases WHERE project_id = ? AND review_status = 'approved') \
         ORDER BY filename"
    )))
    .bind(project_id)
    .fetch_all(db)
    .await
}

/// Every ready file (storage integrity check).
pub async fn all_ready_files(db: &MySqlPool) -> Result<Vec<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE status = 'ready' ORDER BY id"
    )))
    .fetch_all(db)
    .await
}

/// All files of a release, any status (admin page).
pub async fn files_for_release(db: &MySqlPool, release_id: i64) -> Result<Vec<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE release_id = ? ORDER BY path, id"
    )))
    .bind(release_id)
    .fetch_all(db)
    .await
}

pub async fn get_file(db: &MySqlPool, id: i64) -> Result<Option<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// A ready file that is public: its release and project are approved.
pub async fn get_public_file(db: &MySqlPool, id: i64) -> Result<Option<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE id = ? AND status = 'ready' AND release_id IN \
         (SELECT r.id FROM releases r JOIN projects p ON p.id = r.project_id \
          WHERE r.review_status = 'approved' AND p.review_status = 'approved')"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// A published file by its place in the tree:
/// /p/<slug>/<version>/<path>.
pub async fn get_public_file_by_path(
    db: &MySqlPool,
    slug: &str,
    version: &str,
    path: &str,
) -> Result<Option<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE path = ? AND status = 'ready' AND release_id = \
         (SELECT r.id FROM releases r JOIN projects p ON p.id = r.project_id \
          WHERE p.slug = ? AND r.version = ? \
          AND r.review_status = 'approved' AND p.review_status = 'approved')"
    )))
    .bind(path)
    .bind(slug)
    .bind(version)
    .fetch_optional(db)
    .await
}

/// The file at `path` in a release, any status.
pub async fn file_at_path(db: &MySqlPool, release_id: i64, path: &str) -> Result<Option<FileRow>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {FILE_COLUMNS} FROM files WHERE release_id = ? AND path = ?"
    )))
    .bind(release_id)
    .bind(path)
    .fetch_optional(db)
    .await
}

/// (backend, key) of every stored object under a project, for cleanup.
pub async fn objects_for_project(db: &MySqlPool, project_id: i64) -> Result<Vec<(String, String)>> {
    sqlx::query_as(
        "SELECT f.storage_backend, f.storage_key FROM files f \
         JOIN releases r ON r.id = f.release_id WHERE r.project_id = ?",
    )
    .bind(project_id)
    .fetch_all(db)
    .await
}

pub async fn objects_for_release(db: &MySqlPool, release_id: i64) -> Result<Vec<(String, String)>> {
    sqlx::query_as("SELECT storage_backend, storage_key FROM files WHERE release_id = ?")
        .bind(release_id)
        .fetch_all(db)
        .await
}

pub struct NewFile<'a> {
    pub release_id: i64,
    pub filename: &'a str,
    /// Unique in the release; inserting a taken path is a unique violation.
    pub path: &'a str,
    pub size_bytes: i64,
    pub sha256: &'a str,
    pub sha512: Option<&'a str>,
    pub storage_backend: &'a str,
    pub storage_key: &'a str,
    pub status: &'a str,
}

pub async fn insert_file(db: &MySqlPool, f: &NewFile<'_>) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO files (release_id, filename, path, size_bytes, sha256, sha512, storage_backend, storage_key, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(f.release_id)
    .bind(f.filename)
    .bind(f.path)
    .bind(f.size_bytes)
    .bind(f.sha256)
    .bind(f.sha512)
    .bind(f.storage_backend)
    .bind(f.storage_key)
    .bind(f.status)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

/// Marks an import finished. Returns false if the row vanished meanwhile.
pub async fn finish_import(
    db: &MySqlPool,
    id: i64,
    size: i64,
    sha256: &str,
    sha512: &str,
) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE files SET status = 'ready', size_bytes = ?, sha256 = ?, sha512 = ?, error_message = NULL \
         WHERE id = ? AND status = 'importing'",
    )
    .bind(size)
    .bind(sha256)
    .bind(sha512)
    .bind(id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Marks a file failed with a short message (import or recompute).
pub async fn mark_failed(db: &MySqlPool, id: i64, message: &str) -> Result<()> {
    let message: String = message.chars().take(500).collect();
    sqlx::query("UPDATE files SET status = 'failed', error_message = ? WHERE id = ?")
        .bind(message)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Moves a ready or failed file to 'hashing'. False if it was in another state.
pub async fn start_rehash(db: &MySqlPool, id: i64) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE files SET status = 'hashing', error_message = NULL \
         WHERE id = ? AND status IN ('ready', 'failed')",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn finish_rehash(db: &MySqlPool, id: i64, sha256: &str, sha512: &str) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE files SET status = 'ready', sha256 = ?, sha512 = ?, error_message = NULL \
         WHERE id = ? AND status = 'hashing'",
    )
    .bind(sha256)
    .bind(sha512)
    .bind(id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Run at startup: imports cannot survive a restart. An interrupted
/// recompute leaves the stored file and its old hashes intact, so those
/// rows simply return to 'ready'.
pub async fn recover_interrupted_jobs(db: &MySqlPool) -> Result<(u64, u64)> {
    let imports = sqlx::query(
        "UPDATE files SET status = 'failed', error_message = 'interrupted by restart' \
         WHERE status = 'importing'",
    )
    .execute(db)
    .await?;
    let rehashes = sqlx::query("UPDATE files SET status = 'ready' WHERE status = 'hashing'")
        .execute(db)
        .await?;
    Ok((imports.rows_affected(), rehashes.rows_affected()))
}

pub async fn delete_file(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM files WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn increment_downloads(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query("UPDATE files SET download_count = download_count + 1 WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn stats(db: &MySqlPool) -> Result<Stats> {
    sqlx::query_as(
        "SELECT \
           (SELECT COUNT(*) FROM projects) AS projects, \
           (SELECT COUNT(*) FROM releases) AS releases, \
           (SELECT COUNT(*) FROM files WHERE status = 'ready') AS files, \
           (SELECT CAST(COALESCE(SUM(size_bytes), 0) AS SIGNED) FROM files WHERE status = 'ready') AS bytes, \
           (SELECT CAST(COALESCE(SUM(download_count), 0) AS SIGNED) FROM files) AS downloads",
    )
    .fetch_one(db)
    .await
}

// ---- file_mirrors ----------------------------------------------------------

const MIRROR_COLUMNS: &str = "m.id, m.file_id, m.url, m.label, m.kind, m.status, m.source, \
     m.last_checked_at, m.last_error, m.created_at";

pub async fn mirrors_for_file(db: &MySqlPool, file_id: i64) -> Result<Vec<Mirror>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {MIRROR_COLUMNS} FROM file_mirrors m WHERE m.file_id = ? ORDER BY m.kind, m.id"
    )))
    .bind(file_id)
    .fetch_all(db)
    .await
}

/// All mirrors of a release's files (admin files page summary).
pub async fn mirrors_for_release(db: &MySqlPool, release_id: i64) -> Result<Vec<Mirror>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {MIRROR_COLUMNS} FROM file_mirrors m JOIN files f ON f.id = m.file_id \
         WHERE f.release_id = ? ORDER BY m.kind, m.id"
    )))
    .bind(release_id)
    .fetch_all(db)
    .await
}

/// Approved mirrors of a project's ready files (public page).
pub async fn approved_mirrors_for_project(db: &MySqlPool, project_id: i64) -> Result<Vec<Mirror>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {MIRROR_COLUMNS} FROM file_mirrors m JOIN files f ON f.id = m.file_id \
         JOIN releases r ON r.id = f.release_id \
         WHERE r.project_id = ? AND f.status = 'ready' AND m.status = 'approved' \
         AND r.review_status = 'approved' \
         ORDER BY m.kind, m.id"
    )))
    .bind(project_id)
    .fetch_all(db)
    .await
}

pub async fn get_mirror(db: &MySqlPool, id: i64) -> Result<Option<Mirror>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {MIRROR_COLUMNS} FROM file_mirrors m WHERE m.id = ?"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

pub struct NewMirror<'a> {
    pub file_id: i64,
    pub url: &'a str,
    pub label: &'a str,
    pub kind: &'a str,
    pub status: &'a str,
    pub source: &'a str,
}

pub async fn insert_mirror(db: &MySqlPool, m: &NewMirror<'_>) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO file_mirrors (file_id, url, label, kind, status, source) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(m.file_id)
    .bind(m.url)
    .bind(m.label)
    .bind(m.kind)
    .bind(m.status)
    .bind(m.source)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

pub async fn set_mirror_status(db: &MySqlPool, id: i64, status: &str) -> Result<()> {
    sqlx::query("UPDATE file_mirrors SET status = ? WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_mirror(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM file_mirrors WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Verify succeeded. A previously failed mirror goes back to 'pending' so
/// the admin re-approves it deliberately.
pub async fn mirror_verified(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE file_mirrors SET last_checked_at = NOW(), last_error = NULL, \
         status = IF(status = 'failed', 'pending', status) WHERE id = ?",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Verify failed: hide the mirror publicly and record why.
pub async fn mirror_verify_failed(db: &MySqlPool, id: i64, message: &str) -> Result<()> {
    let message: String = message.chars().take(500).collect();
    sqlx::query(
        "UPDATE file_mirrors SET status = 'failed', last_error = ?, last_checked_at = NOW() WHERE id = ?",
    )
    .bind(message)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

// ---- import batches ------------------------------------------------------------

const BATCH_COLUMNS: &str = "b.id, b.release_id, b.source, b.folder, b.created_at, b.finished_at, \
     COUNT(i.id) AS total, \
     CAST(COALESCE(SUM(i.status IN ('queued', 'importing')), 0) AS SIGNED) AS queued, \
     CAST(COALESCE(SUM(i.status = 'done'), 0) AS SIGNED) AS done, \
     CAST(COALESCE(SUM(i.status = 'skipped'), 0) AS SIGNED) AS skipped, \
     CAST(COALESCE(SUM(i.status = 'failed'), 0) AS SIGNED) AS failed";

pub async fn create_batch(
    db: &MySqlPool,
    release_id: i64,
    user_id: Option<i64>,
    source: &str,
    folder: &str,
) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO import_batches (release_id, user_id, source, folder) VALUES (?, ?, ?, ?)",
    )
    .bind(release_id)
    .bind(user_id)
    .bind(source)
    .bind(folder)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

pub async fn add_item(
    db: &MySqlPool,
    batch_id: i64,
    path: &str,
    size: i64,
    status: &str,
    message: Option<&str>,
    file_id: Option<i64>,
) -> Result<i64> {
    let message = message.map(|m| m.chars().take(500).collect::<String>());
    let res = sqlx::query(
        "INSERT INTO import_items (batch_id, path, size_bytes, status, message, file_id, finished_at) \
         VALUES (?, ?, ?, ?, ?, ?, IF(? IN ('queued', 'importing'), NULL, NOW()))",
    )
    .bind(batch_id)
    .bind(path)
    .bind(size)
    .bind(status)
    .bind(message)
    .bind(file_id)
    .bind(status)
    .execute(db)
    .await?;
    Ok(res.last_insert_id() as i64)
}

pub async fn set_item(
    db: &MySqlPool,
    id: i64,
    status: &str,
    message: Option<&str>,
    file_id: Option<i64>,
) -> Result<()> {
    let message = message.map(|m| m.chars().take(500).collect::<String>());
    sqlx::query(
        "UPDATE import_items SET status = ?, message = ?, file_id = COALESCE(?, file_id), \
         finished_at = IF(? IN ('queued', 'importing'), NULL, NOW()) WHERE id = ?",
    )
    .bind(status)
    .bind(message)
    .bind(file_id)
    .bind(status)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn finish_batch(db: &MySqlPool, id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE import_batches SET finished_at = NOW() WHERE id = ? AND finished_at IS NULL",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_batch(db: &MySqlPool, id: i64) -> Result<Option<ImportBatch>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {BATCH_COLUMNS} FROM import_batches b LEFT JOIN import_items i ON i.batch_id = b.id \
         WHERE b.id = ? GROUP BY b.id"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// The most recent batches of a release, newest first.
pub async fn recent_batches(
    db: &MySqlPool,
    release_id: i64,
    limit: i64,
) -> Result<Vec<ImportBatch>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {BATCH_COLUMNS} FROM import_batches b LEFT JOIN import_items i ON i.batch_id = b.id \
         WHERE b.release_id = ? GROUP BY b.id ORDER BY b.id DESC LIMIT ?"
    )))
    .bind(release_id)
    .bind(limit)
    .fetch_all(db)
    .await
}

/// A batch's items: failures first, then in import order.
pub async fn batch_items(db: &MySqlPool, batch_id: i64) -> Result<Vec<ImportItem>> {
    sqlx::query_as(
        "SELECT id, path, size_bytes, status, message, file_id FROM import_items \
         WHERE batch_id = ? ORDER BY status = 'failed' DESC, id",
    )
    .bind(batch_id)
    .fetch_all(db)
    .await
}

/// Startup: batches cannot survive a restart (rerunning them is safe).
pub async fn recover_interrupted_batches(db: &MySqlPool) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE import_items SET status = 'failed', message = 'interrupted by restart; run the import again', \
         finished_at = NOW() WHERE status IN ('queued', 'importing')",
    )
    .execute(db)
    .await?;
    sqlx::query("UPDATE import_batches SET finished_at = NOW() WHERE finished_at IS NULL")
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

// ---- audit log ---------------------------------------------------------------------

pub async fn audit(
    db: &MySqlPool,
    user: Option<(i64, &str)>,
    action: &str,
    target: &str,
    detail: Option<&str>,
) -> Result<()> {
    let target: String = target.chars().take(700).collect();
    let detail = detail.map(|d| d.chars().take(1000).collect::<String>());
    sqlx::query(
        "INSERT INTO audit_log (user_id, username, action, target, detail) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.map(|u| u.0))
    .bind(user.map(|u| u.1).unwrap_or("system"))
    .bind(action)
    .bind(target)
    .bind(detail)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn recent_audit(db: &MySqlPool, limit: i64) -> Result<Vec<AuditEntry>> {
    sqlx::query_as(
        "SELECT created_at, username, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await
}

// ---- R2 copies -------------------------------------------------------------------

/// A published file, as the R2 sync needs it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SyncFile {
    pub id: i64,
    pub slug: String,
    pub version: String,
    pub path: String,
    pub filename: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub storage_backend: String,
    pub storage_key: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct R2Object {
    pub file_id: i64,
    pub object_key: String,
    pub size_bytes: i64,
    pub status: String,
    pub error: Option<String>,
    pub updated_at: chrono::NaiveDateTime,
}

/// Every published file (ready, approved release of an approved project).
pub async fn public_files_for_sync(db: &MySqlPool) -> Result<Vec<SyncFile>> {
    sqlx::query_as(
        "SELECT f.id, p.slug, r.version, f.path, f.filename, f.size_bytes, f.sha256, \
         f.storage_backend, f.storage_key FROM files f \
         JOIN releases r ON r.id = f.release_id JOIN projects p ON p.id = r.project_id \
         WHERE f.status = 'ready' AND f.sha256 <> '' \
         AND r.review_status = 'approved' AND p.review_status = 'approved' \
         ORDER BY r.released_at DESC, f.path",
    )
    .fetch_all(db)
    .await
}

pub async fn r2_objects(db: &MySqlPool) -> Result<Vec<R2Object>> {
    sqlx::query_as(
        "SELECT file_id, object_key, size_bytes, status, error, updated_at FROM r2_objects",
    )
    .fetch_all(db)
    .await
}

pub async fn r2_object(db: &MySqlPool, file_id: i64) -> Result<Option<R2Object>> {
    sqlx::query_as(
        "SELECT file_id, object_key, size_bytes, status, error, updated_at FROM r2_objects \
         WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_optional(db)
    .await
}

/// Records an upload result (insert or replace).
pub async fn r2_record(
    db: &MySqlPool,
    file_id: i64,
    key: &str,
    size: i64,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let error = error.map(|e| e.chars().take(500).collect::<String>());
    sqlx::query(
        "INSERT INTO r2_objects (file_id, object_key, size_bytes, status, error) VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE object_key = VALUES(object_key), size_bytes = VALUES(size_bytes), \
         status = VALUES(status), error = VALUES(error), updated_at = NOW()",
    )
    .bind(file_id)
    .bind(key)
    .bind(size)
    .bind(status)
    .bind(error)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn r2_forget(db: &MySqlPool, file_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM r2_objects WHERE file_id = ?")
        .bind(file_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Failed uploads with the file's place, newest first (admin status page).
pub async fn r2_failures(
    db: &MySqlPool,
    limit: i64,
) -> Result<Vec<(String, String, chrono::NaiveDateTime)>> {
    sqlx::query_as(
        "SELECT o.object_key, COALESCE(o.error, ''), o.updated_at FROM r2_objects o \
         WHERE o.status = 'failed' ORDER BY o.updated_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await
}
