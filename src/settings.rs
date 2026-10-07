//! Site settings (name, tagline, footer, download base URL, external sharing
//! toggles, member accounts), stored in the site_settings table and cached
//! in AppState.
//!
//! The env-backed settings (SITE_NAME, SITE_TAGLINE, DOWNLOAD_BASE_URL and
//! the four sharing toggles) are copied from the environment into the table
//! at every startup, *until* the admin saves a different value in
//! /admin/settings. That save records an `override.<key>` marker, after which
//! the database value wins. Saving a value equal to the env value removes the
//! marker, handing control back to .env.

use sqlx::MySqlPool;

use crate::config::Config;
use crate::db::queries;

pub const SITE_NAME: &str = "site_name";
pub const SITE_TAGLINE: &str = "site_tagline";
pub const FOOTER_TEXT: &str = "footer_text";
pub const DOWNLOAD_BASE_URL: &str = "download_base_url";
pub const EXTERNAL_MIRRORS_ENABLED: &str = "external_mirrors_enabled";
pub const TORRENT_DHT_ENABLED: &str = "torrent_dht_enabled";
pub const MIRROR_DISCOVERY_ENABLED: &str = "mirror_discovery_enabled";
pub const FEDERATION_ENABLED: &str = "federation_enabled";
/// The admin's OpenPGP public key, served at /gpg.pub (set in /admin/settings).
pub const GPG_PUBLIC_KEY: &str = "gpg_public_key";
/// Member settings (docs/MEMBERS.md); database only, no .env counterpart.
pub const REGISTRATION_OPEN: &str = "registration_open";
pub const CONTACT_EMAIL: &str = "contact_email";
pub const REVIEW_MEMBER_UPLOADS: &str = "review_member_uploads";
pub const MEMBER_UPLOAD_LIMIT: &str = "member_upload_limit_bytes";
pub const MEMBER_STORAGE_QUOTA: &str = "member_storage_quota_bytes";

/// Defaults for a new install (and for installs from before members).
pub const DEFAULT_MEMBER_UPLOAD_LIMIT: u64 = 100 << 20;
pub const DEFAULT_MEMBER_STORAGE_QUOTA: u64 = 1 << 30;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiteSettings {
    pub name: String,
    pub tagline: String,
    pub footer: String,
    /// Normalized (no trailing slash); empty means same host, relative links.
    pub download_base_url: String,
    /// Public pages show approved mirror and torrent links.
    pub external_mirrors_enabled: bool,
    /// Future generated torrents are public (DHT/PEX) instead of private.
    pub torrent_dht_enabled: bool,
    /// Stub: no effect yet.
    pub mirror_discovery_enabled: bool,
    /// Stub: no effect yet.
    pub federation_enabled: bool,
    /// ASCII-armored public key for /gpg.pub ("" = not published).
    pub gpg_public_key: String,
    /// /register accepts account requests (each still needs approval).
    pub registration_open: bool,
    /// Shown on /register while registration is closed ("" = generic text).
    pub contact_email: String,
    /// New and changed member projects/releases stay hidden until approved.
    pub review_member_uploads: bool,
    /// Largest single member upload, unless set per member (also capped by
    /// MAX_UPLOAD_BYTES).
    pub member_upload_limit: u64,
    /// Total bytes a member may store, unless set per member.
    pub member_storage_quota: u64,
}

fn override_key(key: &str) -> String {
    format!("override.{key}")
}

fn flag(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

/// (key, value) for every env-backed setting, as stored in the table.
fn env_backed_values(s: &SiteSettings) -> [(&'static str, String); 7] {
    [
        (SITE_NAME, s.name.clone()),
        (SITE_TAGLINE, s.tagline.clone()),
        (DOWNLOAD_BASE_URL, s.download_base_url.clone()),
        (EXTERNAL_MIRRORS_ENABLED, flag(s.external_mirrors_enabled)),
        (TORRENT_DHT_ENABLED, flag(s.torrent_dht_enabled)),
        (MIRROR_DISCOVERY_ENABLED, flag(s.mirror_discovery_enabled)),
        (FEDERATION_ENABLED, flag(s.federation_enabled)),
    ]
}

/// The settings as the environment defines them.
fn from_env(config: &Config) -> SiteSettings {
    SiteSettings {
        name: config.site_name.clone(),
        tagline: config.site_tagline.clone(),
        footer: String::new(),
        download_base_url: config.download_base_url.clone(),
        external_mirrors_enabled: config.external_mirrors_enabled,
        torrent_dht_enabled: config.torrent_dht_enabled,
        mirror_discovery_enabled: config.mirror_discovery_enabled,
        federation_enabled: config.federation_enabled,
        gpg_public_key: String::new(),
        // ALLOW_REGISTRATION only seeds the setting on first start; after
        // that /admin/settings owns it.
        registration_open: config.allow_registration,
        contact_email: String::new(),
        review_member_uploads: true,
        member_upload_limit: DEFAULT_MEMBER_UPLOAD_LIMIT,
        member_storage_quota: DEFAULT_MEMBER_STORAGE_QUOTA,
    }
}

/// Startup: copy env values for keys the admin has not overridden, then load.
pub async fn sync_from_env(db: &MySqlPool, config: &Config) -> sqlx::Result<SiteSettings> {
    let existing = queries::all_settings(db).await?;
    for (key, env_value) in env_backed_values(&from_env(config)) {
        let overridden = existing.iter().any(|(k, _)| *k == override_key(key));
        if !overridden {
            queries::set_setting(db, key, &env_value).await?;
        }
    }
    queries::insert_setting_if_missing(db, FOOTER_TEXT, "").await?;
    for (key, value) in member_values(&from_env(config)) {
        queries::insert_setting_if_missing(db, key, &value).await?;
    }
    load(db).await
}

/// (key, value) for the member settings, as stored in the table.
fn member_values(s: &SiteSettings) -> [(&'static str, String); 5] {
    [
        (REGISTRATION_OPEN, flag(s.registration_open)),
        (CONTACT_EMAIL, s.contact_email.clone()),
        (REVIEW_MEMBER_UPLOADS, flag(s.review_member_uploads)),
        (MEMBER_UPLOAD_LIMIT, s.member_upload_limit.to_string()),
        (MEMBER_STORAGE_QUOTA, s.member_storage_quota.to_string()),
    ]
}

pub async fn load(db: &MySqlPool) -> sqlx::Result<SiteSettings> {
    let mut s = SiteSettings {
        review_member_uploads: true,
        member_upload_limit: DEFAULT_MEMBER_UPLOAD_LIMIT,
        member_storage_quota: DEFAULT_MEMBER_STORAGE_QUOTA,
        ..SiteSettings::default()
    };
    for (k, v) in queries::all_settings(db).await? {
        let on = v == "true";
        match k.as_str() {
            SITE_NAME => s.name = v,
            SITE_TAGLINE => s.tagline = v,
            FOOTER_TEXT => s.footer = v,
            DOWNLOAD_BASE_URL => s.download_base_url = v,
            EXTERNAL_MIRRORS_ENABLED => s.external_mirrors_enabled = on,
            TORRENT_DHT_ENABLED => s.torrent_dht_enabled = on,
            MIRROR_DISCOVERY_ENABLED => s.mirror_discovery_enabled = on,
            FEDERATION_ENABLED => s.federation_enabled = on,
            GPG_PUBLIC_KEY => s.gpg_public_key = v,
            REGISTRATION_OPEN => s.registration_open = on,
            CONTACT_EMAIL => s.contact_email = v,
            REVIEW_MEMBER_UPLOADS => s.review_member_uploads = on,
            MEMBER_UPLOAD_LIMIT => {
                s.member_upload_limit = v.parse().unwrap_or(DEFAULT_MEMBER_UPLOAD_LIMIT)
            }
            MEMBER_STORAGE_QUOTA => {
                s.member_storage_quota = v.parse().unwrap_or(DEFAULT_MEMBER_STORAGE_QUOTA)
            }
            _ => {}
        }
    }
    Ok(s)
}

/// Saves settings from /admin/settings (already validated).
pub async fn save(db: &MySqlPool, config: &Config, new: &SiteSettings) -> sqlx::Result<()> {
    let env = env_backed_values(&from_env(config));
    for ((key, value), (_, env_value)) in env_backed_values(new).into_iter().zip(env) {
        queries::set_setting(db, key, &value).await?;
        if value == env_value {
            queries::delete_setting(db, &override_key(key)).await?;
        } else {
            queries::set_setting(db, &override_key(key), "1").await?;
        }
    }
    queries::set_setting(db, GPG_PUBLIC_KEY, &new.gpg_public_key).await?;
    for (key, value) in member_values(new) {
        queries::set_setting(db, key, &value).await?;
    }
    queries::set_setting(db, FOOTER_TEXT, &new.footer).await
}
