//! Self-seeding through qBittorrent behind a VPN container (compose profile
//! "seeder"): STUB. Nothing here talks to qBittorrent yet; until it does,
//! the admin adds torrents in the qBittorrent Web UI by hand (see
//! docs/TORRENTS.md). The app container never joins the VPN network.

use std::fmt;

use async_trait::async_trait;

use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum SeederError {
    #[error(
        "seeding is not implemented yet; add torrents in the qBittorrent Web UI (docs/TORRENTS.md)"
    )]
    NotImplemented,
    #[error("the seeder is not configured (QBT_URL / QBT_PASSWORD)")]
    NotConfigured,
}

/// What a seeding client reports about one torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedStatus {
    /// Client state, e.g. "uploading", "stalledUP", "error".
    pub state: String,
    pub uploaded_bytes: u64,
    pub peers: u32,
}

/// A BitTorrent client that seeds files from storage.
#[async_trait]
pub trait Seeder: Send + Sync {
    /// Adds a `.torrent` whose data already exists at `save_path` (read-only
    /// storage inside the client container) and starts seeding. Returns the
    /// info-hash (hex).
    async fn add_torrent(&self, torrent: &[u8], save_path: &str) -> Result<String, SeederError>;

    /// Current state of a torrent by info-hash.
    async fn status(&self, infohash: &str) -> Result<SeedStatus, SeederError>;

    /// Stops seeding and forgets the torrent. Never deletes data.
    async fn remove(&self, infohash: &str) -> Result<(), SeederError>;
}

/// The seeder used today: every call is "not implemented".
pub struct NoSeeder;

#[async_trait]
impl Seeder for NoSeeder {
    async fn add_torrent(&self, _: &[u8], _: &str) -> Result<String, SeederError> {
        Err(SeederError::NotImplemented)
    }
    async fn status(&self, _: &str) -> Result<SeedStatus, SeederError> {
        Err(SeederError::NotImplemented)
    }
    async fn remove(&self, _: &str) -> Result<(), SeederError> {
        Err(SeederError::NotImplemented)
    }
}

/// Skeleton of the qBittorrent Web API client (QBT_URL, QBT_USERNAME,
/// QBT_PASSWORD). Planned calls:
///
/// * login: `POST {QBT_URL}/api/v2/auth/login` (form `username`, `password`),
///   keep the `SID` cookie, send `Referer: {QBT_URL}` (CSRF check)
/// * add: `POST /api/v2/torrents/add` (multipart `torrents`, `savepath`,
///   `skip_checking=false`, `paused=false`)
/// * status: `GET /api/v2/torrents/info?hashes=<hash>`
/// * remove: `POST /api/v2/torrents/delete` with `deleteFiles=false`
///
/// Reaching qBittorrent from the app means going to the gluetun service on
/// the Docker network (e.g. `http://gluetun:8081`), which also requires
/// `FIREWALL_INPUT_PORTS=8081` on gluetun. The app itself stays off the VPN.
pub struct QbittorrentSeeder {
    pub url: String,
    pub username: String,
    password: String,
}

impl fmt::Debug for QbittorrentSeeder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QbittorrentSeeder")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl QbittorrentSeeder {
    /// Built from QBT_URL / QBT_USERNAME / QBT_PASSWORD; None if unset.
    pub fn from_config(config: &Config) -> Option<Self> {
        Some(Self {
            url: config.qbt_url.clone()?,
            username: config.qbt_username.clone(),
            password: config.qbt_password.clone()?,
        })
    }
}

#[async_trait]
impl Seeder for QbittorrentSeeder {
    async fn add_torrent(&self, _: &[u8], _: &str) -> Result<String, SeederError> {
        let _ = &self.password; // used by the future login call
        Err(SeederError::NotImplemented)
    }
    async fn status(&self, _: &str) -> Result<SeedStatus, SeederError> {
        Err(SeederError::NotImplemented)
    }
    async fn remove(&self, _: &str) -> Result<(), SeederError> {
        Err(SeederError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn stubs_report_not_implemented() {
        assert!(matches!(
            NoSeeder.status("x").await,
            Err(SeederError::NotImplemented)
        ));
        assert!(matches!(
            NoSeeder.remove("x").await,
            Err(SeederError::NotImplemented)
        ));
        assert!(matches!(
            NoSeeder.add_torrent(b"", "/data").await,
            Err(SeederError::NotImplemented)
        ));
    }

    #[test]
    fn qbittorrent_skeleton_needs_url_and_password() {
        let base = [("DATABASE_URL", "mysql://u:p@h/d"), ("SITE_NAME", "S")];
        let cfg = |extra: &[(&str, &str)]| {
            let map: HashMap<String, String> = base
                .iter()
                .chain(extra)
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Config::from_lookup(|k| map.get(k).cloned()).unwrap()
        };
        assert!(QbittorrentSeeder::from_config(&cfg(&[])).is_none());
        let s = QbittorrentSeeder::from_config(&cfg(&[
            ("QBT_URL", "http://gluetun:8081/"),
            ("QBT_PASSWORD", "secret-pw"),
        ]))
        .unwrap();
        assert_eq!(s.url, "http://gluetun:8081");
        assert_eq!(s.username, "admin");
        assert!(!format!("{s:?}").contains("secret-pw"));
    }
}
