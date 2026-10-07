//! Runtime configuration, read from environment variables (and `.env` when
//! present). Every problem is collected and reported at once so a broken
//! `.env` can be fixed in a single pass.
//!
//! Variables used only by docker compose / install.sh (DB_PORT, HTTP_PORT,
//! APP_HTTP_BIND, COMPOSE_PROFILES, MARIADB_*, *_HOST_PATH) are not read here.

use std::fmt;
use std::path::PathBuf;

/// The container (and the binary) always listens here.
pub const LISTEN_ADDR: &str = "0.0.0.0:8080";

/// Default MAX_UPLOAD_BYTES: just under Cloudflare's ~100 MB request cap.
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 90_000_000;

/// Default TORRENT_PIECE_LENGTH (4 MiB).
pub const DEFAULT_TORRENT_PIECE_LENGTH: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageKind {
    Local,
    Smb,
}

impl StorageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageKind::Local => "local",
            StorageKind::Smb => "smb",
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    /// Env value of SITE_NAME; the DB value may override it (see settings).
    pub site_name: String,
    pub site_tagline: String,
    /// Env value of DOWNLOAD_BASE_URL (normalized, no trailing slash).
    pub download_base_url: String,
    pub public_url: Option<String>,
    pub cookie_secure: bool,
    pub storage_backend: StorageKind,
    pub storage_path: PathBuf,
    pub incoming_path: PathBuf,
    pub import_min_age_secs: u64,
    pub allow_web_upload: bool,
    pub max_upload_bytes: u64,
    pub allow_registration: bool,
    pub torrent_enabled: bool,
    pub torrent_trackers: Vec<String>,
    pub torrent_piece_length: u64,
    pub sign_checksums: bool,
    pub strip_metadata: bool,
    /// External sharing toggles (env seeds; /admin/settings may override).
    pub external_mirrors_enabled: bool,
    pub torrent_dht_enabled: bool,
    pub mirror_discovery_enabled: bool,
    pub federation_enabled: bool,
    /// qBittorrent Web API for the future seeder integration (src/seeder.rs).
    pub qbt_url: Option<String>,
    pub qbt_username: String,
    pub qbt_password: Option<String>,
    /// Hardening settings (see docs/SECURITY-REVIEW.md, .env.example).
    pub security: Security,
}

/// Security and abuse-resistance settings. Every default is the safe one;
/// anything that could lock the admin out or change the deployment
/// (TOTP, admin allowlist/host, HSTS) is opt-in.
#[derive(Clone)]
pub struct Security {
    pub session_idle: std::time::Duration,
    pub session_absolute: std::time::Duration,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub totp_enabled: bool,
    /// AES-256-GCM key for TOTP secrets (TOTP_ENCRYPTION_KEY, base64).
    pub totp_key: Option<[u8; 32]>,
    pub proxy: crate::net::ProxyPolicy,
    /// Empty = no restriction.
    pub admin_allowed_cidrs: Vec<crate::net::Cidr>,
    /// Lowercase host name without port; None = any host.
    pub admin_host: Option<String>,
    pub setup_enabled: bool,
    pub hsts_enabled: bool,
    pub hsts_include_subdomains: bool,
    pub log_ip_mode: crate::net::LogIpMode,
    pub request_timeout: std::time::Duration,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub download_max_concurrent: usize,
    pub download_max_per_ip: usize,
    /// Requests per minute per client IP on all routes (0 = off).
    pub rate_limit_per_minute: u32,
    pub import_concurrency: usize,
    pub storage_min_free_bytes: u64,
    /// Optional http(s)/socks5 proxy for mirror Verify.
    pub verify_proxy_url: Option<String>,
}

impl fmt::Debug for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Security")
            .field("session_idle", &self.session_idle)
            .field("session_absolute", &self.session_absolute)
            .field("totp_enabled", &self.totp_enabled)
            .field("totp_key", &self.totp_key.map(|_| "<redacted>"))
            .field("admin_allowed_cidrs", &self.admin_allowed_cidrs.len())
            .field("admin_host", &self.admin_host)
            .field("setup_enabled", &self.setup_enabled)
            .field("hsts_enabled", &self.hsts_enabled)
            .field("log_ip_mode", &self.log_ip_mode)
            .finish_non_exhaustive()
    }
}

// Hand-written so DATABASE_URL (which contains a password) never reaches logs.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("site_name", &self.site_name)
            .field("download_base_url", &self.download_base_url)
            .field("public_url", &self.public_url)
            .field("cookie_secure", &self.cookie_secure)
            .field("storage_backend", &self.storage_backend)
            .field("storage_path", &self.storage_path)
            .field("incoming_path", &self.incoming_path)
            .field("import_min_age_secs", &self.import_min_age_secs)
            .field("allow_web_upload", &self.allow_web_upload)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("allow_registration", &self.allow_registration)
            .field("torrent_enabled", &self.torrent_enabled)
            .field("sign_checksums", &self.sign_checksums)
            .field("strip_metadata", &self.strip_metadata)
            .field("external_mirrors_enabled", &self.external_mirrors_enabled)
            .field("torrent_dht_enabled", &self.torrent_dht_enabled)
            .field("qbt_url", &self.qbt_url)
            .field(
                "qbt_password",
                &self.qbt_password.as_ref().map(|_| "<redacted>"),
            )
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ConfigError(pub Vec<String>);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "invalid configuration:")?;
        for e in &self.0 {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load from the process environment, after reading `.env` if present.
    pub fn from_env() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv();
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from any key lookup (the environment in production, a map in tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        // Treat empty values as unset.
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let database_url = get("DATABASE_URL").unwrap_or_default();
        if database_url.is_empty() {
            errors.push("DATABASE_URL is required (mysql://user:pass@host:port/db)".into());
        } else if !database_url.starts_with("mysql://") {
            errors.push("DATABASE_URL must start with mysql://".into());
        }

        let site_name = get("SITE_NAME").unwrap_or_default();
        if site_name.is_empty() {
            errors.push("SITE_NAME is required".into());
        } else if site_name.chars().count() > 100 {
            errors.push("SITE_NAME must be at most 100 characters".into());
        }
        let site_tagline = get("SITE_TAGLINE").unwrap_or_default();

        let download_base_url = match get("DOWNLOAD_BASE_URL") {
            None => String::new(),
            Some(v) => validate_base_url(&v).unwrap_or_else(|e| {
                errors.push(format!("DOWNLOAD_BASE_URL: {e}"));
                String::new()
            }),
        };

        let public_url = get("PUBLIC_URL").map(|u| u.trim_end_matches('/').to_string());
        if let Some(u) = &public_url
            && !(u.starts_with("http://") || u.starts_with("https://"))
        {
            errors.push("PUBLIC_URL must start with http:// or https://".into());
        }

        // Default: secure cookies whenever the public URL is HTTPS.
        let https_default = public_url
            .as_deref()
            .is_some_and(|u| u.starts_with("https://"));
        let cookie_secure = parse_bool_var(&get, "COOKIE_SECURE", https_default, &mut errors);

        let storage_backend = match get("STORAGE_BACKEND").as_deref() {
            None | Some("local") => StorageKind::Local,
            Some("smb") => StorageKind::Smb,
            Some(other) => {
                errors.push(format!(
                    "STORAGE_BACKEND must be 'local' or 'smb', got '{other}'"
                ));
                StorageKind::Local
            }
        };
        let storage_path =
            PathBuf::from(get("STORAGE_PATH").unwrap_or_else(|| "./data/storage".into()));
        // Default: a sibling of the storage directory.
        let incoming_path = get("INCOMING_PATH").map(PathBuf::from).unwrap_or_else(|| {
            storage_path
                .parent()
                .map(|p| p.join("incoming"))
                .unwrap_or_else(|| PathBuf::from("incoming"))
        });

        let import_min_age_secs = match get("IMPORT_MIN_AGE_SECS") {
            None => 30,
            Some(v) => v.parse().unwrap_or_else(|_| {
                errors.push(format!(
                    "IMPORT_MIN_AGE_SECS must be a whole number of seconds, got '{v}'"
                ));
                30
            }),
        };

        let allow_web_upload = parse_bool_var(&get, "ALLOW_WEB_UPLOAD", true, &mut errors);
        let max_upload_bytes = match get("MAX_UPLOAD_BYTES") {
            None => DEFAULT_MAX_UPLOAD_BYTES,
            Some(v) => parse_size(&v).unwrap_or_else(|| {
                errors.push(format!(
                    "MAX_UPLOAD_BYTES must be a byte count, optionally with K/M/G/T suffix, got '{v}'"
                ));
                DEFAULT_MAX_UPLOAD_BYTES
            }),
        };
        let allow_registration = parse_bool_var(&get, "ALLOW_REGISTRATION", false, &mut errors);

        let torrent_enabled = parse_bool_var(&get, "TORRENT_ENABLED", false, &mut errors);
        let torrent_trackers = get("TORRENT_TRACKERS")
            .map(|v| {
                v.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let torrent_piece_length = match get("TORRENT_PIECE_LENGTH") {
            None => DEFAULT_TORRENT_PIECE_LENGTH,
            Some(v) => match parse_size(&v) {
                Some(n) if n >= 16 * 1024 && n.is_power_of_two() => n,
                _ => {
                    errors.push(format!(
                        "TORRENT_PIECE_LENGTH must be a power of two of at least 16384, got '{v}'"
                    ));
                    DEFAULT_TORRENT_PIECE_LENGTH
                }
            },
        };

        let sign_checksums = parse_bool_var(&get, "SIGN_CHECKSUMS", false, &mut errors);
        let strip_metadata = parse_bool_var(&get, "STRIP_METADATA", false, &mut errors);
        let external_mirrors_enabled =
            parse_bool_var(&get, "EXTERNAL_MIRRORS_ENABLED", false, &mut errors);
        let torrent_dht_enabled = parse_bool_var(&get, "TORRENT_DHT_ENABLED", false, &mut errors);
        let mirror_discovery_enabled =
            parse_bool_var(&get, "MIRROR_DISCOVERY_ENABLED", false, &mut errors);
        let federation_enabled = parse_bool_var(&get, "FEDERATION_ENABLED", false, &mut errors);
        let qbt_url = get("QBT_URL").map(|u| u.trim_end_matches('/').to_string());
        if let Some(u) = &qbt_url
            && !(u.starts_with("http://") || u.starts_with("https://"))
        {
            errors.push("QBT_URL must start with http:// or https://".into());
        }
        let qbt_username = get("QBT_USERNAME").unwrap_or_else(|| "admin".into());
        let qbt_password = get("QBT_PASSWORD");
        let security = parse_security(&get, &mut errors);

        if !errors.is_empty() {
            return Err(ConfigError(errors));
        }
        Ok(Config {
            database_url,
            site_name,
            site_tagline,
            download_base_url,
            public_url,
            cookie_secure,
            storage_backend,
            storage_path,
            incoming_path,
            import_min_age_secs,
            allow_web_upload,
            max_upload_bytes,
            allow_registration,
            torrent_enabled,
            torrent_trackers,
            torrent_piece_length,
            sign_checksums,
            strip_metadata,
            external_mirrors_enabled,
            torrent_dht_enabled,
            mirror_discovery_enabled,
            federation_enabled,
            qbt_url,
            qbt_username,
            qbt_password,
            security,
        })
    }
}

fn parse_num_var<T: std::str::FromStr + Copy + PartialOrd + fmt::Display>(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: T,
    min: T,
    errors: &mut Vec<String>,
) -> T {
    match get(key) {
        None => default,
        Some(v) => match v.parse::<T>() {
            Ok(n) if n >= min => n,
            _ => {
                errors.push(format!(
                    "{key} must be a number of at least {min}, got '{v}'"
                ));
                default
            }
        },
    }
}

fn parse_security(get: &impl Fn(&str) -> Option<String>, errors: &mut Vec<String>) -> Security {
    use crate::net::{
        ClientIpHeader, DEFAULT_TRUSTED_PROXIES, LogIpMode, ProxyPolicy, parse_cidr_list,
    };
    use std::time::Duration;

    let idle_mins = parse_num_var(get, "SESSION_IDLE_TIMEOUT_MINS", 30u64, 1, errors);
    let abs_hours = parse_num_var(get, "SESSION_ABSOLUTE_TIMEOUT_HOURS", 12u64, 1, errors);

    let totp_enabled = parse_bool_var(get, "TOTP_ENABLED", false, errors);
    let totp_key = match get("TOTP_ENCRYPTION_KEY") {
        None => None,
        Some(v) => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(v.trim()) {
                Ok(bytes) if bytes.len() == 32 => bytes.try_into().ok(),
                _ => {
                    errors.push("TOTP_ENCRYPTION_KEY must be 32 random bytes, base64 (openssl rand -base64 32)".into());
                    None
                }
            }
        }
    };
    if totp_enabled
        && totp_key.is_none()
        && !errors.iter().any(|e| e.starts_with("TOTP_ENCRYPTION_KEY"))
    {
        errors.push("TOTP_ENABLED=true needs TOTP_ENCRYPTION_KEY (re-run ./install.sh or: openssl rand -base64 32)".into());
    }

    let trusted =
        parse_cidr_list(&get("TRUSTED_PROXIES").unwrap_or_else(|| DEFAULT_TRUSTED_PROXIES.into()))
            .unwrap_or_else(|e| {
                errors.push(format!("TRUSTED_PROXIES: {e}"));
                Vec::new()
            });
    let header = match get("CLIENT_IP_HEADER") {
        None => ClientIpHeader::XForwardedFor,
        Some(v) => ClientIpHeader::parse(&v).unwrap_or_else(|| {
            errors.push(format!(
                "CLIENT_IP_HEADER must be x-forwarded-for or cf-connecting-ip, got '{v}'"
            ));
            ClientIpHeader::XForwardedFor
        }),
    };
    let admin_allowed_cidrs = parse_cidr_list(&get("ADMIN_ALLOWED_CIDRS").unwrap_or_default())
        .unwrap_or_else(|e| {
            errors.push(format!("ADMIN_ALLOWED_CIDRS: {e}"));
            Vec::new()
        });
    let admin_host = get("ADMIN_HOST").map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    if let Some(h) = &admin_host
        && (h.contains('/') || h.contains(':') || h.contains(' '))
    {
        errors.push("ADMIN_HOST must be a bare host name, e.g. admin.example.com".into());
    }
    let log_ip_mode = match get("LOG_IP_MODE") {
        None => LogIpMode::Truncated,
        Some(v) => LogIpMode::parse(&v).unwrap_or_else(|| {
            errors.push(format!(
                "LOG_IP_MODE must be none, truncated or full, got '{v}'"
            ));
            LogIpMode::Truncated
        }),
    };
    let verify_proxy_url = get("VERIFY_PROXY_URL");
    if let Some(u) = &verify_proxy_url
        && !["http://", "https://", "socks5://", "socks5h://"]
            .iter()
            .any(|p| u.starts_with(p))
    {
        errors.push(
            "VERIFY_PROXY_URL must start with http://, https://, socks5:// or socks5h://".into(),
        );
    }
    let storage_min_free_bytes = match get("STORAGE_MIN_FREE_BYTES") {
        None => 1 << 30,
        Some(v) => parse_size(&v).unwrap_or_else(|| {
            errors.push(format!(
                "STORAGE_MIN_FREE_BYTES must be a byte count (K/M/G/T suffix allowed), got '{v}'"
            ));
            1 << 30
        }),
    };

    Security {
        session_idle: Duration::from_secs(idle_mins * 60),
        session_absolute: Duration::from_secs(abs_hours * 3600),
        argon2_memory_kib: parse_num_var(get, "ARGON2_MEMORY_KIB", 19_456u32, 8_192, errors),
        argon2_iterations: parse_num_var(get, "ARGON2_ITERATIONS", 2u32, 1, errors),
        argon2_parallelism: parse_num_var(get, "ARGON2_PARALLELISM", 1u32, 1, errors),
        totp_enabled,
        totp_key,
        proxy: ProxyPolicy { trusted, header },
        admin_allowed_cidrs,
        admin_host,
        setup_enabled: parse_bool_var(get, "SETUP_ENABLED", true, errors),
        hsts_enabled: parse_bool_var(get, "HSTS_ENABLED", false, errors),
        hsts_include_subdomains: parse_bool_var(get, "HSTS_INCLUDE_SUBDOMAINS", false, errors),
        log_ip_mode,
        request_timeout: Duration::from_secs(parse_num_var(
            get,
            "REQUEST_TIMEOUT_SECS",
            30u64,
            1,
            errors,
        )),
        max_connections: parse_num_var(get, "MAX_CONNECTIONS", 1024usize, 1, errors),
        max_connections_per_ip: parse_num_var(get, "MAX_CONNECTIONS_PER_IP", 64usize, 1, errors),
        download_max_concurrent: parse_num_var(get, "DOWNLOAD_MAX_CONCURRENT", 64usize, 1, errors),
        download_max_per_ip: parse_num_var(get, "DOWNLOAD_MAX_PER_IP", 4usize, 1, errors),
        rate_limit_per_minute: parse_num_var(get, "RATE_LIMIT_PER_MINUTE", 600u32, 0, errors),
        import_concurrency: parse_num_var(get, "IMPORT_CONCURRENCY", 1usize, 1, errors),
        storage_min_free_bytes,
        verify_proxy_url,
    }
}

fn parse_bool_var(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: bool,
    errors: &mut Vec<String>,
) -> bool {
    match get(key) {
        None => default,
        Some(v) => parse_bool(&v).unwrap_or_else(|| {
            errors.push(format!("{key} must be true or false, got '{v}'"));
            default
        }),
    }
}

/// Accepts true/false, yes/no, on/off, 1/0 (case-insensitive).
pub fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Parses a byte count such as `90000000`, `512M`, `4GiB` or `1T`
/// (binary multiples).
pub fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim();
    let digits_end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(digits_end);
    let n: u64 = num.parse().ok()?;
    let mult: u64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        "T" | "TB" | "TIB" => 1 << 40,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Validates and normalizes a base URL such as DOWNLOAD_BASE_URL:
/// http/https only, a host, no path, query, fragment or credentials.
/// Returns it without a trailing slash; blank input yields "".
pub fn validate_base_url(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(String::new());
    }
    let url = url::Url::parse(input).map_err(|_| format!("'{input}' is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("must start with http:// or https://".into());
    }
    let host = url.host_str().ok_or("must include a host name")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain a username or password".into());
    }
    if url.path() != "/" {
        return Err("must not contain a path (e.g. https://dl.example.com)".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query string or fragment".into());
    }
    // host_str() already brackets IPv6 literals.
    Ok(match url.port() {
        Some(p) => format!("{}://{}:{}", url.scheme(), host, p),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// Validates a mirror URL: http/https with a host, at most 2048 bytes.
/// Blank input yields None (clears the mirror).
pub fn validate_mirror_url(input: &str) -> Result<Option<String>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if input.len() > 2048 {
        return Err("mirror URL must be at most 2048 characters".into());
    }
    let url = url::Url::parse(input).map_err(|_| "mirror URL is not a valid URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("mirror URL must be an http:// or https:// address".into());
    }
    Ok(Some(url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    const BASE: &[(&str, &str)] = &[
        ("DATABASE_URL", "mysql://u:p@db:3306/x"),
        ("SITE_NAME", "My Files"),
    ];

    #[test]
    fn minimal_config_uses_defaults() {
        let c = cfg(BASE).unwrap();
        assert_eq!(c.site_name, "My Files");
        assert_eq!(c.max_upload_bytes, 90_000_000);
        assert!(c.allow_web_upload);
        assert!(!c.allow_registration);
        assert!(!c.cookie_secure);
        assert!(!c.torrent_enabled);
        assert_eq!(c.torrent_piece_length, 4_194_304);
        assert_eq!(c.storage_backend, StorageKind::Local);
        assert_eq!(c.incoming_path, PathBuf::from("./data/incoming"));
        assert_eq!(c.import_min_age_secs, 30);
        assert_eq!(c.download_base_url, "");
        assert!(!c.sign_checksums);
        assert!(!c.strip_metadata);
        assert!(!c.external_mirrors_enabled);
        assert!(!c.torrent_dht_enabled);
        assert!(!c.mirror_discovery_enabled);
        assert!(!c.federation_enabled);
        assert_eq!(c.qbt_url, None);
        let sec = &c.security;
        assert_eq!(sec.session_idle.as_secs(), 30 * 60);
        assert_eq!(sec.session_absolute.as_secs(), 12 * 3600);
        assert_eq!(
            (
                sec.argon2_memory_kib,
                sec.argon2_iterations,
                sec.argon2_parallelism
            ),
            (19_456, 2, 1)
        );
        assert!(!sec.totp_enabled && !sec.hsts_enabled && sec.setup_enabled);
        assert!(sec.admin_allowed_cidrs.is_empty() && sec.admin_host.is_none());
        assert_eq!(sec.log_ip_mode, crate::net::LogIpMode::Truncated);
        assert_eq!(sec.import_concurrency, 1);
    }

    #[test]
    fn security_settings_validate() {
        let mut pairs = BASE.to_vec();
        pairs.push(("TOTP_ENABLED", "true"));
        assert!(cfg(&pairs).unwrap_err().0[0].contains("TOTP_ENCRYPTION_KEY"));
        pairs.push(("TOTP_ENCRYPTION_KEY", "c2hvcnQ="));
        assert!(cfg(&pairs).is_err(), "key must be 32 bytes");
        pairs.pop();
        pairs.push((
            "TOTP_ENCRYPTION_KEY",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ));
        assert!(cfg(&pairs).unwrap().security.totp_key.is_some());
        let mut bad = BASE.to_vec();
        bad.extend([
            ("TRUSTED_PROXIES", "10.0.0.0/99"),
            ("ADMIN_ALLOWED_CIDRS", "nope"),
            ("LOG_IP_MODE", "everything"),
            ("ADMIN_HOST", "https://admin.example.com"),
            ("VERIFY_PROXY_URL", "ftp://x"),
            ("SESSION_IDLE_TIMEOUT_MINS", "0"),
            ("ARGON2_MEMORY_KIB", "1024"),
        ]);
        assert_eq!(cfg(&bad).unwrap_err().0.len(), 7);
        let mut ok = BASE.to_vec();
        ok.extend([
            ("ADMIN_HOST", "Admin.Example.com."),
            ("ADMIN_ALLOWED_CIDRS", "10.0.0.0/8, 2001:db8::/32"),
        ]);
        let c = cfg(&ok).unwrap();
        assert_eq!(c.security.admin_host.as_deref(), Some("admin.example.com"));
        assert_eq!(c.security.admin_allowed_cidrs.len(), 2);
    }

    #[test]
    fn missing_required_values_are_all_reported() {
        let err = cfg(&[]).unwrap_err();
        assert_eq!(err.0.len(), 2, "{err}");
    }

    #[test]
    fn invalid_values_are_reported() {
        let mut pairs = BASE.to_vec();
        pairs.extend([
            ("COOKIE_SECURE", "maybe"),
            ("STORAGE_BACKEND", "s3"),
            ("MAX_UPLOAD_BYTES", "lots"),
            ("DOWNLOAD_BASE_URL", "ftp://x"),
            ("TORRENT_PIECE_LENGTH", "1000"),
        ]);
        assert_eq!(cfg(&pairs).unwrap_err().0.len(), 5);
    }

    #[test]
    fn https_public_url_implies_secure_cookies() {
        let mut pairs = BASE.to_vec();
        pairs.push(("PUBLIC_URL", "https://files.example.com/"));
        let c = cfg(&pairs).unwrap();
        assert!(c.cookie_secure);
        assert_eq!(c.public_url.as_deref(), Some("https://files.example.com"));
        pairs.push(("COOKIE_SECURE", "false"));
        assert!(!cfg(&pairs).unwrap().cookie_secure);
    }

    #[test]
    fn explicit_values_parse() {
        let mut pairs = BASE.to_vec();
        pairs.extend([
            ("STORAGE_BACKEND", "smb"),
            ("STORAGE_PATH", "/data/storage"),
            ("INCOMING_PATH", "/data/incoming"),
            ("MAX_UPLOAD_BYTES", "50M"),
            ("TORRENT_TRACKERS", "udp://a:1, ,udp://b:2"),
            ("DOWNLOAD_BASE_URL", "https://dl.example.com/"),
        ]);
        let c = cfg(&pairs).unwrap();
        assert_eq!(c.storage_backend, StorageKind::Smb);
        assert_eq!(c.incoming_path, PathBuf::from("/data/incoming"));
        assert_eq!(c.max_upload_bytes, 50 << 20);
        assert_eq!(c.torrent_trackers, vec!["udp://a:1", "udp://b:2"]);
        assert_eq!(c.download_base_url, "https://dl.example.com");
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut pairs = BASE.to_vec();
        pairs.push(("QBT_PASSWORD", "hunter2-secret"));
        pairs.push((
            "TOTP_ENCRYPTION_KEY",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ));
        let c = cfg(&pairs).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("u:p@"));
        assert!(!dbg.contains("hunter2-secret"));
        assert!(!dbg.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("1K"), Some(1024));
        assert_eq!(parse_size("2gib"), Some(2 << 30));
        assert_eq!(parse_size("1T"), Some(1 << 40));
        assert_eq!(parse_size("1X"), None);
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("99999999999999999999T"), None);
    }

    #[test]
    fn parse_bool_variants() {
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("nah"), None);
    }

    #[test]
    fn base_url_validation() {
        assert_eq!(validate_base_url("").unwrap(), "");
        assert_eq!(
            validate_base_url("https://dl.example.com/").unwrap(),
            "https://dl.example.com"
        );
        assert_eq!(
            validate_base_url("http://10.0.0.5:8080").unwrap(),
            "http://10.0.0.5:8080"
        );
        assert_eq!(
            validate_base_url("https://[::1]:9000").unwrap(),
            "https://[::1]:9000"
        );
        assert!(validate_base_url("ftp://dl.example.com").is_err());
        assert!(validate_base_url("https://dl.example.com/files").is_err());
        assert!(validate_base_url("https://dl.example.com/?a=b").is_err());
        assert!(validate_base_url("https://dl.example.com/#x").is_err());
        assert!(validate_base_url("https://user:pw@dl.example.com").is_err());
        assert!(validate_base_url("dl.example.com").is_err());
        assert!(validate_base_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn mirror_url_validation() {
        assert_eq!(validate_mirror_url("  ").unwrap(), None);
        assert_eq!(
            validate_mirror_url("https://archive.org/download/x/y.iso")
                .unwrap()
                .as_deref(),
            Some("https://archive.org/download/x/y.iso")
        );
        assert!(validate_mirror_url("javascript:alert(1)").is_err());
        assert!(validate_mirror_url("ftp://mirror/x").is_err());
        assert!(validate_mirror_url("not a url").is_err());
        assert!(validate_mirror_url(&format!("https://x.com/{}", "a".repeat(2100))).is_err());
    }
}
