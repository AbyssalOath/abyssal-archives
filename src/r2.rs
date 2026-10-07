//! Optional Cloudflare R2 download origin (docs/DOWNLOADS.md, "Cloudflare
//! R2"). Off until an administrator configures it in /admin/storage.
//!
//! * The server's own storage stays the master copy (imports, hashing,
//!   integrity checks, backups). R2 holds a copy of every **published**
//!   file, under `<project>/<version>/<path>`, so the bucket is a readable
//!   mirror of the public releases.
//! * A background job ([`spawn_worker`]) uploads published files one at a
//!   time and deletes objects whose file was unpublished or deleted (R2
//!   objects are public). Single uploads are signed with the file's
//!   recorded SHA-256 and multipart parts with their own, so R2 rejects any
//!   byte that differs from what was imported.
//! * With "Serve downloads from R2" on, the stable URLs answer with one
//!   redirect to the R2 copy once it is uploaded; files not uploaded yet
//!   are still served by this server. Turning it off serves everything
//!   locally again; no public URL ever changes.
//! * The secret access key is stored AES-256-GCM encrypted with a key
//!   derived from TOTP_ENCRYPTION_KEY (never in the database), write-only
//!   in the UI and never logged.
//!
//! Requests are signed with AWS Signature Version 4 (R2 speaks the S3 API),
//! implemented here on top of reqwest instead of pulling in an AWS SDK.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::db::queries;
use crate::state::AppState;
use crate::util::encode_path_segment;

/// Files above this size are uploaded in parts (R2 caps single uploads
/// just under 5 GiB).
const SINGLE_PUT_MAX: u64 = 4 << 30;
/// Multipart part size (R2: equal parts except the last, at most 10,000).
const PART_SIZE: u64 = 128 << 20;
/// A failed upload is retried after this long (or on "Sync now").
const RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
/// How often the job looks for work without being woken.
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
/// Cache lifetime given to objects. Paths are never overwritten, but a file
/// deleted and imported again at the same path reuses its key.
const OBJECT_CACHE_CONTROL: &str = "public, max-age=86400";

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---- settings ----------------------------------------------------------------

/// R2 settings (site_settings keys `r2.*`).
#[derive(Clone, Default)]
pub struct R2Settings {
    /// 32 hex characters (Cloudflare dashboard, R2, Account details).
    pub account_id: String,
    pub bucket: String,
    pub access_key_id: String,
    /// Decrypted secret access key ("" = none stored).
    pub secret: String,
    /// The bucket's public custom domain, e.g. https://dl.example.com.
    pub public_url: String,
    /// "" (default), "eu" or "fedramp".
    pub jurisdiction: String,
    /// Upload published files.
    pub sync: bool,
    /// Redirect downloads to uploaded copies.
    pub serve: bool,
}

impl std::fmt::Debug for R2Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Settings")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field("public_url", &self.public_url)
            .field("jurisdiction", &self.jurisdiction)
            .field("sync", &self.sync)
            .field("serve", &self.serve)
            .finish()
    }
}

impl R2Settings {
    /// Everything needed to talk to the bucket is set.
    pub fn complete(&self) -> bool {
        !self.account_id.is_empty()
            && !self.bucket.is_empty()
            && !self.access_key_id.is_empty()
            && !self.secret.is_empty()
            && !self.public_url.is_empty()
    }

    /// The S3 API endpoint (the bucket goes in the path).
    pub fn endpoint(&self) -> String {
        match self.jurisdiction.as_str() {
            "" => format!("https://{}.r2.cloudflarestorage.com", self.account_id),
            j => format!("https://{}.{j}.r2.cloudflarestorage.com", self.account_id),
        }
    }

    /// The public URL of an object.
    pub fn public_object_url(&self, key: &str) -> String {
        format!("{}/{}", self.public_url, encode_key(key))
    }
}

const K_ACCOUNT: &str = "r2.account_id";
const K_BUCKET: &str = "r2.bucket";
const K_ACCESS_KEY: &str = "r2.access_key_id";
const K_SECRET: &str = "r2.secret_enc";
const K_PUBLIC_URL: &str = "r2.public_url";
const K_JURISDICTION: &str = "r2.jurisdiction";
const K_SYNC: &str = "r2.sync";
const K_SERVE: &str = "r2.serve";

/// The key that seals the secret: HMAC-SHA256(TOTP_ENCRYPTION_KEY, purpose),
/// so the stored value is useless without the key from .env.
fn sealing_key(master: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(master).expect("any key length");
    mac.update(b"filehost r2 credentials v1");
    mac.finalize().into_bytes().into()
}

/// Loads the settings. A secret that cannot be decrypted (key changed) is
/// treated as missing, with a warning.
pub async fn load(db: &MySqlPool, master: Option<[u8; 32]>) -> sqlx::Result<R2Settings> {
    let all: HashMap<String, String> = queries::all_settings(db)
        .await?
        .into_iter()
        .filter(|(k, _)| k.starts_with("r2."))
        .collect();
    let get = |k: &str| all.get(k).cloned().unwrap_or_default();
    let secret = match (master, all.get(K_SECRET)) {
        (Some(m), Some(sealed)) if !sealed.is_empty() => hex::decode(sealed)
            .ok()
            .and_then(|b| crate::totp::decrypt(&sealing_key(&m), &b))
            .and_then(|p| String::from_utf8(p).ok())
            .unwrap_or_else(|| {
                tracing::warn!("the stored R2 secret cannot be decrypted (TOTP_ENCRYPTION_KEY changed?); enter it again in /admin/storage");
                String::new()
            }),
        _ => String::new(),
    };
    Ok(R2Settings {
        account_id: get(K_ACCOUNT),
        bucket: get(K_BUCKET),
        access_key_id: get(K_ACCESS_KEY),
        secret,
        public_url: get(K_PUBLIC_URL),
        jurisdiction: get(K_JURISDICTION),
        sync: get(K_SYNC) == "true",
        serve: get(K_SERVE) == "true",
    })
}

/// Saves validated settings; the secret is sealed with `master`.
pub async fn save(db: &MySqlPool, master: &[u8; 32], s: &R2Settings) -> sqlx::Result<()> {
    let flag = |b: bool| if b { "true" } else { "false" };
    let sealed = if s.secret.is_empty() {
        String::new()
    } else {
        hex::encode(crate::totp::encrypt(
            &sealing_key(master),
            s.secret.as_bytes(),
        ))
    };
    for (k, v) in [
        (K_ACCOUNT, s.account_id.as_str()),
        (K_BUCKET, s.bucket.as_str()),
        (K_ACCESS_KEY, s.access_key_id.as_str()),
        (K_SECRET, sealed.as_str()),
        (K_PUBLIC_URL, s.public_url.as_str()),
        (K_JURISDICTION, s.jurisdiction.as_str()),
        (K_SYNC, flag(s.sync)),
        (K_SERVE, flag(s.serve)),
    ] {
        queries::set_setting(db, k, v).await?;
    }
    Ok(())
}

/// Checks the form values; returns the first problem.
pub fn validate(s: &R2Settings) -> Result<(), String> {
    let all = [&s.account_id, &s.bucket, &s.access_key_id, &s.public_url];
    if all.iter().all(|v| v.is_empty()) && s.secret.is_empty() {
        return if s.sync || s.serve {
            Err("Fill in the R2 settings before turning uploads or serving on.".into())
        } else {
            Ok(())
        };
    }
    if s.account_id.len() != 32 || !s.account_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Account ID must be the 32 hex characters shown in the R2 dashboard.".into());
    }
    let b = s.bucket.as_bytes();
    if !(3..=63).contains(&b.len())
        || !b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        || b[0] == b'-'
        || b[b.len() - 1] == b'-'
    {
        return Err("Bucket name: 3-63 lowercase letters, digits or '-'.".into());
    }
    if s.access_key_id.is_empty()
        || s.access_key_id.len() > 128
        || !s.access_key_id.bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(
            "Access key ID: the letters and digits of the R2 API token's access key.".into(),
        );
    }
    if s.secret.is_empty() {
        return Err("Enter the secret access key.".into());
    }
    if s.secret.len() > 256 || !s.secret.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("The secret access key looks wrong (printable characters only).".into());
    }
    if !matches!(s.jurisdiction.as_str(), "" | "eu" | "fedramp") {
        return Err("Unknown jurisdiction.".into());
    }
    let url =
        crate::config::validate_base_url(&s.public_url).map_err(|e| format!("Public URL {e}."))?;
    if !url.starts_with("https://") {
        return Err("Public URL must be https:// (the bucket's custom domain).".into());
    }
    if url.contains(".r2.dev") {
        return Err(
            "Use a custom domain: r2.dev URLs are rate-limited and meant for development only."
                .into(),
        );
    }
    Ok(())
}

// ---- object keys -----------------------------------------------------------------

/// `<project>/<version>/<path>`: the bucket mirrors the public releases.
pub fn object_key(slug: &str, version: &str, path: &str) -> String {
    format!("{slug}/{}/{path}", version.replace('/', "_"))
}

/// Percent-encodes each `/`-separated segment (S3 canonical URI rules match
/// the RFC 3986 unreserved set used for page links).
pub fn encode_key(key: &str) -> String {
    key.split('/')
        .map(encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

// ---- AWS Signature Version 4 --------------------------------------------------------

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// What a request is signed over.
pub struct SignInput<'a> {
    pub method: &'a str,
    /// Already encoded, e.g. `/bucket/a/b%20c.tar.gz`.
    pub canonical_uri: &'a str,
    /// Unencoded (name, value) pairs.
    pub query: &'a [(&'a str, &'a str)],
    /// Lowercase names; all of them are signed (must include host,
    /// x-amz-content-sha256 and x-amz-date).
    pub headers: &'a BTreeMap<String, String>,
    pub payload_hash: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
    pub region: &'a str,
    pub access_key_id: &'a str,
    pub secret: &'a str,
}

/// The encoded, sorted query string.
fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (encode_path_segment(k), encode_path_segment(v)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Authorization` header value.
pub fn authorization(i: &SignInput<'_>) -> String {
    let canonical_headers: String = i
        .headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed_headers = i.headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        i.method,
        i.canonical_uri,
        canonical_query(i.query),
        i.payload_hash
    );
    let date = &i.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", i.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        i.amz_date,
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac(format!("AWS4{}", i.secret).as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, i.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        i.access_key_id
    )
}

// ---- client ---------------------------------------------------------------------------

/// A minimal S3 client for one R2 bucket.
pub struct Client {
    http: reqwest::Client,
    s: R2Settings,
    /// "auto" for R2 (overridable for tests against other S3 servers).
    region: String,
    single_put_max: u64,
    part_size: u64,
}

impl Client {
    pub fn new(s: &R2Settings) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(15))
            // No overall timeout: multi-GB uploads take as long as they take.
            .read_timeout(Duration::from_secs(120))
            .user_agent("filehost-r2")
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Client {
            http,
            s: s.clone(),
            region: std::env::var("R2_SIGNING_REGION").unwrap_or_else(|_| "auto".into()),
            single_put_max: SINGLE_PUT_MAX,
            part_size: PART_SIZE,
        })
    }

    fn endpoint(&self) -> String {
        // Tests point this at a local S3-compatible server.
        std::env::var("R2_ENDPOINT_OVERRIDE").unwrap_or_else(|_| self.s.endpoint())
    }

    /// Sends one signed request.
    async fn send(
        &self,
        method: reqwest::Method,
        key: &str,
        query: &[(&str, &str)],
        payload_hash: &str,
        body: Option<(reqwest::Body, u64)>,
        extra: &[(&str, String)],
    ) -> Result<reqwest::Response, String> {
        let endpoint = self.endpoint();
        let host = url::Url::parse(&endpoint)
            .ok()
            .and_then(|u| {
                u.host_str()
                    .map(|h| u.port().map_or(h.to_string(), |p| format!("{h}:{p}")))
            })
            .ok_or("bad R2 endpoint")?;
        let canonical_uri = if key.is_empty() {
            format!("/{}", self.s.bucket)
        } else {
            format!("/{}/{}", self.s.bucket, encode_key(key))
        };
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers = BTreeMap::from([
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ]);
        for (k, v) in extra {
            headers.insert(k.to_string(), v.clone());
        }
        let auth = authorization(&SignInput {
            method: method.as_str(),
            canonical_uri: &canonical_uri,
            query,
            headers: &headers,
            payload_hash,
            amz_date: &amz_date,
            region: &self.region,
            access_key_id: &self.s.access_key_id,
            secret: &self.s.secret,
        });
        let qs = canonical_query(query);
        let url = if qs.is_empty() {
            format!("{endpoint}{canonical_uri}")
        } else {
            format!("{endpoint}{canonical_uri}?{qs}")
        };
        let mut req = self
            .http
            .request(method, &url)
            .header("authorization", auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        req = match body {
            Some((b, len)) => req.header("content-length", len).body(b),
            None => req.header("content-length", 0),
        };
        req.send().await.map_err(|e| {
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(": ");
                msg.push_str(&s.to_string());
                src = s.source();
            }
            msg
        })
    }

    /// Fails with R2's error code/message for a non-2xx response.
    async fn check(resp: reqwest::Response, what: &str) -> Result<reqwest::Response, String> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let code = between(&body, "<Code>", "</Code>").unwrap_or_default();
        let message = between(&body, "<Message>", "</Message>").unwrap_or_default();
        Err(format!("{what}: HTTP {status} {code} {message}")
            .trim()
            .to_string())
    }

    /// Uploads `len` bytes from `open(offset, len)` to `key`. `sha256` (hex)
    /// is the content's recorded hash: R2 verifies the bytes against it.
    pub async fn put_object<F, Fut>(
        &self,
        key: &str,
        len: u64,
        sha256: &str,
        filename: &str,
        open: F,
    ) -> Result<(), String>
    where
        F: Fn(u64, u64) -> Fut,
        Fut: std::future::Future<Output = Result<crate::storage::ByteReader, String>>,
    {
        let meta = [
            ("content-type", "application/octet-stream".to_string()),
            (
                "content-disposition",
                crate::util::content_disposition(filename),
            ),
            ("cache-control", OBJECT_CACHE_CONTROL.to_string()),
        ];
        if len <= self.single_put_max {
            let reader = open(0, len).await?;
            let body = reqwest::Body::wrap_stream(ReaderStream::with_capacity(reader, 256 * 1024));
            let resp = self
                .send(
                    reqwest::Method::PUT,
                    key,
                    &[],
                    sha256,
                    Some((body, len)),
                    &meta,
                )
                .await?;
            Self::check(resp, "upload").await?;
            return Ok(());
        }

        // Multipart: each part is hashed first, then sent signed with that hash.
        let resp = self
            .send(
                reqwest::Method::POST,
                key,
                &[("uploads", "")],
                EMPTY_SHA256,
                None,
                &meta,
            )
            .await?;
        let xml = Self::check(resp, "start multipart upload")
            .await?
            .text()
            .await
            .map_err(|e| e.to_string())?;
        let upload_id = between(&xml, "<UploadId>", "</UploadId>")
            .ok_or("start multipart upload: no UploadId in the response")?;
        let result = async {
            let mut parts = Vec::new();
            let mut offset = 0u64;
            let mut number = 1u32;
            while offset < len {
                let part_len = self.part_size.min(len - offset);
                let mut hasher = Sha256::new();
                let mut reader = open(offset, part_len).await?;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                let part_hash = hex::encode(hasher.finalize());
                let reader = open(offset, part_len).await?;
                let body =
                    reqwest::Body::wrap_stream(ReaderStream::with_capacity(reader, 256 * 1024));
                let n = number.to_string();
                let resp = self
                    .send(
                        reqwest::Method::PUT,
                        key,
                        &[("partNumber", &n), ("uploadId", &upload_id)],
                        &part_hash,
                        Some((body, part_len)),
                        &[],
                    )
                    .await?;
                let resp = Self::check(resp, &format!("upload part {number}")).await?;
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .ok_or("upload part: no ETag")?
                    .to_string();
                parts.push(format!(
                    "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
                ));
                offset += part_len;
                number += 1;
            }
            let body = format!(
                "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
                parts.join("")
            );
            let hash = sha256_hex(body.as_bytes());
            let len = body.len() as u64;
            let resp = self
                .send(
                    reqwest::Method::POST,
                    key,
                    &[("uploadId", &upload_id)],
                    &hash,
                    Some((reqwest::Body::from(body), len)),
                    &[],
                )
                .await?;
            let text = Self::check(resp, "complete multipart upload")
                .await?
                .text()
                .await
                .unwrap_or_default();
            if text.contains("<Error>") {
                return Err(format!(
                    "complete multipart upload: {}",
                    between(&text, "<Message>", "</Message>").unwrap_or(text)
                ));
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = self
                .send(
                    reqwest::Method::DELETE,
                    key,
                    &[("uploadId", &upload_id)],
                    EMPTY_SHA256,
                    None,
                    &[],
                )
                .await;
        }
        result
    }

    /// Deletes an object (deleting a missing one is fine).
    pub async fn delete_object(&self, key: &str) -> Result<(), String> {
        let resp = self
            .send(reqwest::Method::DELETE, key, &[], EMPTY_SHA256, None, &[])
            .await?;
        Self::check(resp, "delete").await.map(|_| ())
    }

    /// Size of an object, or None if it does not exist.
    pub async fn head_object(&self, key: &str) -> Result<Option<u64>, String> {
        let resp = self
            .send(reqwest::Method::HEAD, key, &[], EMPTY_SHA256, None, &[])
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = Self::check(resp, "check").await?;
        // Read the header: for HEAD, reqwest reports the (empty) body's length.
        Ok(resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok()))
    }
}

/// Text between two markers (first occurrence).
fn between(s: &str, start: &str, end: &str) -> Option<String> {
    let a = s.find(start)? + start.len();
    let b = s[a..].find(end)? + a;
    Some(s[a..b].to_string())
}

// ---- connection test -------------------------------------------------------------------

/// Uploads a small test object, downloads it through the public URL
/// (SSRF-guarded, like mirror Verify), and deletes it. Returns one line per
/// step; Err stops at the failing step.
pub async fn test_connection(s: &R2Settings) -> Result<Vec<String>, (Vec<String>, String)> {
    let mut done = Vec::new();
    let client = Client::new(s).map_err(|e| (done.clone(), e))?;
    let mut token = [0u8; 8];
    crate::util::os_random(&mut token);
    let key = format!(".filehost-check/{}.txt", hex::encode(token));
    let body = format!("filehost R2 check {}\n", hex::encode(token)).into_bytes();
    let hash = sha256_hex(&body);
    let data = body.clone();
    let open = move |_: u64, _: u64| {
        let data = data.clone();
        async move { Ok::<crate::storage::ByteReader, String>(Box::pin(std::io::Cursor::new(data))) }
    };
    client
        .put_object(&key, body.len() as u64, &hash, "check.txt", open)
        .await
        .map_err(|e| (done.clone(), format!("Uploading a test object failed: {e}")))?;
    done.push(format!("Uploaded a test object to bucket {}.", s.bucket));
    let public = s.public_object_url(&key);
    let fetched = crate::mirrors::verify_http_mirror(&public, body.len() as u64, &hash, None).await;
    let cleanup = client.delete_object(&key).await;
    match fetched {
        Ok(()) => done.push(format!(
            "Downloaded it through {} and the SHA-256 matched.",
            s.public_url
        )),
        Err(e) => {
            return Err((
                done,
                format!(
                    "Downloading it through {public} failed: {e}. Is the custom domain connected to this bucket (R2, bucket, Settings, Custom Domains) and active?"
                ),
            ));
        }
    }
    cleanup.map_err(|e| {
        (
            done.clone(),
            format!("Deleting the test object failed: {e}"),
        )
    })?;
    done.push("Deleted the test object.".into());
    Ok(done)
}

// ---- sync ------------------------------------------------------------------------------

/// The sync job's state, shown in /admin/storage.
#[derive(Clone, Default)]
pub struct SyncStatus {
    pub running: bool,
    /// The file being uploaded now.
    pub current: Option<String>,
    pub last_finished: Option<chrono::DateTime<chrono::Utc>>,
    /// Summary of the last run.
    pub last_result: String,
    /// Retry failed uploads at once on the next run ("Sync now").
    pub force: bool,
}

/// Runs the sync job for the life of the server: every minute, and right
/// away when woken (publish, unpublish, delete, import, "Sync now").
pub fn spawn_worker(st: AppState) {
    tokio::spawn(async move {
        loop {
            let _ = tokio::time::timeout(SYNC_INTERVAL, st.r2_wake.notified()).await;
            let s = st.r2();
            if !s.complete() {
                continue;
            }
            let force = {
                let mut status = st.r2_status.lock().unwrap();
                status.running = true;
                std::mem::take(&mut status.force)
            };
            let result = sync_once(&st, &s, force).await;
            let mut status = st.r2_status.lock().unwrap();
            status.running = false;
            status.current = None;
            status.last_finished = Some(chrono::Utc::now());
            status.last_result = match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "R2 sync failed");
                    format!("failed: {e}")
                }
            };
        }
    });
}

/// One pass: delete objects that must no longer be public, then (when
/// uploads are on) upload what is missing. Returns a summary.
async fn sync_once(st: &AppState, s: &R2Settings, force: bool) -> Result<String, String> {
    let client = Client::new(s)?;
    let db_err = |e: sqlx::Error| e.to_string();
    let wanted = queries::public_files_for_sync(&st.db)
        .await
        .map_err(db_err)?;
    let have = queries::r2_objects(&st.db).await.map_err(db_err)?;
    let wanted_by_id: HashMap<i64, &queries::SyncFile> = wanted.iter().map(|w| (w.id, w)).collect();
    let key_for = |w: &queries::SyncFile| object_key(&w.slug, &w.version, &w.path);

    // 1. Objects whose file is gone or no longer public. Keys still used by
    //    another uploaded file (deleted and re-imported at the same path)
    //    are left alone.
    let live_keys: std::collections::HashSet<String> = have
        .iter()
        .filter(|o| wanted_by_id.contains_key(&o.file_id))
        .map(|o| o.object_key.clone())
        .collect();
    let mut removed = 0;
    for o in have
        .iter()
        .filter(|o| !wanted_by_id.contains_key(&o.file_id))
    {
        if !live_keys.contains(&o.object_key)
            && o.status == "uploaded"
            && let Err(e) = client.delete_object(&o.object_key).await
        {
            tracing::warn!(key = %o.object_key, error = %e, "R2 delete failed; retrying later");
            continue;
        }
        queries::r2_forget(&st.db, o.file_id)
            .await
            .map_err(db_err)?;
        removed += 1;
    }

    if !s.sync {
        return Ok(format!("{removed} removed; uploads are off"));
    }

    // 2. Uploads: missing, failed (after a pause), or under an old key
    //    (renamed project/version).
    let have_by_id: HashMap<i64, &queries::R2Object> =
        have.iter().map(|o| (o.file_id, o)).collect();
    let now = chrono::Utc::now().naive_utc();
    let (mut uploaded, mut failed) = (0, 0);
    for w in &wanted {
        let key = key_for(w);
        let old = have_by_id.get(&w.id);
        let needed = match old {
            None => true,
            Some(o) if o.status == "uploaded" => o.object_key != key,
            Some(o) => {
                force
                    || now
                        .signed_duration_since(o.updated_at)
                        .to_std()
                        .unwrap_or_default()
                        >= RETRY_AFTER
            }
        };
        if !needed {
            continue;
        }
        if !st.r2().sync {
            break; // turned off meanwhile
        }
        st.r2_status.lock().unwrap().current = Some(format!("{}/{}/{}", w.slug, w.version, w.path));
        let backend = st
            .storage
            .get(&w.storage_backend)
            .map_err(|e| e.to_string())?;
        let storage_key = w.storage_key.clone();
        let open = |offset: u64, len: u64| {
            let backend = backend.clone();
            let storage_key = storage_key.clone();
            async move {
                backend
                    .open(&storage_key, offset, len)
                    .await
                    .map_err(|e| e.to_string())
            }
        };
        match client
            .put_object(&key, w.size_bytes as u64, &w.sha256, &w.filename, open)
            .await
        {
            Ok(()) => {
                queries::r2_record(&st.db, w.id, &key, w.size_bytes, "uploaded", None)
                    .await
                    .map_err(db_err)?;
                // A renamed project/version: drop the copy under the old key.
                if let Some(o) = old
                    && o.object_key != key
                    && o.status == "uploaded"
                    && let Err(e) = client.delete_object(&o.object_key).await
                {
                    tracing::warn!(key = %o.object_key, error = %e, "could not delete an old R2 key");
                }
                tracing::info!(file_id = w.id, key = %key, "uploaded to R2");
                uploaded += 1;
            }
            Err(e) => {
                tracing::warn!(file_id = w.id, error = %e, "R2 upload failed");
                queries::r2_record(&st.db, w.id, &key, w.size_bytes, "failed", Some(&e))
                    .await
                    .map_err(db_err)?;
                failed += 1;
            }
        }
    }
    Ok(format!(
        "{uploaded} uploaded, {failed} failed, {removed} removed"
    ))
}

/// Where a download should go: the R2 copy's URL when serving from R2 is on
/// and this file's copy is uploaded under its current key.
pub async fn redirect_target(st: &AppState, file_id: i64) -> Option<String> {
    let s = st.r2();
    if !s.serve || !s.complete() {
        return None;
    }
    match queries::r2_object(&st.db, file_id).await {
        Ok(Some(o)) if o.status == "uploaded" => Some(s.public_object_url(&o.object_key)),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "R2 lookup failed; serving locally");
            None
        }
    }
}

/// Wakes the sync job (after publishing changes, deletions and imports).
pub fn wake(st: &AppState) {
    st.r2_wake.notify_one();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the AWS S3 SigV4 documentation
    /// ("GET Object", examplebucket, 20130524).
    #[test]
    fn sigv4_matches_the_aws_example() {
        let headers = BTreeMap::from([
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ]);
        let auth = authorization(&SignInput {
            method: "GET",
            canonical_uri: "/test.txt",
            query: &[],
            headers: &headers,
            payload_hash: EMPTY_SHA256,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn query_and_keys_are_encoded() {
        assert_eq!(
            canonical_query(&[("uploadId", "a b/c"), ("partNumber", "2")]),
            "partNumber=2&uploadId=a%20b%2Fc"
        );
        assert_eq!(canonical_query(&[("uploads", "")]), "uploads=");
        assert_eq!(
            encode_key("sanctum/v0.1 rc/sources/a+b.tar.gz"),
            "sanctum/v0.1%20rc/sources/a%2Bb.tar.gz"
        );
        assert_eq!(object_key("s", "1/2", "a/b"), "s/1_2/a/b");
    }

    #[test]
    fn settings_validation() {
        let good = R2Settings {
            account_id: "0123456789abcdef0123456789abcdef".into(),
            bucket: "abyssal-downloads".into(),
            access_key_id: "AKIA0123456789".into(),
            secret: "s3cr3t/with+chars".into(),
            public_url: "https://dl.example.com".into(),
            jurisdiction: String::new(),
            sync: true,
            serve: true,
        };
        assert!(validate(&good).is_ok());
        assert!(validate(&R2Settings::default()).is_ok(), "all empty = off");
        let bad = |f: fn(&mut R2Settings)| {
            let mut s = good.clone();
            f(&mut s);
            validate(&s).is_err()
        };
        assert!(bad(|s| s.account_id = "xyz".into()));
        assert!(bad(|s| s.bucket = "Bad_Bucket".into()));
        assert!(bad(|s| s.bucket = "-x-".into()));
        assert!(bad(|s| s.access_key_id = "a b".into()));
        assert!(bad(|s| s.secret = String::new()));
        assert!(bad(|s| s.public_url = "http://dl.example.com".into()));
        assert!(bad(|s| s.public_url = "https://pub-123.r2.dev".into()));
        assert!(bad(|s| s.public_url = "https://dl.example.com/path".into()));
        assert!(bad(|s| s.jurisdiction = "mars".into()));
        let mut off = R2Settings {
            sync: true,
            ..R2Settings::default()
        };
        assert!(validate(&off).is_err(), "cannot turn on without settings");
        off.sync = false;
        assert!(validate(&off).is_ok());
        assert_eq!(
            good.endpoint(),
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
        );
        let eu = R2Settings {
            jurisdiction: "eu".into(),
            ..good.clone()
        };
        assert!(eu.endpoint().contains(".eu.r2.cloudflarestorage.com"));
        assert_eq!(
            good.public_object_url("p/1.0/a b.iso"),
            "https://dl.example.com/p/1.0/a%20b.iso"
        );
    }

    #[test]
    fn secrets_are_sealed_and_redacted() {
        let master = [7u8; 32];
        let sealed = crate::totp::encrypt(&sealing_key(&master), b"secret");
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(
            crate::totp::decrypt(&sealing_key(&master), &sealed).unwrap(),
            b"secret"
        );
        assert!(crate::totp::decrypt(&sealing_key(&[8u8; 32]), &sealed).is_none());
        let s = R2Settings {
            secret: "hunter2".into(),
            ..R2Settings::default()
        };
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    /// Against a local S3-compatible server (e.g. MinIO): set
    /// R2_ENDPOINT_OVERRIDE (e.g. http://127.0.0.1:9000), R2_TEST_KEY,
    /// R2_TEST_SECRET and R2_TEST_BUCKET, then
    /// `cargo test --lib r2 -- --ignored`. Single and multipart uploads,
    /// a rejected wrong hash, head and delete.
    #[tokio::test]
    #[ignore]
    async fn against_s3_compatible_server() {
        let s = R2Settings {
            account_id: "0".repeat(32),
            bucket: std::env::var("R2_TEST_BUCKET").expect("R2_TEST_BUCKET"),
            access_key_id: std::env::var("R2_TEST_KEY").expect("R2_TEST_KEY"),
            secret: std::env::var("R2_TEST_SECRET").expect("R2_TEST_SECRET"),
            public_url: "https://unused.example".into(),
            ..R2Settings::default()
        };
        let mut c = Client::new(&s).unwrap();
        c.region = "us-east-1".into();
        c.single_put_max = 6 << 20;
        c.part_size = 5 << 20;
        for (len, key) in [
            (1000usize, "t/small file.bin"),
            (12 << 20, "t/sources/multi part.bin"),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let hash = sha256_hex(&data);
            let d = data.clone();
            let open = move |off: u64, n: u64| {
                let part = d[off as usize..(off + n) as usize].to_vec();
                async move {
                    Ok::<crate::storage::ByteReader, String>(Box::pin(std::io::Cursor::new(part)))
                }
            };
            c.put_object(key, len as u64, &hash, "x.bin", open)
                .await
                .unwrap();
            assert_eq!(c.head_object(key).await.unwrap(), Some(len as u64), "{key}");
            // A wrong hash is rejected by the server (single uploads).
            if len < 6 << 20 {
                let d = data.clone();
                let open = move |_: u64, _: u64| {
                    let d = d.clone();
                    async move {
                        Ok::<crate::storage::ByteReader, String>(Box::pin(std::io::Cursor::new(d)))
                    }
                };
                assert!(
                    c.put_object("t/bad", len as u64, EMPTY_SHA256, "x", open)
                        .await
                        .is_err()
                );
            }
            c.delete_object(key).await.unwrap();
            assert_eq!(c.head_object(key).await.unwrap(), None);
        }
    }
}
