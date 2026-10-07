//! Public pages: home, project pages, downloads, health check, stylesheet.
//! Nothing here reads cookies or sessions, so /download works on any host
//! name (e.g. a separate download domain pointing at the same app).
//!
//! Only approved projects and releases exist here (member content awaiting
//! review is 404 everywhere public: pages, downloads, checksums).

use askama::Template;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use crate::checksums::{Algo, build_sums, sums_line};
use crate::db::models::{FileRow, ProjectListItem};
use crate::db::queries;
use crate::error::AppError;
use crate::markdown;
use crate::net::ClientInfo;
use crate::range::{RangeResult, parse_range};
use crate::state::AppState;
use crate::util::{encode_path_segment, human_size};
use crate::views::{Layout, render};

/// The whole theme, compiled into the binary.
pub const STYLE_CSS: &str = include_str!("../../static/style.css");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/p/{slug}", get(project))
        .route("/download/{file_id}", get(download))
        .route("/download/{file_id}/torrent", get(torrent))
        .route("/download/{file_id}/sha256", get(file_sha256))
        .route("/download/{file_id}/sha512", get(file_sha512))
        .route("/p/{slug}/{version}/SHA256SUMS", get(sha256sums))
        .route("/p/{slug}/{version}/SHA512SUMS", get(sha512sums))
        .route(
            "/p/{slug}/{version}/SHA256SUMS.asc",
            get(sha256sums_signature),
        )
        .route("/gpg.pub", get(gpg_public_key))
        .route("/healthz", get(healthz))
        .route("/static/style.css", get(stylesheet))
}

pub async fn not_found() -> AppError {
    AppError::NotFound
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    l: Layout,
    projects: Vec<ProjectListItem>,
}

async fn index(State(st): State<AppState>) -> Result<Response, AppError> {
    let projects = queries::list_projects(&st.db).await?;
    render(&IndexTemplate {
        l: st.layout("", None),
        projects,
    })
}

/// A downloadable file as shown on the public project page.
pub struct FileView {
    pub filename: String,
    pub size: String,
    pub sha256: String,
    /// None for files from before SHA-512 was recorded ("n/a").
    pub sha512: Option<String>,
    pub downloads: i64,
    pub download_url: String,
    pub sha256_url: String,
    pub sha512_url: Option<String>,
    /// Approved mirrors; empty unless EXTERNAL_MIRRORS_ENABLED.
    pub mirrors: Vec<MirrorLink>,
    /// Never set while torrents are a stub (see docs/TORRENTS.md).
    pub torrent_url: Option<String>,
}

/// A public mirror link: "Mirror (<label>)" or "Torrent (<label>)".
pub struct MirrorLink {
    pub text: String,
    pub url: String,
}

pub struct ReleaseView {
    pub version: String,
    pub date: String,
    pub notes_html: String,
    pub files: Vec<FileView>,
    pub sha256sums_url: String,
    pub sha512sums_url: String,
    /// e.g. "sha256sum -c SHA256SUMS".
    pub verify_hint: &'static str,
    /// SHA256SUMS.asc, when SIGN_CHECKSUMS is on and the signature is current.
    pub signature_url: Option<String>,
}

#[derive(Template)]
#[template(path = "project.html")]
struct ProjectTemplate {
    l: Layout,
    /// /gpg.pub is published.
    has_gpg_key: bool,
    name: String,
    summary: String,
    description_html: String,
    releases: Vec<ReleaseView>,
}

async fn project(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let p = queries::get_project_by_slug(&st.db, &slug)
        .await?
        .ok_or(AppError::NotFound)?;
    let releases = queries::list_public_releases(&st.db, p.id).await?;
    let mut files = queries::ready_files_for_project(&st.db, p.id).await?;
    // With external sharing off, mirrors are not even read.
    let mirrors = if st.site().external_mirrors_enabled {
        queries::approved_mirrors_for_project(&st.db, p.id).await?
    } else {
        Vec::new()
    };
    let mirror_links = |file_id: i64| -> Vec<MirrorLink> {
        mirrors
            .iter()
            .filter(|m| m.file_id == file_id)
            .map(|m| MirrorLink {
                text: format!(
                    "{} ({})",
                    if m.kind == "torrent" {
                        "Torrent"
                    } else {
                        "Mirror"
                    },
                    m.label
                ),
                url: m.url.clone(),
            })
            .collect()
    };

    let releases = releases
        .into_iter()
        .map(|r| {
            let (mine, rest): (Vec<_>, Vec<_>) =
                files.drain(..).partition(|f| f.release_id == r.id);
            files = rest;
            let sums_base = format!("/p/{}/{}", p.slug, encode_path_segment(&r.version));
            let signature_url = (st.config.sign_checksums
                && current_signature(&r, &mine).is_some())
            .then(|| format!("{sums_base}/SHA256SUMS.asc"));
            ReleaseView {
                signature_url,
                sha256sums_url: format!("{sums_base}/SHA256SUMS"),
                sha512sums_url: format!("{sums_base}/SHA512SUMS"),
                verify_hint: Algo::Sha256.verify_hint(),
                version: r.version,
                date: r.released_at.format("%Y-%m-%d").to_string(),
                notes_html: markdown::render(&r.notes_md),
                files: mine
                    .into_iter()
                    .map(|f| FileView {
                        download_url: st.download_url(f.id),
                        sha256_url: st.checksum_url(f.id, Algo::Sha256),
                        sha512_url: f
                            .sha512
                            .as_ref()
                            .map(|_| st.checksum_url(f.id, Algo::Sha512)),
                        filename: f.filename,
                        size: human_size(f.size_bytes as u64),
                        sha256: f.sha256,
                        sha512: f.sha512,
                        downloads: f.download_count,
                        mirrors: mirror_links(f.id),
                        torrent_url: None,
                    })
                    .collect(),
            }
        })
        .collect();

    render(&ProjectTemplate {
        has_gpg_key: !st.site().gpg_public_key.is_empty(),
        l: st.layout(p.name.clone(), None),
        name: p.name,
        summary: p.summary,
        description_html: markdown::render(&p.description_md),
        releases,
    })
}

/// A published file (ready, approved release of an approved project).
async fn public_file(st: &AppState, file_id: i64) -> Result<FileRow, AppError> {
    queries::get_public_file(&st.db, file_id)
        .await?
        .ok_or(AppError::NotFound)
}

async fn download(
    State(st): State<AppState>,
    Path(file_id): Path<i64>,
    client: ClientInfo,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let f = public_file(&st, file_id).await?;
    serve_file(&st, f, client, method, &headers, true).await
}

/// Streams a ready file from storage with Range/resume support. With
/// `count`, a download is counted only for GET requests that start at byte
/// 0, so resumed or segmented downloads are not counted several times.
pub async fn serve_file(
    st: &AppState,
    f: FileRow,
    client: ClientInfo,
    method: Method,
    headers: &HeaderMap,
    count: bool,
) -> Result<Response, AppError> {
    let backend = st.storage.get(&f.storage_backend)?;
    let size = f.size_bytes as u64;
    let etag = format!("\"{}\"", f.sha256);

    // If-Range: only honor the Range header if the client's copy is current.
    let if_range_ok = headers
        .get(header::IF_RANGE)
        .map(|v| v.as_bytes() == etag.as_bytes())
        .unwrap_or(true);
    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|_| if_range_ok);

    let (status_code, start, len) = match parse_range(range_header, size) {
        RangeResult::Full => (StatusCode::OK, 0, size),
        RangeResult::Partial { start, end } => {
            (StatusCode::PARTIAL_CONTENT, start, end - start + 1)
        }
        RangeResult::Unsatisfiable => {
            return Ok((
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{size}"))],
            )
                .into_response());
        }
    };

    // DOWNLOAD_MAX_CONCURRENT / DOWNLOAD_MAX_PER_IP; the slot is held until
    // the response body has been sent (or the client disconnects).
    let Some(slot) = st.downloads.try_acquire(client.ip) else {
        return Err(AppError::TooManyRequests(
            "Too many downloads at once from your address (or on the server). Try again in a minute.".into(),
        ));
    };
    let reader = backend.open(&f.storage_key, start, len).await?;
    if count
        && method == Method::GET
        && start == 0
        && let Err(e) = queries::increment_downloads(&st.db, f.id).await
    {
        tracing::warn!(error = %e, "could not count download");
    }

    let stream = ReaderStream::with_capacity(reader, 256 * 1024).map(move |chunk| {
        let _held = &slot;
        chunk
    });
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = status_code;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-transform"),
    );
    // RFC 6266 attachment with an RFC 5987 filename* (injection safe).
    if let Ok(v) = HeaderValue::from_str(&crate::util::content_disposition(&f.filename)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    if status_code == StatusCode::PARTIAL_CONTENT {
        let range = format!("bytes {}-{}/{}", start, start + len - 1, size);
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&range).expect("ascii"),
        );
    }
    Ok(resp)
}

/// Torrent download: hidden (404) unless TORRENT_ENABLED, and a stub (501)
/// until generation is implemented. See docs/TORRENTS.md.
async fn torrent(
    State(st): State<AppState>,
    Path(file_id): Path<i64>,
) -> Result<Response, AppError> {
    if !st.config.torrent_enabled {
        return Err(AppError::NotFound);
    }
    public_file(&st, file_id).await?;
    // Plan (docs/TORRENTS.md): resolve the stored object's local path, call
    // crate::torrent::generate_torrent(path, &f.filename, piece_length,
    // trackers, &[st.download_url_for_torrent(f.id)]), cache the result and
    // record files.torrent_infohash. Until then this is a themed 501.
    Err(AppError::NotImplemented(
        "Torrent downloads are not available yet. Please use the direct download.".into(),
    ))
}

// ---- checksum files ------------------------------------------------------------
// Generated from the database on every request (Cache-Control: no-cache), in
// GNU coreutils format. Like downloads: no cookies, any Host header.

fn text_response(body: String, filename: &str) -> Response {
    let mut resp = Response::new(Body::from(body));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    let disposition =
        crate::util::content_disposition(filename).replacen("attachment", "inline", 1);
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

async fn release_files(st: &AppState, slug: &str, version: &str) -> Result<Vec<FileRow>, AppError> {
    let release = queries::get_release_by_slug_version(&st.db, slug, version)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(queries::files_for_release(&st.db, release.id).await?)
}

async fn sums(
    st: AppState,
    slug: String,
    version: String,
    algo: Algo,
) -> Result<Response, AppError> {
    let files = release_files(&st, &slug, &version).await?;
    let name = match algo {
        Algo::Sha256 => "SHA256SUMS",
        Algo::Sha512 => "SHA512SUMS",
    };
    Ok(text_response(build_sums(&files, algo), name))
}

async fn sha256sums(
    State(st): State<AppState>,
    Path((slug, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    sums(st, slug, version, Algo::Sha256).await
}

async fn sha512sums(
    State(st): State<AppState>,
    Path((slug, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    sums(st, slug, version, Algo::Sha512).await
}

/// Detached GPG signature of SHA256SUMS: 404 unless SIGN_CHECKSUMS, then a
/// themed 501 until signing exists (plan in docs/FUTURE.md).
/// The detached signature of SHA256SUMS, made by the admin on their own
/// machine and served verbatim (the server holds no private key). 404 when
/// SIGN_CHECKSUMS is off, when there is none, or when the release's file set
/// changed since signing (it would no longer verify).
async fn sha256sums_signature(
    State(st): State<AppState>,
    Path((slug, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    if !st.config.sign_checksums {
        return Err(AppError::NotFound);
    }
    let release = queries::get_release_by_slug_version(&st.db, &slug, &version)
        .await?
        .ok_or(AppError::NotFound)?;
    let files = queries::files_for_release(&st.db, release.id).await?;
    match current_signature(&release, &files) {
        Some(sig) => Ok(text_response(sig.to_string(), "SHA256SUMS.asc")),
        None => Err(AppError::NotFound),
    }
}

/// The release's signature if it still matches the current SHA256SUMS.
pub fn current_signature<'a>(
    release: &'a crate::db::models::Release,
    files: &[FileRow],
) -> Option<&'a str> {
    let sig = release.sums_signature.as_deref()?;
    let signed = release.sums_signed_sha256.as_deref()?;
    let current = crate::util::sha256_hex(build_sums(files, Algo::Sha256).as_bytes());
    crate::util::ct_eq(signed, &current).then_some(sig)
}

/// The admin's public key (set in /admin/settings), as plain text.
async fn gpg_public_key(State(st): State<AppState>) -> Result<Response, AppError> {
    let key = st.site().gpg_public_key;
    if key.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(text_response(key, "gpg.pub"))
}

async fn file_checksum(st: AppState, file_id: i64, algo: Algo) -> Result<Response, AppError> {
    let f = public_file(&st, file_id).await?;
    let hash = algo.hash_of(&f).ok_or(AppError::NotFound)?;
    let ext = match algo {
        Algo::Sha256 => "sha256",
        Algo::Sha512 => "sha512",
    };
    Ok(text_response(
        sums_line(hash, &f.filename),
        &format!("{}.{ext}", f.filename),
    ))
}

async fn file_sha256(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    file_checksum(st, id, Algo::Sha256).await
}

async fn file_sha512(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    file_checksum(st, id, Algo::Sha512).await
}

async fn healthz(State(st): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&st.db).await {
        Ok(_) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "health check: database unreachable");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable").into_response()
        }
    }
}

#[derive(Deserialize)]
struct CssQuery {
    v: Option<String>,
}

/// Serves the embedded stylesheet. Versioned URLs (`?v=<hash>`, as emitted
/// by the base template) are cached for a year.
async fn stylesheet(
    State(st): State<AppState>,
    Query(q): Query<CssQuery>,
    headers: HeaderMap,
) -> Response {
    let etag = format!("\"{}\"", st.css_version);
    let cache = if q.v.as_deref() == Some(&*st.css_version) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=300"
    };
    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes())
    {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, cache.into())],
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, cache.to_string()),
            (header::ETAG, etag),
        ],
        STYLE_CSS,
    )
        .into_response()
}
