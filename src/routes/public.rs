//! Public pages: home, project and release pages, downloads, checksums,
//! files.json, health check, stylesheet.
//!
//! Stable download URLs: /p/<project>/<version>/<path> (plain GET with
//! Range support, no redirects, tokens or cookies). /download/<id> keeps
//! working for older links.
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
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use crate::checksums::{Algo, build_sums, sums_line};
use crate::db::models::{FileRow, Mirror, Project, ProjectListItem, Release, status};
use crate::db::queries;
use crate::error::AppError;
use crate::markdown;
use crate::net::ClientInfo;
use crate::range::{RangeResult, parse_range};
use crate::state::AppState;
use crate::tree::{self, TreeRow};
use crate::util::{encode_path_segment, human_size};
use crate::views::{Layout, render};

/// The whole theme, compiled into the binary.
pub const STYLE_CSS: &str = include_str!("../../static/style.css");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/p/{slug}", get(project))
        .route("/p/{slug}/latest", get(latest_release))
        .route("/p/{slug}/latest/download", get(latest_download))
        .route("/p/{slug}/{version}", get(release_page))
        .route("/p/{slug}/{version}/files.json", get(files_json))
        .route("/p/{slug}/{version}/{*path}", get(release_file))
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

/// A downloadable file as shown on the public pages.
pub struct FileView {
    pub filename: String,
    /// Place in the release tree, e.g. "sources/a.tar.gz".
    pub path: String,
    pub size: String,
    pub sha256: String,
    /// None for files from before SHA-512 was recorded ("n/a").
    pub sha512: Option<String>,
    pub downloads: i64,
    /// The stable URL /p/<project>/<version>/<path>.
    pub download_url: String,
    pub sha256_url: String,
    pub sha512_url: Option<String>,
    /// Approved mirrors; empty unless EXTERNAL_MIRRORS_ENABLED.
    pub mirrors: Vec<MirrorLink>,
    /// Never set while torrents are a stub (see docs/TORRENTS.md).
    pub torrent_url: Option<String>,
    /// The release's recommended file.
    pub recommended: bool,
}

/// A public mirror link: "Mirror (<label>)" or "Torrent (<label>)".
pub struct MirrorLink {
    pub text: String,
    pub url: String,
}

/// A top-level folder of a release, summarized on the project page.
pub struct FolderSummary {
    pub name: String,
    pub files: usize,
    pub size: String,
}

pub struct ReleaseView {
    pub version: String,
    pub date: String,
    pub notes_html: String,
    /// /p/<project>/<version>.
    pub page_url: String,
    pub files_json_url: String,
    /// Top-level files, the recommended one first (the main downloads).
    pub main: Vec<FileView>,
    /// Top-level folders (project page; the release page shows `tree`).
    pub folders: Vec<FolderSummary>,
    /// Every file as a folder tree (release page only).
    pub tree: Vec<TreeRow<FileView>>,
    pub file_count: usize,
    pub total_size: String,
    pub recommended_url: Option<String>,
    pub sha256sums_url: String,
    pub sha512sums_url: String,
    /// e.g. "sha256sum -c SHA256SUMS".
    pub verify_hint: &'static str,
    /// SHA256SUMS.asc, when SIGN_CHECKSUMS is on and the signature is current.
    pub signature_url: Option<String>,
}

fn mirror_links(mirrors: &[Mirror], file_id: i64) -> Vec<MirrorLink> {
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
}

/// A published release for the templates. `full` builds the whole tree
/// (release page); otherwise only the main files and folder summaries.
fn release_view(
    st: &AppState,
    p: &Project,
    r: Release,
    files: Vec<FileRow>,
    mirrors: &[Mirror],
    full: bool,
) -> ReleaseView {
    let base = format!("/p/{}/{}", p.slug, encode_path_segment(&r.version));
    let signature_url = (st.config.sign_checksums && current_signature(&r, &files).is_some())
        .then(|| format!("{base}/SHA256SUMS.asc"));
    let file_count = files.len();
    let total: u64 = files.iter().map(|f| f.size_bytes as u64).sum();
    let mut views: Vec<(u64, FileView)> = files
        .into_iter()
        .map(|f| {
            let size = f.size_bytes as u64;
            let view = FileView {
                download_url: st.release_file_url(&p.slug, &r.version, &f.path),
                sha256_url: st.checksum_url(f.id, Algo::Sha256),
                sha512_url: f
                    .sha512
                    .as_ref()
                    .map(|_| st.checksum_url(f.id, Algo::Sha512)),
                mirrors: mirror_links(mirrors, f.id),
                recommended: r.recommended_file_id == Some(f.id),
                filename: f.filename,
                path: f.path,
                size: human_size(size),
                sha256: f.sha256,
                sha512: f.sha512,
                downloads: f.download_count,
                torrent_url: None,
            };
            (size, view)
        })
        .collect();
    views.sort_by(|a, b| (!a.1.recommended, &a.1.path).cmp(&(!b.1.recommended, &b.1.path)));
    let recommended_url = views
        .iter()
        .find(|v| v.1.recommended)
        .map(|v| v.1.download_url.clone());

    let (main, tree, folders) = if full {
        let tree = tree::build(
            views
                .into_iter()
                .map(|(s, v)| (v.path.clone(), s, v))
                .collect(),
        );
        (Vec::new(), tree, Vec::new())
    } else {
        let mut main = Vec::new();
        let mut folders: std::collections::BTreeMap<String, (usize, u64)> =
            std::collections::BTreeMap::new();
        for (size, v) in views {
            match v.path.split_once('/') {
                Some((top, _)) => {
                    let e = folders.entry(top.to_string()).or_default();
                    e.0 += 1;
                    e.1 += size;
                }
                None => main.push(v),
            }
        }
        let folders = folders
            .into_iter()
            .map(|(name, (files, bytes))| FolderSummary {
                name,
                files,
                size: human_size(bytes),
            })
            .collect();
        (main, Vec::new(), folders)
    };

    ReleaseView {
        signature_url,
        sha256sums_url: format!("{base}/SHA256SUMS"),
        sha512sums_url: format!("{base}/SHA512SUMS"),
        files_json_url: format!("{base}/files.json"),
        verify_hint: Algo::Sha256.verify_hint(),
        page_url: base,
        version: r.version,
        date: r.released_at.format("%Y-%m-%d").to_string(),
        notes_html: markdown::render(&r.notes_md),
        main,
        folders,
        tree,
        file_count,
        total_size: human_size(total),
        recommended_url,
    }
}

/// Approved mirrors of a project's files; not even read while sharing is off.
async fn public_mirrors(st: &AppState, project_id: i64) -> Result<Vec<Mirror>, AppError> {
    Ok(if st.site().external_mirrors_enabled {
        queries::approved_mirrors_for_project(&st.db, project_id).await?
    } else {
        Vec::new()
    })
}

#[derive(Template)]
#[template(path = "project.html")]
struct ProjectTemplate {
    l: Layout,
    /// /gpg.pub is published.
    has_gpg_key: bool,
    slug: String,
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
    let mirrors = public_mirrors(&st, p.id).await?;
    let releases = releases
        .into_iter()
        .map(|r| {
            let (mine, rest): (Vec<_>, Vec<_>) =
                files.drain(..).partition(|f| f.release_id == r.id);
            files = rest;
            release_view(&st, &p, r, mine, &mirrors, false)
        })
        .collect();

    render(&ProjectTemplate {
        has_gpg_key: !st.site().gpg_public_key.is_empty(),
        l: st.layout(p.name.clone(), None),
        slug: p.slug,
        name: p.name,
        summary: p.summary,
        description_html: markdown::render(&p.description_md),
        releases,
    })
}

#[derive(Template)]
#[template(path = "release.html")]
struct ReleaseTemplate {
    l: Layout,
    has_gpg_key: bool,
    slug: String,
    name: String,
    r: ReleaseView,
    is_latest: bool,
}

/// A published release and its project, or 404.
async fn public_release(
    st: &AppState,
    slug: &str,
    version: &str,
) -> Result<(Project, Release), AppError> {
    let r = queries::get_release_by_slug_version(&st.db, slug, version)
        .await?
        .ok_or(AppError::NotFound)?;
    let p = queries::get_project_by_slug(&st.db, slug)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((p, r))
}

/// /p/<project>/<version>: notes, the main downloads, then every folder
/// (collapsed) with sizes and SHA-256s.
async fn release_page(
    State(st): State<AppState>,
    Path((slug, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (p, r) = public_release(&st, &slug, &version).await?;
    let latest = queries::latest_public_release(&st.db, &slug).await?;
    let files: Vec<FileRow> = queries::files_for_release(&st.db, r.id)
        .await?
        .into_iter()
        .filter(|f| f.status == status::READY)
        .collect();
    let mirrors = public_mirrors(&st, p.id).await?;
    let is_latest = latest.is_some_and(|l| l.id == r.id);
    let view = release_view(&st, &p, r, files, &mirrors, true);
    render(&ReleaseTemplate {
        has_gpg_key: !st.site().gpg_public_key.is_empty(),
        l: st.layout(format!("{} {}", p.name, view.version), None),
        slug: p.slug,
        name: p.name,
        r: view,
        is_latest,
    })
}

/// /p/<project>/latest: the newest published release's page.
async fn latest_release(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let r = queries::latest_public_release(&st.db, &slug)
        .await?
        .ok_or(AppError::NotFound)?;
    let to = format!("/p/{slug}/{}", encode_path_segment(&r.version));
    Ok(Redirect::to(&to).into_response())
}

/// /p/<project>/latest/download: one redirect to the stable URL of the
/// newest release's recommended file (so clients save it under its real
/// name and version).
async fn latest_download(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let r = queries::latest_public_release(&st.db, &slug)
        .await?
        .ok_or(AppError::NotFound)?;
    let missing = || {
        AppError::NotFoundMsg(format!(
            "Release {} has no recommended file yet; see /p/{slug}/latest for its files.",
            r.version
        ))
    };
    let file_id = r.recommended_file_id.ok_or_else(missing)?;
    let f = queries::get_public_file(&st.db, file_id)
        .await?
        .ok_or_else(missing)?;
    // Straight to the R2 copy when it serves downloads: one hop, never two.
    let to = match crate::r2::redirect_target(&st, f.id).await {
        Some(url) => url,
        None => st.release_file_url(&slug, &r.version, &f.path),
    };
    Ok(Redirect::to(&to).into_response())
}

/// /p/<project>/<version>/<path>: the stable direct download (served from
/// here, or one redirect to its R2 copy when that is on).
async fn release_file(
    State(st): State<AppState>,
    Path((slug, version, path)): Path<(String, String, String)>,
    client: ClientInfo,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let f = queries::get_public_file_by_path(&st.db, &slug, &version, &path)
        .await?
        .ok_or(AppError::NotFound)?;
    if let Some(resp) = r2_redirect(&st, &f, &method, &headers).await {
        return Ok(resp);
    }
    serve_file(&st, f, client, method, &headers, true).await
}

#[derive(serde::Serialize)]
struct FilesJson {
    project: String,
    version: String,
    released_at: String,
    /// Path of the recommended file, if any.
    recommended: Option<String>,
    files: Vec<FileJson>,
}

#[derive(serde::Serialize)]
struct FileJson {
    path: String,
    size: i64,
    sha256: String,
    sha512: Option<String>,
    url: String,
}

/// /p/<project>/<version>/files.json: every ready file with path, size,
/// hashes and absolute URL (PUBLIC_URL or DOWNLOAD_BASE_URL; relative when
/// neither is set), for release scripts.
async fn files_json(
    State(st): State<AppState>,
    Path((slug, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (p, r) = public_release(&st, &slug, &version).await?;
    let mut files: Vec<FileRow> = queries::files_for_release(&st.db, r.id)
        .await?
        .into_iter()
        .filter(|f| f.status == status::READY)
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let site = st.site();
    let base = if site.download_base_url.is_empty() {
        st.config
            .public_url
            .as_deref()
            .unwrap_or("")
            .trim_end_matches('/')
            .to_string()
    } else {
        site.download_base_url.clone()
    };
    let body = FilesJson {
        recommended: files
            .iter()
            .find(|f| r.recommended_file_id == Some(f.id))
            .map(|f| f.path.clone()),
        files: files
            .iter()
            .map(|f| FileJson {
                url: crate::util::build_release_file_url(&base, &p.slug, &r.version, &f.path),
                path: f.path.clone(),
                size: f.size_bytes,
                sha256: f.sha256.clone(),
                sha512: f.sha512.clone(),
            })
            .collect(),
        project: p.slug,
        version: r.version,
        released_at: r.released_at.format("%Y-%m-%d").to_string(),
    };
    let json = serde_json::to_string_pretty(&body).map_err(AppError::internal)?;
    let mut resp = Response::new(Body::from(json + "\n"));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(resp)
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
    if let Some(resp) = r2_redirect(&st, &f, &method, &headers).await {
        return Ok(resp);
    }
    serve_file(&st, f, client, method, &headers, true).await
}

/// With "Serve downloads from R2" on and this file's copy uploaded: one
/// `302` to the copy (counted like a download that starts at byte 0).
/// Otherwise None, and the file is served from here.
async fn r2_redirect(
    st: &AppState,
    f: &FileRow,
    method: &Method,
    headers: &HeaderMap,
) -> Option<Response> {
    let url = crate::r2::redirect_target(st, f.id).await?;
    let from_start = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(r) => matches!(
            parse_range(Some(r), f.size_bytes as u64),
            RangeResult::Full | RangeResult::Partial { start: 0, .. }
        ),
    };
    if *method == Method::GET
        && from_start
        && let Err(e) = queries::increment_downloads(&st.db, f.id).await
    {
        tracing::warn!(error = %e, "could not count download");
    }
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::FOUND;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&url) {
        h.insert(header::LOCATION, v);
    }
    // Never cached: turning R2 off must take effect at once.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Some(resp)
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
