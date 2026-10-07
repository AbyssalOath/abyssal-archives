//! Admin area: dashboard, project/release CRUD, file import and upload,
//! mirrors, site settings. Every POST verifies the session's CSRF token.
//!
//! Project, release and file handlers are mounted twice: under /admin for
//! administrators (every project) and under /my for members (only their own
//! projects; see docs/MEMBERS.md). They take [`Actor`]; the admin-only ones
//! (import, mirrors, signatures, settings, ...) take [`AdminUser`].

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use askama::Template;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Form, Multipart, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::{NaiveDate, Utc};
use futures_util::TryStreamExt;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use super::auth::{Actor, AdminUser};
use crate::config::parse_size;
use crate::config::{Config, validate_base_url};
use crate::db::models::{
    FileRow, Mirror, Project, Release, Stats, WorkspaceProject, review, status,
};
use crate::db::queries::{self, NewFile, NewMirror, ProjectInput, is_unique_violation};
use crate::error::AppError;
use crate::fsid::{FileIdentity, open_regular};
use crate::hashing::{Digests, MultiHasher, hash_file, hash_reader};
use crate::incoming;
use crate::mirrors::{
    self, MirrorKind, archive_org_urls, clean_label, github_release_url, status as mirror_status,
    validate_mirror,
};
use crate::net::ClientInfo;
use crate::settings::{self, SiteSettings};
use crate::state::AppState;
use crate::storage::{StorageBackend, new_key};
use crate::util::{human_size, is_valid_slug, sanitize_filename, slugify};
use crate::views::{Layout, render};

/// Longest description / release notes (forms are capped at 64 KiB).
const MAX_TEXT_BYTES: usize = 60_000;

pub fn routes(config: &Config) -> Router<AppState> {
    Router::new()
        .merge(workspace_routes("/admin", config))
        .merge(workspace_routes("/my", config))
        .route("/my", get(|| async { Redirect::to("/my/projects") }))
        .route("/admin", get(dashboard))
        .route("/admin/integrity", post(integrity_start))
        .route("/admin/releases/{id}/import", post(import_file))
        .route("/admin/releases/{id}/signature", post(release_signature))
        .route("/admin/files/{id}/mirror", post(file_set_mirror))
        .route(
            "/admin/files/{id}/mirrors",
            get(mirrors_page).post(mirror_add),
        )
        .route("/admin/files/{id}/mirrors/quick", post(mirror_quick_add))
        .route("/admin/mirrors/{id}/{action}", post(mirror_action))
        .route("/admin/files/{id}/rehash", post(file_rehash))
        .route("/admin/settings", get(settings_page).post(settings_save))
}

/// Project, release and file management under `prefix` ("/admin" or "/my").
fn workspace_routes(prefix: &str, config: &Config) -> Router<AppState> {
    // Multipart uploads get their own body limit (the hard cap for everyone;
    // members also have their own, lower limits); every other form keeps
    // the small default.
    let upload_limit = usize::try_from(config.max_upload_bytes).unwrap_or(usize::MAX);
    Router::new()
        .route(
            &format!("{prefix}/projects"),
            get(projects_page).post(project_create),
        )
        .route(
            &format!("{prefix}/projects/{{id}}/edit"),
            get(project_edit_page).post(project_update),
        )
        .route(
            &format!("{prefix}/projects/{{id}}/delete"),
            post(project_delete),
        )
        .route(
            &format!("{prefix}/projects/{{id}}/releases"),
            get(releases_page).post(release_create),
        )
        .route(
            &format!("{prefix}/releases/{{id}}/edit"),
            get(release_edit_page).post(release_update),
        )
        .route(
            &format!("{prefix}/releases/{{id}}/delete"),
            post(release_delete),
        )
        .route(&format!("{prefix}/releases/{{id}}/files"), get(files_page))
        .route(
            &format!("{prefix}/releases/{{id}}/upload"),
            post(upload_files).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route(&format!("{prefix}/files/{{id}}/delete"), post(file_delete))
        .route(
            &format!("{prefix}/files/{{id}}/download"),
            get(file_download),
        )
}

#[derive(Deserialize)]
struct DeleteForm {
    csrf: String,
    confirm: Option<String>,
}

fn require_confirm(f: &DeleteForm) -> Result<(), AppError> {
    if f.confirm.is_none() {
        return Err(AppError::BadRequest(
            "Tick the confirmation box to delete.".into(),
        ));
    }
    Ok(())
}

/// Deletes stored objects after their rows are gone. Failures only leave
/// orphaned bytes behind, so they are logged rather than surfaced.
pub(crate) async fn delete_objects(st: &AppState, objects: Vec<(String, String)>) {
    for (backend, key) in objects {
        let result = match st.storage.get(&backend) {
            Ok(b) => b.delete(&key).await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            tracing::warn!(backend = %backend, key = %key, error = %e, "could not delete stored object");
        }
    }
}

/// A project the actor may manage: any for administrators, their own for
/// members (404 otherwise, so other members' projects are not revealed).
async fn load_project(st: &AppState, actor: &Actor, id: i64) -> Result<Project, AppError> {
    let p = queries::get_project(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !actor.is_admin && p.owner_id != Some(actor.id) {
        return Err(AppError::NotFound);
    }
    Ok(p)
}

async fn load_release(
    st: &AppState,
    actor: &Actor,
    id: i64,
) -> Result<(Project, Release), AppError> {
    let r = queries::get_release(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((load_project(st, actor, r.project_id).await?, r))
}

async fn load_file(st: &AppState, actor: &Actor, id: i64) -> Result<FileRow, AppError> {
    let f = queries::get_file(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    load_release(st, actor, f.release_id).await?;
    Ok(f)
}

/// The review state a member's new or changed project/release gets: pending
/// while "Review member uploads" is on. None = unchanged (administrators,
/// or review off: published directly, but an admin's rejection stands).
fn member_review(st: &AppState, actor: &Actor) -> Option<&'static str> {
    (!actor.is_admin && st.site().review_member_uploads).then_some(review::PENDING)
}

// ---- dashboard -------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardTemplate {
    l: Layout,
    stats: Stats,
    /// (accounts, projects + releases, limit requests) awaiting a decision.
    pending: (i64, i64, i64),
    total_size: String,
    integrity: crate::integrity::Report,
}

async fn dashboard(admin: AdminUser, State(st): State<AppState>) -> Result<Response, AppError> {
    let stats = queries::stats(&st.db).await?;
    let integrity = st.integrity.lock().unwrap().clone();
    let mut l = st.layout("Admin", Some(&admin));
    if integrity.running {
        l.refresh = Some(5);
    }
    render(&DashboardTemplate {
        l,
        pending: queries::pending_counts(&st.db).await?,
        total_size: human_size(stats.bytes as u64),
        stats,
        integrity,
    })
}

/// Starts the background storage integrity check.
async fn integrity_start(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    crate::integrity::start(&st);
    Ok(Redirect::to("/admin").into_response())
}

// ---- projects --------------------------------------------------------------

#[derive(Default, Deserialize)]
struct ProjectForm {
    #[serde(default)]
    csrf: String,
    name: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    description_md: String,
}

impl ProjectForm {
    /// Trims, fills in the slug from the name if blank, and validates.
    fn normalize(&mut self) -> Result<(), String> {
        self.name = self.name.trim().to_string();
        self.summary = self.summary.trim().to_string();
        self.slug = self.slug.trim().to_ascii_lowercase();
        if self.slug.is_empty() {
            self.slug = slugify(&self.name);
        }
        if self.name.is_empty() || self.name.chars().count() > 200 {
            return Err("Name is required (at most 200 characters).".into());
        }
        if !is_valid_slug(&self.slug) {
            return Err(
                "Slug may only contain lowercase letters, digits and single dashes (max 64)."
                    .into(),
            );
        }
        if self.summary.chars().count() > 500 {
            return Err("Summary must be at most 500 characters.".into());
        }
        if self.description_md.len() > MAX_TEXT_BYTES {
            return Err("Description is too long.".into());
        }
        Ok(())
    }

    fn input(&self) -> ProjectInput<'_> {
        ProjectInput {
            slug: &self.slug,
            name: &self.name,
            summary: &self.summary,
            description_md: &self.description_md,
        }
    }
}

#[derive(Template)]
#[template(path = "admin/projects.html")]
struct ProjectsTemplate {
    l: Layout,
    projects: Vec<WorkspaceProject>,
    form: ProjectForm,
    error: Option<String>,
    /// Members: "Using X of Y" and the review notice.
    usage: Option<MemberUsage>,
}

/// A member's limits and usage, as shown in the workspace.
pub struct MemberUsage {
    pub used: String,
    pub quota: String,
    pub upload_limit: String,
    pub review: bool,
}

async fn member_usage(st: &AppState, actor: &Actor) -> Result<Option<MemberUsage>, AppError> {
    if actor.is_admin {
        return Ok(None);
    }
    let caps = MemberCaps::load(st, actor.id).await?;
    Ok(Some(MemberUsage {
        used: human_size(caps.used),
        quota: human_size(caps.quota),
        upload_limit: human_size(caps.file_limit),
        review: st.site().review_member_uploads,
    }))
}

async fn render_projects(
    st: &AppState,
    actor: &Actor,
    form: ProjectForm,
    error: Option<String>,
) -> Result<Response, AppError> {
    let owner = (!actor.is_admin).then_some(actor.id);
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let title = if actor.is_admin {
        "Projects"
    } else {
        "My projects"
    };
    let page = render(&ProjectsTemplate {
        projects: queries::workspace_projects(&st.db, owner).await?,
        l: st.layout(title, Some(actor)),
        form,
        error,
        usage: member_usage(st, actor).await?,
    })?;
    Ok((status, page).into_response())
}

async fn projects_page(actor: Actor, State(st): State<AppState>) -> Result<Response, AppError> {
    render_projects(&st, &actor, ProjectForm::default(), None).await
}

async fn project_create(
    actor: Actor,
    State(st): State<AppState>,
    Form(mut f): Form<ProjectForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    let review = member_review(&st, &actor).unwrap_or(review::APPROVED);
    let error = match f.normalize() {
        Err(e) => e,
        Ok(()) => match queries::create_project(&st.db, &f.input(), actor.id, review).await {
            Ok(id) => {
                return Ok(
                    Redirect::to(&format!("{}/projects/{id}/releases", actor.base()))
                        .into_response(),
                );
            }
            Err(e) if is_unique_violation(&e) => format!("The slug '{}' is already taken.", f.slug),
            Err(e) => return Err(e.into()),
        },
    };
    render_projects(&st, &actor, f, Some(error)).await
}

#[derive(Template)]
#[template(path = "admin/project_edit.html")]
struct ProjectEditTemplate {
    l: Layout,
    id: i64,
    form: ProjectForm,
    error: Option<String>,
    review_status: String,
    review_note: String,
    /// The edit sends a published project back for review (member, review on).
    resubmits: bool,
}

async fn project_edit_page(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let p = load_project(&st, &actor, id).await?;
    render(&ProjectEditTemplate {
        l: st.layout(format!("Edit {}", p.name), Some(&actor)),
        id,
        form: ProjectForm {
            csrf: String::new(),
            name: p.name,
            slug: p.slug,
            summary: p.summary,
            description_md: p.description_md,
        },
        error: None,
        review_status: p.review_status,
        review_note: p.review_note.unwrap_or_default(),
        resubmits: member_review(&st, &actor).is_some(),
    })
}

async fn project_update(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(mut f): Form<ProjectForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    let p = load_project(&st, &actor, id).await?;
    let review = member_review(&st, &actor);
    let error = match f.normalize() {
        Err(e) => e,
        Ok(()) => match queries::update_project(&st.db, id, &f.input(), review).await {
            Ok(()) => {
                return Ok(Redirect::to(&format!("{}/projects", actor.base())).into_response());
            }
            Err(e) if is_unique_violation(&e) => format!("The slug '{}' is already taken.", f.slug),
            Err(e) => return Err(e.into()),
        },
    };
    let page = render(&ProjectEditTemplate {
        l: st.layout("Edit project", Some(&actor)),
        id,
        form: f,
        error: Some(error),
        review_status: p.review_status,
        review_note: p.review_note.unwrap_or_default(),
        resubmits: review.is_some(),
    })?;
    Ok((StatusCode::BAD_REQUEST, page).into_response())
}

async fn project_delete(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<DeleteForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    require_confirm(&f)?;
    load_project(&st, &actor, id).await?;
    let objects = queries::objects_for_project(&st.db, id).await?;
    queries::delete_project(&st.db, id).await?; // cascades to releases and files
    delete_objects(&st, objects).await;
    Ok(Redirect::to(&format!("{}/projects", actor.base())).into_response())
}

// ---- releases --------------------------------------------------------------

#[derive(Deserialize)]
struct ReleaseForm {
    csrf: String,
    version: String,
    #[serde(default)]
    notes_md: String,
    #[serde(default)]
    released_at: String,
}

/// Validated release fields.
struct ReleaseValues {
    version: String,
    released_at: NaiveDate,
}

impl ReleaseForm {
    fn validate(&self) -> Result<ReleaseValues, String> {
        let version = self.version.trim().to_string();
        if version.is_empty() || version.chars().count() > 64 {
            return Err("Version is required (at most 64 characters).".into());
        }
        if self.notes_md.len() > MAX_TEXT_BYTES {
            return Err("Release notes are too long.".into());
        }
        let date = self.released_at.trim();
        let released_at = if date.is_empty() {
            Utc::now().date_naive()
        } else {
            NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .map_err(|_| "Date must be YYYY-MM-DD.".to_string())?
        };
        Ok(ReleaseValues {
            version,
            released_at,
        })
    }
}

/// Release form fields as shown in templates.
#[derive(Default)]
struct ReleaseFields {
    version: String,
    notes_md: String,
    released_at: String,
}

impl From<&ReleaseForm> for ReleaseFields {
    fn from(f: &ReleaseForm) -> Self {
        Self {
            version: f.version.clone(),
            notes_md: f.notes_md.clone(),
            released_at: f.released_at.clone(),
        }
    }
}

struct ReleaseRow {
    id: i64,
    version: String,
    date: String,
    review_status: String,
    review_note: String,
}

#[derive(Template)]
#[template(path = "admin/releases.html")]
struct ReleasesTemplate {
    l: Layout,
    project: Project,
    releases: Vec<ReleaseRow>,
    form: ReleaseFields,
    error: Option<String>,
}

async fn render_releases(
    st: &AppState,
    actor: &Actor,
    project: Project,
    form: ReleaseFields,
    error: Option<String>,
) -> Result<Response, AppError> {
    let releases = queries::list_releases(&st.db, project.id)
        .await?
        .into_iter()
        .map(|r| ReleaseRow {
            id: r.id,
            version: r.version,
            date: r.released_at.format("%Y-%m-%d").to_string(),
            review_status: r.review_status,
            review_note: r.review_note.unwrap_or_default(),
        })
        .collect();
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&ReleasesTemplate {
        l: st.layout(format!("Releases of {}", project.name), Some(actor)),
        project,
        releases,
        form,
        error,
    })?;
    Ok((status, page).into_response())
}

async fn releases_page(
    actor: Actor,
    State(st): State<AppState>,
    Path(project_id): Path<i64>,
) -> Result<Response, AppError> {
    let project = load_project(&st, &actor, project_id).await?;
    let form = ReleaseFields {
        released_at: Utc::now().date_naive().format("%Y-%m-%d").to_string(),
        ..Default::default()
    };
    render_releases(&st, &actor, project, form, None).await
}

async fn release_create(
    actor: Actor,
    State(st): State<AppState>,
    Path(project_id): Path<i64>,
    Form(f): Form<ReleaseForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    let project = load_project(&st, &actor, project_id).await?;
    let review = member_review(&st, &actor).unwrap_or(review::APPROVED);
    let error = match f.validate() {
        Err(e) => e,
        Ok(v) => match queries::create_release(
            &st.db,
            project_id,
            &v.version,
            &f.notes_md,
            v.released_at,
            review,
        )
        .await
        {
            Ok(id) => {
                return Ok(
                    Redirect::to(&format!("{}/releases/{id}/files", actor.base())).into_response(),
                );
            }
            Err(e) if is_unique_violation(&e) => format!("Version '{}' already exists.", v.version),
            Err(e) => return Err(e.into()),
        },
    };
    render_releases(&st, &actor, project, (&f).into(), Some(error)).await
}

#[derive(Template)]
#[template(path = "admin/release_edit.html")]
struct ReleaseEditTemplate {
    l: Layout,
    project: Project,
    id: i64,
    form: ReleaseFields,
    error: Option<String>,
    /// The edit sends a published release back for review.
    resubmits: bool,
}

async fn release_edit_page(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let (project, r) = load_release(&st, &actor, id).await?;
    render(&ReleaseEditTemplate {
        l: st.layout(format!("Edit {} {}", project.name, r.version), Some(&actor)),
        project,
        id,
        form: ReleaseFields {
            version: r.version,
            notes_md: r.notes_md,
            released_at: r.released_at.format("%Y-%m-%d").to_string(),
        },
        error: None,
        resubmits: member_review(&st, &actor).is_some(),
    })
}

async fn release_update(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<ReleaseForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    let (project, _) = load_release(&st, &actor, id).await?;
    let review = member_review(&st, &actor);
    let error = match f.validate() {
        Err(e) => e,
        Ok(v) => match queries::update_release(
            &st.db,
            id,
            &v.version,
            &f.notes_md,
            v.released_at,
            review,
        )
        .await
        {
            Ok(()) => {
                return Ok(Redirect::to(&format!(
                    "{}/projects/{}/releases",
                    actor.base(),
                    project.id
                ))
                .into_response());
            }
            Err(e) if is_unique_violation(&e) => format!("Version '{}' already exists.", v.version),
            Err(e) => return Err(e.into()),
        },
    };
    let page = render(&ReleaseEditTemplate {
        l: st.layout("Edit release", Some(&actor)),
        project,
        id,
        form: (&f).into(),
        error: Some(error),
        resubmits: review.is_some(),
    })?;
    Ok((StatusCode::BAD_REQUEST, page).into_response())
}

async fn release_delete(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<DeleteForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    require_confirm(&f)?;
    let (project, _) = load_release(&st, &actor, id).await?;
    let objects = queries::objects_for_release(&st.db, id).await?;
    queries::delete_release(&st.db, id).await?; // cascades to files
    delete_objects(&st, objects).await;
    Ok(Redirect::to(&format!(
        "{}/projects/{}/releases",
        actor.base(),
        project.id
    ))
    .into_response())
}

// ---- files: listing ----------------------------------------------------------

struct AdminFileView {
    id: i64,
    filename: String,
    status: String,
    error_message: String,
    size: String,
    sha256: String,
    /// Empty for rows created before SHA-512 existed (shown as "n/a").
    sha512: String,
    downloads: i64,
    download_url: String,
    /// "label (kind, status)" per mirror, for the summary line.
    mirrors: Vec<String>,
    /// Opaque storage key (needed when seeding by hand, see docs/TORRENTS.md).
    storage_key: String,
    /// "Recompute hashes" is offered for ready files and for failed files
    /// that were stored once.
    can_rehash: bool,
}

struct CandidateView {
    rel_path: String,
    size: String,
    modified: String,
    settled: bool,
    in_flight: bool,
}

#[derive(Template)]
#[template(path = "admin/files.html")]
struct FilesTemplate {
    l: Layout,
    project: Project,
    release: Release,
    /// Project and release are both approved (public).
    published: bool,
    /// Members: limits, usage and the review notice.
    usage: Option<MemberUsage>,
    files: Vec<AdminFileView>,
    candidates: Vec<CandidateView>,
    incoming_path: String,
    incoming_error: Option<String>,
    min_age_secs: u64,
    allow_web_upload: bool,
    max_upload: String,
    /// The "stored byte-for-byte" line.
    storage_note: &'static str,
    /// SIGN_CHECKSUMS is on.
    sign_checksums: bool,
    /// "none", "current" or "outdated".
    signature_status: &'static str,
    /// Public SHA256SUMS URL of this release (for the signing commands).
    sums_url: String,
    flash: Option<&'static str>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct FlashQuery {
    msg: Option<String>,
}

/// Maps known ?msg= codes to text (arbitrary text is never reflected).
fn flash_text(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "import-started" => "Import started. This page refreshes until it finishes.",
        "rehash-started" => "Recomputing hashes. This page refreshes until it finishes.",
        "uploaded" => "Upload complete.",
        "deleted" => "File deleted.",
        "mirror-saved" => "Mirror URL saved.",
        "signature-saved" => "Signature saved; SHA256SUMS.asc is now served for this release.",
        "signature-removed" => "Signature removed.",
        _ => return None,
    })
}

/// `download_url` is the public link once published, otherwise the
/// workspace link (`base`/files/{id}/download) only the owner and admins can use.
fn file_view(
    st: &AppState,
    f: FileRow,
    all_mirrors: &[Mirror],
    base: Option<&str>,
) -> AdminFileView {
    AdminFileView {
        mirrors: all_mirrors
            .iter()
            .filter(|m| m.file_id == f.id)
            .map(|m| format!("{} ({}, {})", m.label, m.kind, m.status))
            .collect(),
        storage_key: f.storage_key.clone(),
        download_url: match base {
            None => st.download_url(f.id),
            Some(base) => format!("{base}/files/{}/download", f.id),
        },
        can_rehash: f.status == status::READY
            || (f.status == status::FAILED && !f.sha256.is_empty()),
        id: f.id,
        filename: f.filename,
        status: f.status,
        error_message: f.error_message.unwrap_or_default(),
        size: human_size(f.size_bytes as u64),
        sha256: f.sha256,
        sha512: f.sha512.unwrap_or_default(),
        downloads: f.download_count,
    }
}

fn storage_note(st: &AppState) -> &'static str {
    if st.config.strip_metadata && !st.strippers.is_empty() {
        "Files are stored byte-for-byte unless a metadata stripper ran \
         (images and PDFs only; never disk images, archives or binaries)."
    } else {
        "Files are stored byte-for-byte as uploaded or imported (no metadata stripper is active)."
    }
}

async fn render_files(
    st: &AppState,
    actor: &Actor,
    release_id: i64,
    flash: Option<&'static str>,
    error: Option<String>,
) -> Result<Response, AppError> {
    let (project, release) = load_release(st, actor, release_id).await?;
    let published =
        project.review_status == review::APPROVED && release.review_status == review::APPROVED;
    let all_mirrors = queries::mirrors_for_release(&st.db, release_id).await?;
    let raw_files = queries::files_for_release(&st.db, release_id).await?;
    let signature_status = match (
        release.sums_signature.is_some(),
        crate::routes::public::current_signature(&release, &raw_files).is_some(),
    ) {
        (false, _) => "none",
        (true, true) => "current",
        (true, false) => "outdated",
    };
    let sums_url = format!(
        "{}/p/{}/{}/SHA256SUMS",
        st.config.public_url.as_deref().unwrap_or(""),
        project.slug,
        crate::util::encode_path_segment(&release.version)
    );
    let link_base = (!published).then(|| actor.base());
    let files: Vec<_> = raw_files
        .into_iter()
        .map(|f| file_view(st, f, &all_mirrors, link_base))
        .collect();
    let usage = member_usage(st, actor).await?;

    // Scanning touches the disk; keep it off the async workers. Members
    // never see the incoming folder (it is the admin's).
    let root = st.config.incoming_path.clone();
    let min_age = Duration::from_secs(st.config.import_min_age_secs);
    let scan = if actor.is_admin {
        tokio::task::spawn_blocking(move || incoming::scan(&root, min_age, SystemTime::now()))
            .await
            .map_err(AppError::internal)?
    } else {
        Ok(Vec::new())
    };
    let (candidates, incoming_error) = match scan {
        Ok(list) => {
            let in_flight = st.imports_in_flight.lock().unwrap().clone();
            let canon_root = st.config.incoming_path.canonicalize().ok();
            let views = list
                .into_iter()
                .map(|c| CandidateView {
                    in_flight: canon_root
                        .as_ref()
                        .is_some_and(|r| in_flight.contains(&r.join(&c.rel_path))),
                    size: human_size(c.size),
                    modified: chrono::DateTime::<Utc>::from(c.modified)
                        .format("%Y-%m-%d %H:%M UTC")
                        .to_string(),
                    settled: c.settled,
                    rel_path: c.rel_path,
                })
                .collect();
            (views, None)
        }
        Err(e) => (
            Vec::new(),
            Some(format!("Cannot read the incoming folder: {e}")),
        ),
    };

    let mut l = st.layout(
        format!("Files of {} {}", project.name, release.version),
        Some(actor),
    );
    if files
        .iter()
        .any(|f| f.status == status::IMPORTING || f.status == status::HASHING)
    {
        l.refresh = Some(5);
    }
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let max_upload = match &usage {
        Some(u) => u.upload_limit.clone(),
        None => human_size(st.config.max_upload_bytes),
    };
    let page = render(&FilesTemplate {
        l,
        project,
        release,
        published,
        usage,
        files,
        candidates,
        incoming_path: st.config.incoming_path.display().to_string(),
        incoming_error,
        min_age_secs: st.config.import_min_age_secs,
        allow_web_upload: st.config.allow_web_upload,
        max_upload,
        storage_note: storage_note(st),
        sign_checksums: st.config.sign_checksums,
        signature_status,
        sums_url,
        flash,
        error,
    })?;
    Ok((status, page).into_response())
}

async fn files_page(
    actor: Actor,
    State(st): State<AppState>,
    Path(release_id): Path<i64>,
    Query(q): Query<FlashQuery>,
) -> Result<Response, AppError> {
    render_files(&st, &actor, release_id, flash_text(q.msg.as_deref()), None).await
}

fn files_redirect(actor: &Actor, release_id: i64, msg: &str) -> Response {
    Redirect::to(&format!(
        "{}/releases/{release_id}/files?msg={msg}",
        actor.base()
    ))
    .into_response()
}

/// Serves a stored file to its owner or an administrator, published or not
/// (for checking before / during review). Never counted as a download.
async fn file_download(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    client: ClientInfo,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let f = load_file(&st, &actor, id).await?;
    if f.status != status::READY {
        return Err(AppError::NotFound);
    }
    crate::routes::public::serve_file(&st, f, client, method, &headers, false).await
}

// ---- files: the store pipeline ------------------------------------------------

/// strip (only if STRIP_METADATA and a stripper supports the file) ->
/// hash + size (SHA-256 and SHA-512 in one pass) -> move into storage.
///
/// `src` is a local file (an incoming file, or a spooled upload); stripped
/// copies are written to `work_dir`. Returns the digests of the bytes that
/// were stored. Without a stripper the file is stored byte-for-byte.
///
/// `validated` pins the file checked when the import was requested: the
/// file hashed must be that same, unmodified inode, and storage only moves
/// the inode that was hashed (no swap between check, hash and move).
#[allow(clippy::too_many_arguments)]
async fn strip_hash_store(
    st: &AppState,
    backend: &Arc<dyn StorageBackend>,
    key: &str,
    src: &FsPath,
    validated: Option<FileIdentity>,
    filename: &str,
    mime: Option<&str>,
    work_dir: &FsPath,
) -> Result<Digests, String> {
    let registry = st.strippers.clone();
    let enabled = st.config.strip_metadata;
    let (src_c, name_c, mime_c, work_c) = (
        src.to_path_buf(),
        filename.to_string(),
        mime.map(str::to_string),
        work_dir.to_path_buf(),
    );
    let stripped = tokio::task::spawn_blocking(move || {
        registry.maybe_strip(enabled, &name_c, mime_c.as_deref(), &src_c, &work_c)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let to_store = stripped.clone().unwrap_or_else(|| src.to_path_buf());

    let result = async {
        let hash_path = to_store.clone();
        let (digests, hashed) = tokio::task::spawn_blocking(move || hash_file(&hash_path))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("reading the file failed: {e}"))?;
        if let Some(v) = validated
            && stripped.is_none()
            && !hashed.unchanged(&v)
        {
            return Err("the file was replaced or modified after the import was requested".into());
        }
        let stored = backend
            .import_from_path(key, &to_store, hashed)
            .await
            .map_err(|e| format!("moving into storage failed: {e}"))?;
        if stored != digests.size {
            let _ = backend.delete(key).await;
            return Err(
                "the file changed while it was being imported; copy it again and retry".into(),
            );
        }
        Ok(digests)
    }
    .await;

    if let Some(stripped) = stripped {
        // Left over only on failure (on success it was moved into storage).
        let _ = tokio::fs::remove_file(&stripped).await;
        if result.is_ok() {
            // The stripped copy replaced the original.
            let _ = tokio::fs::remove_file(src).await;
        }
    }
    result
}

// ---- files: import from INCOMING_PATH -----------------------------------------

#[derive(Deserialize)]
struct ImportForm {
    csrf: String,
    path: String,
}

/// Removes an in-flight marker when the import task ends (even on panic).
struct InFlightGuard {
    set: Arc<std::sync::Mutex<std::collections::HashSet<PathBuf>>>,
    path: PathBuf,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.path);
        }
    }
}

/// Validates the request, records an 'importing' row and hands the actual
/// work to a background task, so the request returns immediately regardless
/// of file size (proxies time out long requests).
async fn import_file(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(release_id): Path<i64>,
    Form(f): Form<ImportForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    load_release(&st, &admin, release_id).await?;

    let root = st.config.incoming_path.clone();
    let min_age = Duration::from_secs(st.config.import_min_age_secs);
    let rel = f.path.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        incoming::resolve(&root, &rel, min_age, SystemTime::now())
    })
    .await
    .map_err(AppError::internal)?;
    let src = match resolved {
        Ok(p) => p,
        Err(e) => return render_files(&st, &admin, release_id, None, Some(e.to_string())).await,
    };
    // Open it now (no symlinks, no FIFOs, no hard links) and pin its identity;
    // the background job only proceeds with this exact, unmodified inode.
    let open_path = src.clone();
    let identity = match tokio::task::spawn_blocking(move || open_regular(&open_path))
        .await
        .map_err(AppError::internal)?
    {
        Ok((_, id)) => id,
        Err(e) => {
            return render_files(
                &st,
                &admin,
                release_id,
                None,
                Some(format!("Cannot import this file: {e}")),
            )
            .await;
        }
    };
    // Refuse up front when storage would run (nearly) full.
    let size = identity.len;
    if let Err(msg) = crate::limits::check_free_space(
        &st.config.storage_path,
        size,
        st.config.security.storage_min_free_bytes,
    ) {
        return render_files(&st, &admin, release_id, None, Some(msg)).await;
    }

    if !st.imports_in_flight.lock().unwrap().insert(src.clone()) {
        let msg = "That file is already being imported.".to_string();
        return render_files(&st, &admin, release_id, None, Some(msg)).await;
    }
    let guard = InFlightGuard {
        set: st.imports_in_flight.clone(),
        path: src.clone(),
    };

    let backend = st.storage.active();
    let key = new_key();
    let filename = sanitize_filename(&f.path);
    let id = queries::insert_file(
        &st.db,
        &NewFile {
            release_id,
            filename: &filename,
            size_bytes: 0,
            sha256: "",
            sha512: None,
            storage_backend: backend.name(),
            storage_key: &key,
            status: status::IMPORTING,
        },
    )
    .await?;
    tracing::info!(file_id = id, path = %f.path, "import started");

    tokio::spawn(async move {
        let _guard = guard;
        run_import(st, id, src, identity, key, filename, backend).await;
    });
    Ok(files_redirect(&admin, release_id, "import-started"))
}

/// The background half of an import: strip/hash/store, then mark ready (or
/// failed with a short message).
async fn run_import(
    st: AppState,
    id: i64,
    src: PathBuf,
    identity: FileIdentity,
    key: String,
    filename: String,
    backend: Arc<dyn StorageBackend>,
) {
    // Queue behind IMPORT_CONCURRENCY other hashing jobs (status stays
    // 'importing' while waiting).
    let _slot = st.job_slots.clone().acquire_owned().await;
    // Stripped copies (if any) go next to the source: same filesystem, and
    // hidden from the incoming scan by the leading dot.
    let work_dir = src.parent().map(FsPath::to_path_buf).unwrap_or_default();
    let result = strip_hash_store(
        &st,
        &backend,
        &key,
        &src,
        Some(identity),
        &filename,
        None,
        &work_dir,
    )
    .await;
    match result {
        Ok(d) => {
            match queries::finish_import(&st.db, id, d.size as i64, &d.sha256, &d.sha512).await {
                Ok(true) => tracing::info!(file_id = id, size = d.size, "import finished"),
                Ok(false) => {
                    // The row was deleted meanwhile; drop the now-orphaned object.
                    tracing::warn!(file_id = id, "file row vanished during import");
                    let _ = backend.delete(&key).await;
                }
                Err(e) => {
                    tracing::error!(file_id = id, error = %e, "could not mark import finished")
                }
            }
        }
        Err(msg) => {
            tracing::warn!(file_id = id, error = %msg, "import failed");
            if let Err(e) = queries::mark_failed(&st.db, id, &msg).await {
                tracing::error!(file_id = id, error = %e, "could not mark import failed");
            }
        }
    }
}

// ---- files: recompute hashes ---------------------------------------------------

#[derive(Deserialize)]
struct CsrfOnlyForm {
    csrf: String,
}

/// Re-reads a stored file in the background and recomputes both hashes
/// (also backfills SHA-512 on rows from before it existed).
async fn file_rehash(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let file = queries::get_file(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !queries::start_rehash(&st.db, id).await? {
        let msg = "Only ready or failed files can have their hashes recomputed.".to_string();
        return render_files(&st, &admin, file.release_id, None, Some(msg)).await;
    }
    let release_id = file.release_id;
    tracing::info!(file_id = id, "hash recompute started");
    tokio::spawn(run_rehash(st, file));
    Ok(files_redirect(&admin, release_id, "rehash-started"))
}

async fn run_rehash(st: AppState, f: FileRow) {
    let _slot = st.job_slots.clone().acquire_owned().await;
    let result: Result<Digests, String> = async {
        let backend = st.storage.get(&f.storage_backend).map_err(|e| e.to_string())?;
        let size = backend
            .size(&f.storage_key)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("the stored file is missing")?;
        if size != f.size_bytes as u64 {
            return Err(format!(
                "size mismatch: the database records {} bytes but storage holds {size} bytes",
                f.size_bytes
            ));
        }
        let reader = backend
            .open(&f.storage_key, 0, size)
            .await
            .map_err(|e| e.to_string())?;
        let d = hash_reader(reader)
            .await
            .map_err(|e| format!("reading the stored file failed: {e}"))?;
        if d.size != size {
            return Err(format!(
                "size mismatch: read {} bytes, expected {size}",
                d.size
            ));
        }
        // A different SHA-256 for the same bytes count means the stored copy
        // changed; publishing a fresh checksum would hide corruption.
        if !f.sha256.is_empty() && f.sha256 != d.sha256 {
            return Err(
                "SHA-256 no longer matches the recorded value; the stored file may be corrupted (re-import it)"
                    .into(),
            );
        }
        Ok(d)
    }
    .await;

    match result {
        Ok(d) => match queries::finish_rehash(&st.db, f.id, &d.sha256, &d.sha512).await {
            Ok(_) => tracing::info!(file_id = f.id, "hash recompute finished"),
            Err(e) => {
                tracing::error!(file_id = f.id, error = %e, "could not save recomputed hashes")
            }
        },
        Err(msg) => {
            tracing::warn!(file_id = f.id, error = %msg, "hash recompute failed");
            if let Err(e) = queries::mark_failed(&st.db, f.id, &msg).await {
                tracing::error!(file_id = f.id, error = %e, "could not mark recompute failed");
            }
        }
    }
}

// ---- files: small web uploads ------------------------------------------------

/// A member's effective limits and current usage.
pub struct MemberCaps {
    /// Largest single file: the member's override or the site default,
    /// never above MAX_UPLOAD_BYTES.
    pub file_limit: u64,
    pub quota: u64,
    pub used: u64,
}

impl MemberCaps {
    pub async fn load(st: &AppState, user_id: i64) -> Result<Self, AppError> {
        let (limit, quota) = queries::user_limits(&st.db, user_id).await?;
        let site = st.site();
        let as_u64 = |v: Option<i64>| v.and_then(|v| u64::try_from(v).ok());
        Ok(MemberCaps {
            file_limit: as_u64(limit)
                .unwrap_or(site.member_upload_limit)
                .min(st.config.max_upload_bytes),
            quota: as_u64(quota).unwrap_or(site.member_storage_quota),
            used: u64::try_from(queries::used_bytes(&st.db, user_id).await?).unwrap_or(0),
        })
    }
}

/// Stream error raised when a member's upload passes their limit; carries
/// the message for the 413 page.
#[derive(Debug)]
struct OverLimit(String);

impl std::fmt::Display for OverLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OverLimit {}

/// Turns a stream error into the right response, recognizing the body-size
/// limit (413) inside wrapped multipart errors and member limits.
fn upload_error(e: std::io::Error, too_large: impl Fn() -> AppError) -> AppError {
    if let Some(over) = e.get_ref().and_then(|r| r.downcast_ref::<OverLimit>()) {
        return AppError::PayloadTooLarge(over.0.clone());
    }
    if let Some(me) = e
        .get_ref()
        .and_then(|r| r.downcast_ref::<axum::extract::multipart::MultipartError>())
    {
        if me.status() == StatusCode::PAYLOAD_TOO_LARGE {
            return too_large();
        }
        return AppError::BadRequest(format!("Upload failed: {}", me.body_text()));
    }
    AppError::internal(e)
}

/// The most a member may still upload as one file, and the message when a
/// file goes over it.
fn member_allowance(caps: &MemberCaps) -> (u64, String) {
    let left = caps.quota.saturating_sub(caps.used);
    if caps.file_limit <= left {
        (
            caps.file_limit,
            format!(
                "That file is larger than your upload limit of {}. You can request a higher limit on the Limits page.",
                human_size(caps.file_limit)
            ),
        )
    } else {
        (
            left,
            format!(
                "That file does not fit in your storage quota ({} of {} used). Delete files or request a larger quota on the Limits page.",
                human_size(caps.used),
                human_size(caps.quota)
            ),
        )
    }
}

/// Counts bytes against `limit` (None = no member limit).
fn over_limit(seen: &mut u64, len: usize, limit: &Option<(u64, String)>) -> std::io::Result<()> {
    *seen += len as u64;
    match limit {
        Some((max, msg)) if *seen > *max => Err(std::io::Error::other(OverLimit(msg.clone()))),
        _ => Ok(()),
    }
}

/// Streams multipart file fields to storage, hashing (SHA-256 + SHA-512) on
/// the way. The CSRF field must come before the file fields (it does in our
/// form), so nothing is written for a forged request. If metadata stripping
/// applies, the upload is spooled to a temp file first and goes through the
/// same strip -> hash -> store pipeline as imports.
///
/// Members are held to their upload limit and storage quota while the bytes
/// arrive (an oversized file is dropped, never stored), and with review on,
/// a release they upload to goes back to "awaiting review".
async fn upload_files(
    actor: Actor,
    State(st): State<AppState>,
    Path(release_id): Path<i64>,
    headers: axum::http::HeaderMap,
    mut mp: Multipart,
) -> Result<Response, AppError> {
    if !st.config.allow_web_upload {
        return Err(AppError::NotFound);
    }
    load_release(&st, &actor, release_id).await?;
    let incoming = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if let Err(msg) = crate::limits::check_free_space(
        &st.config.storage_path,
        incoming,
        st.config.security.storage_min_free_bytes,
    ) {
        return Err(AppError::ServiceUnavailable(msg));
    }
    let mut caps = if actor.is_admin {
        None
    } else {
        let caps = MemberCaps::load(&st, actor.id).await?;
        if caps.used >= caps.quota {
            return Err(AppError::PayloadTooLarge(format!(
                "Your storage quota ({}) is full. Delete files or request a larger quota on the Limits page.",
                human_size(caps.quota)
            )));
        }
        Some(caps)
    };
    let too_large = || {
        AppError::PayloadTooLarge(format!(
            "Uploads through the browser are limited to {}. Copy larger files into the incoming folder and import them instead.",
            human_size(st.config.max_upload_bytes)
        ))
    };
    let multipart_err = |e: axum::extract::multipart::MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            too_large()
        } else {
            AppError::BadRequest(format!("Upload failed: {}", e.body_text()))
        }
    };

    let mut csrf_ok = false;
    let mut uploaded = 0;
    while let Some(mut field) = mp.next_field().await.map_err(multipart_err)? {
        match field.name() {
            Some("csrf") => {
                let token = field.text().await.map_err(multipart_err)?;
                actor.verify_csrf(&token)?;
                csrf_ok = true;
            }
            Some("file") => {
                if !csrf_ok {
                    return Err(AppError::Forbidden("Missing CSRF token.".into()));
                }
                let Some(raw_name) = field
                    .file_name()
                    .map(str::to_string)
                    .filter(|n| !n.is_empty())
                else {
                    continue; // no file chosen
                };
                let filename = sanitize_filename(&raw_name);
                let mime = field.content_type().map(str::to_string);
                let backend = st.storage.active();
                let key = new_key();
                let limit = caps.as_ref().map(member_allowance);
                let mut seen = 0u64;

                let strip = st.config.strip_metadata
                    && st.strippers.find(&filename, mime.as_deref()).is_some();
                let digests = if strip {
                    let work_dir = std::env::temp_dir();
                    let spooled = work_dir.join(format!(".upload-{}", new_key()));
                    let spool = async {
                        let mut out = tokio::fs::File::create(&spooled).await?;
                        while let Some(chunk) =
                            field.chunk().await.map_err(std::io::Error::other)?
                        {
                            over_limit(&mut seen, chunk.len(), &limit)?;
                            out.write_all(&chunk).await?;
                        }
                        out.flush().await
                    }
                    .await;
                    let result = match spool {
                        Ok(()) => strip_hash_store(
                            &st,
                            &backend,
                            &key,
                            &spooled,
                            None,
                            &filename,
                            mime.as_deref(),
                            &work_dir,
                        )
                        .await
                        .map_err(AppError::BadRequest),
                        Err(e) => Err(upload_error(e, too_large)),
                    };
                    let _ = tokio::fs::remove_file(&spooled).await;
                    result?
                } else {
                    let mut hasher = MultiHasher::new();
                    let stream = field.map_err(std::io::Error::other).and_then(|chunk| {
                        let checked = over_limit(&mut seen, chunk.len(), &limit).map(|()| {
                            hasher.update(&chunk);
                            chunk
                        });
                        std::future::ready(checked)
                    });
                    match backend.put(&key, Box::pin(stream)).await {
                        Ok(_) => {}
                        Err(crate::storage::StorageError::Io(e)) => {
                            return Err(upload_error(e, too_large));
                        }
                        Err(e) => return Err(e.into()),
                    }
                    hasher.finish()
                };

                let inserted = queries::insert_file(
                    &st.db,
                    &NewFile {
                        release_id,
                        filename: &filename,
                        size_bytes: digests.size as i64,
                        sha256: &digests.sha256,
                        sha512: Some(&digests.sha512),
                        storage_backend: backend.name(),
                        storage_key: &key,
                        status: status::READY,
                    },
                )
                .await;
                if let Err(e) = inserted {
                    let _ = backend.delete(&key).await;
                    return Err(e.into());
                }
                if let Some(c) = caps.as_mut() {
                    c.used += digests.size;
                }
                tracing::info!(release_id, size = digests.size, "file uploaded");
                uploaded += 1;
            }
            _ => {} // unknown fields are ignored (and drained by next_field)
        }
    }
    if !csrf_ok {
        return Err(AppError::Forbidden("Missing CSRF token.".into()));
    }
    if uploaded == 0 {
        return render_files(
            &st,
            &actor,
            release_id,
            None,
            Some("Choose a file to upload.".into()),
        )
        .await;
    }
    if let Some(review) = member_review(&st, &actor) {
        queries::set_release_review(&st.db, release_id, review, None).await?;
    }
    Ok(files_redirect(&actor, release_id, "uploaded"))
}

// ---- mirrors --------------------------------------------------------------------
// Admin-curated: admin-added mirrors are approved immediately; anything
// discovered/federated (future) starts 'pending'. Public pages show approved
// mirrors only when EXTERNAL_MIRRORS_ENABLED is on.

struct MirrorView {
    id: i64,
    url: String,
    label: String,
    kind: String,
    status: String,
    source: String,
    last_checked: String,
    last_error: String,
    verifying: bool,
}

/// A URL built by a quick-add helper, shown for confirmation.
struct QuickPreview {
    url: String,
    label: String,
    kind: &'static str,
    note: &'static str,
}

#[derive(Default)]
struct MirrorFields {
    url: String,
    label: String,
    kind: String,
}

#[derive(Template)]
#[template(path = "admin/mirrors.html")]
struct MirrorsTemplate {
    l: Layout,
    project: Project,
    release: Release,
    file: FileRow,
    mirrors: Vec<MirrorView>,
    sharing_enabled: bool,
    previews: Vec<QuickPreview>,
    form: MirrorFields,
    flash: Option<&'static str>,
    error: Option<String>,
}

fn mirror_flash(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "added" => "Mirror added (approved).",
        "updated" => "Mirror updated.",
        "deleted" => "Mirror deleted.",
        "verify-started" => {
            "Verifying: downloading the mirror and comparing its SHA-256. This page refreshes until it finishes."
        }
        _ => return None,
    })
}

async fn render_mirrors(
    st: &AppState,
    admin: &Actor,
    file_id: i64,
    flash: Option<&'static str>,
    error: Option<String>,
    previews: Vec<QuickPreview>,
    form: MirrorFields,
) -> Result<Response, AppError> {
    let file = queries::get_file(&st.db, file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (project, release) = load_release(st, admin, file.release_id).await?;
    let verifying = st.verifying.lock().unwrap().clone();
    let mirrors: Vec<MirrorView> = queries::mirrors_for_file(&st.db, file_id)
        .await?
        .into_iter()
        .map(|m| MirrorView {
            verifying: verifying.contains(&m.id),
            id: m.id,
            url: m.url,
            label: m.label,
            kind: m.kind,
            status: m.status,
            source: m.source,
            last_checked: m
                .last_checked_at
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default(),
            last_error: m.last_error.unwrap_or_default(),
        })
        .collect();
    let mut l = st.layout(format!("Mirrors of {}", file.filename), Some(admin));
    if mirrors.iter().any(|m| m.verifying) {
        l.refresh = Some(5);
    }
    let code = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&MirrorsTemplate {
        l,
        project,
        release,
        file,
        mirrors,
        sharing_enabled: st.site().external_mirrors_enabled,
        previews,
        form,
        flash,
        error,
    })?;
    Ok((code, page).into_response())
}

fn mirrors_redirect(file_id: i64, msg: &str) -> Response {
    Redirect::to(&format!("/admin/files/{file_id}/mirrors?msg={msg}")).into_response()
}

async fn mirrors_page(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(file_id): Path<i64>,
    Query(q): Query<FlashQuery>,
) -> Result<Response, AppError> {
    let flash = mirror_flash(q.msg.as_deref());
    render_mirrors(
        &st,
        &admin,
        file_id,
        flash,
        None,
        Vec::new(),
        MirrorFields::default(),
    )
    .await
}

#[derive(Deserialize)]
struct AddMirrorForm {
    csrf: String,
    url: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    kind: String,
}

/// Validates and stores an admin-added mirror (approved immediately).
async fn add_admin_mirror(
    st: &AppState,
    file_id: i64,
    kind: &str,
    url: &str,
    label: &str,
) -> Result<Result<(), String>, AppError> {
    let Some(kind) = MirrorKind::parse(kind) else {
        return Ok(Err("Choose a mirror kind.".into()));
    };
    let url = match validate_mirror(kind, url) {
        Ok(u) => u,
        Err(e) => return Ok(Err(e)),
    };
    let label = match clean_label(label, &url) {
        Ok(l) => l,
        Err(e) => return Ok(Err(e)),
    };
    queries::insert_mirror(
        &st.db,
        &NewMirror {
            file_id,
            url: &url,
            label: &label,
            kind: kind.as_str(),
            status: mirror_status::APPROVED,
            source: "admin",
        },
    )
    .await?;
    tracing::info!(file_id, kind = kind.as_str(), "mirror added");
    Ok(Ok(()))
}

async fn mirror_add(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(file_id): Path<i64>,
    Form(f): Form<AddMirrorForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    queries::get_file(&st.db, file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    match add_admin_mirror(&st, file_id, &f.kind, &f.url, &f.label).await? {
        Ok(()) => Ok(mirrors_redirect(file_id, "added")),
        Err(e) => {
            let form = MirrorFields {
                url: f.url,
                label: f.label,
                kind: f.kind,
            };
            render_mirrors(&st, &admin, file_id, None, Some(e), Vec::new(), form).await
        }
    }
}

#[derive(Deserialize)]
struct QuickAddForm {
    csrf: String,
    /// "archive" or "github".
    source: String,
    #[serde(default)]
    identifier: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    asset: String,
}

/// Builds mirror URLs from an Archive.org identifier or a GitHub release
/// (string templating only, no network) and shows them for confirmation.
async fn mirror_quick_add(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(file_id): Path<i64>,
    Form(f): Form<QuickAddForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let file = queries::get_file(&st.db, file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let pick = |s: &str| {
        if s.trim().is_empty() {
            file.filename.clone()
        } else {
            s.trim().to_string()
        }
    };
    let built = match f.source.as_str() {
        "archive" => archive_org_urls(&f.identifier, &pick(&f.filename)).map(|(http, torrent)| {
            vec![
                QuickPreview {
                    url: http,
                    label: "Archive.org".into(),
                    kind: "http",
                    note: "Direct download of this file from the Archive.org item.",
                },
                QuickPreview {
                    url: torrent,
                    label: "Archive.org".into(),
                    kind: "torrent",
                    note: "The torrent Archive.org generates for the whole item (it may contain other files too).",
                },
            ]
        }),
        "github" => github_release_url(&f.owner, &f.repo, &f.tag, &pick(&f.asset)).map(|url| {
            vec![QuickPreview {
                url,
                label: "GitHub".into(),
                kind: "http",
                note: "GitHub release asset download (GitHub does not generate torrents).",
            }]
        }),
        _ => Err("Unknown quick-add source.".into()),
    };
    match built {
        Ok(previews) => {
            render_mirrors(
                &st,
                &admin,
                file_id,
                None,
                None,
                previews,
                MirrorFields::default(),
            )
            .await
        }
        Err(e) => {
            render_mirrors(
                &st,
                &admin,
                file_id,
                None,
                Some(e),
                Vec::new(),
                MirrorFields::default(),
            )
            .await
        }
    }
}

/// Approve / reject / delete / verify a mirror.
async fn mirror_action(
    admin: AdminUser,
    State(st): State<AppState>,
    Path((id, action)): Path<(i64, String)>,
    Form(f): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let m = queries::get_mirror(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    match action.as_str() {
        "approve" => queries::set_mirror_status(&st.db, id, mirror_status::APPROVED).await?,
        "reject" => queries::set_mirror_status(&st.db, id, mirror_status::REJECTED).await?,
        "delete" => {
            queries::delete_mirror(&st.db, id).await?;
            return Ok(mirrors_redirect(m.file_id, "deleted"));
        }
        "verify" => return start_verify(&st, &admin, m).await,
        _ => return Err(AppError::NotFound),
    }
    Ok(mirrors_redirect(m.file_id, "updated"))
}

/// Starts an explicit, admin-triggered Verify of an http mirror.
async fn start_verify(st: &AppState, admin: &Actor, m: Mirror) -> Result<Response, AppError> {
    let err = |msg: &str| {
        render_mirrors(
            st,
            admin,
            m.file_id,
            None,
            Some(msg.to_string()),
            Vec::new(),
            MirrorFields::default(),
        )
    };
    if m.kind != "http" {
        return err("Only http mirrors can be verified; torrent links stay unverified.").await;
    }
    let file = queries::get_file(&st.db, m.file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if file.status != status::READY || file.sha256.is_empty() {
        return err("The file must be ready (with a SHA-256) before its mirrors can be verified.")
            .await;
    }
    if !st.verifying.lock().unwrap().insert(m.id) {
        return err("A verification of this mirror is already running.").await;
    }
    let (state, file_id) = (st.clone(), m.file_id);
    tokio::spawn(async move {
        let result = mirrors::verify_http_mirror(
            &m.url,
            file.size_bytes as u64,
            &file.sha256,
            state.config.security.verify_proxy_url.as_deref(),
        )
        .await;
        let db_result = match &result {
            Ok(()) => {
                tracing::info!(mirror_id = m.id, "mirror verified");
                queries::mirror_verified(&state.db, m.id).await
            }
            Err(e) => {
                tracing::warn!(mirror_id = m.id, error = %e, "mirror verification failed");
                queries::mirror_verify_failed(&state.db, m.id, &e.to_string()).await
            }
        };
        if let Err(e) = db_result {
            tracing::error!(mirror_id = m.id, error = %e, "could not record verification result");
        }
        state.verifying.lock().unwrap().remove(&m.id);
    });
    Ok(mirrors_redirect(file_id, "verify-started"))
}

#[derive(Deserialize)]
struct LegacyMirrorForm {
    csrf: String,
    #[serde(default)]
    mirror_url: String,
}

/// Old single-mirror form (POST /admin/files/{id}/mirror), kept as an alias:
/// a non-blank URL is added as an approved http mirror.
async fn file_set_mirror(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<LegacyMirrorForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    queries::get_file(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if f.mirror_url.trim().is_empty() {
        return Ok(mirrors_redirect(id, "updated"));
    }
    match add_admin_mirror(&st, id, "http", &f.mirror_url, "").await? {
        Ok(()) => Ok(mirrors_redirect(id, "added")),
        Err(e) => {
            render_mirrors(
                &st,
                &admin,
                id,
                None,
                Some(e),
                Vec::new(),
                MirrorFields::default(),
            )
            .await
        }
    }
}

// ---- release signature (SHA256SUMS.asc) -------------------------------------------

#[derive(Deserialize)]
struct SignatureForm {
    csrf: String,
    #[serde(default)]
    signature: String,
}

/// Stores the admin's detached signature of this release's current
/// SHA256SUMS (made on their own machine), or clears it when blank.
async fn release_signature(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(release_id): Path<i64>,
    Form(f): Form<SignatureForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    load_release(&st, &admin, release_id).await?;
    if f.signature.trim().is_empty() {
        queries::set_release_signature(&st.db, release_id, None).await?;
        return Ok(files_redirect(&admin, release_id, "signature-removed"));
    }
    let sig = match crate::checksums::validate_armored(&f.signature, "PGP SIGNATURE", 16 * 1024) {
        Ok(s) => s,
        Err(e) => {
            return render_files(
                &st,
                &admin,
                release_id,
                None,
                Some(format!("Signature: {e}")),
            )
            .await;
        }
    };
    let files = queries::files_for_release(&st.db, release_id).await?;
    let sums = crate::checksums::build_sums(&files, crate::checksums::Algo::Sha256);
    if sums.is_empty() {
        return render_files(
            &st,
            &admin,
            release_id,
            None,
            Some("This release has no ready files to sign.".into()),
        )
        .await;
    }
    let digest = crate::util::sha256_hex(sums.as_bytes());
    queries::set_release_signature(&st.db, release_id, Some((&sig, &digest))).await?;
    tracing::info!(release_id, "SHA256SUMS signature stored");
    Ok(files_redirect(&admin, release_id, "signature-saved"))
}

// ---- files: delete ---------------------------------------------------------------

async fn file_delete(
    actor: Actor,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<DeleteForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    require_confirm(&f)?;
    let file = load_file(&st, &actor, id).await?;
    if file.status == status::IMPORTING {
        return render_files(
            &st,
            &actor,
            file.release_id,
            None,
            Some("Wait for the import to finish (or fail) before deleting.".into()),
        )
        .await;
    }
    queries::delete_file(&st.db, id).await?;
    delete_objects(&st, vec![(file.storage_backend, file.storage_key)]).await;
    Ok(files_redirect(&actor, file.release_id, "deleted"))
}

// ---- settings --------------------------------------------------------------

#[derive(Deserialize)]
struct SettingsForm {
    csrf: String,
    site_name: String,
    #[serde(default)]
    site_tagline: String,
    #[serde(default)]
    footer_text: String,
    #[serde(default)]
    download_base_url: String,
    // Checkboxes: present when ticked.
    external_mirrors_enabled: Option<String>,
    torrent_dht_enabled: Option<String>,
    mirror_discovery_enabled: Option<String>,
    federation_enabled: Option<String>,
    #[serde(default)]
    gpg_public_key: String,
    registration_open: Option<String>,
    #[serde(default)]
    contact_email: String,
    review_member_uploads: Option<String>,
    #[serde(default)]
    member_upload_limit: String,
    #[serde(default)]
    member_storage_quota: String,
}

#[derive(Template)]
#[template(path = "admin/settings.html")]
struct SettingsTemplate {
    l: Layout,
    form: SiteSettings,
    /// The member size fields as typed / as "100M" style text.
    member_upload_limit: String,
    member_storage_quota: String,
    max_upload: String,
    error: Option<String>,
    saved: bool,
}

/// A byte count as short input text that [`parse_size`] reads back: "100M",
/// "2G", or plain bytes.
pub fn size_input(bytes: u64) -> String {
    for (unit, shift) in [("T", 40), ("G", 30), ("M", 20), ("K", 10)] {
        if bytes > 0 && bytes.is_multiple_of(1u64 << shift) {
            return format!("{}{unit}", bytes >> shift);
        }
    }
    bytes.to_string()
}

fn settings_template(
    st: &AppState,
    admin: &Actor,
    form: SiteSettings,
    sizes: Option<(String, String)>,
    error: Option<String>,
    saved: bool,
) -> SettingsTemplate {
    let (member_upload_limit, member_storage_quota) = sizes.unwrap_or_else(|| {
        (
            size_input(form.member_upload_limit),
            size_input(form.member_storage_quota),
        )
    });
    SettingsTemplate {
        l: st.layout("Settings", Some(admin)),
        form,
        member_upload_limit,
        member_storage_quota,
        max_upload: human_size(st.config.max_upload_bytes),
        error,
        saved,
    }
}

async fn settings_page(admin: AdminUser, State(st): State<AppState>) -> Result<Response, AppError> {
    render(&settings_template(
        &st,
        &admin,
        st.site(),
        None,
        None,
        false,
    ))
}

/// Accepts a plain e-mail address (shown as text, never as a link target
/// other than mailto:) or nothing.
fn valid_contact_email(e: &str) -> bool {
    e.is_empty()
        || (e.len() <= 254
            && e.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
            })
            && e.chars()
                .all(|c| c.is_ascii_alphanumeric() || "@.!#$%&'*+/=?^_`{|}~-".contains(c)))
}

async fn settings_save(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<SettingsForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let mut new = SiteSettings {
        name: f.site_name.trim().to_string(),
        tagline: f.site_tagline.trim().to_string(),
        footer: f.footer_text.trim().to_string(),
        download_base_url: f.download_base_url.trim().to_string(),
        external_mirrors_enabled: f.external_mirrors_enabled.is_some(),
        torrent_dht_enabled: f.torrent_dht_enabled.is_some(),
        mirror_discovery_enabled: f.mirror_discovery_enabled.is_some(),
        federation_enabled: f.federation_enabled.is_some(),
        gpg_public_key: f.gpg_public_key.trim().to_string(),
        registration_open: f.registration_open.is_some(),
        contact_email: f.contact_email.trim().to_string(),
        review_member_uploads: f.review_member_uploads.is_some(),
        member_upload_limit: 0,
        member_storage_quota: 0,
    };
    let sizes = (
        f.member_upload_limit.trim().to_string(),
        f.member_storage_quota.trim().to_string(),
    );
    let error = if new.name.is_empty() || new.name.chars().count() > 100 {
        Some("Site name is required (at most 100 characters).".to_string())
    } else if new.tagline.chars().count() > 200 {
        Some("Tagline must be at most 200 characters.".to_string())
    } else if new.footer.chars().count() > 500 {
        Some("Footer text must be at most 500 characters.".to_string())
    } else {
        match validate_base_url(&new.download_base_url) {
            Ok(url) => {
                new.download_base_url = url;
                None
            }
            Err(e) => Some(format!("Download base URL {e}.")),
        }
    };
    let error = error.or_else(|| {
        if !valid_contact_email(&new.contact_email) {
            return Some("Contact e-mail must be a plain address like admin@example.com.".into());
        }
        // Blank keeps the current value.
        let current = st.site();
        let size = |v: &str, cur: u64| {
            if v.is_empty() {
                Some(cur)
            } else {
                parse_size(v)
            }
        };
        match (
            size(&sizes.0, current.member_upload_limit),
            size(&sizes.1, current.member_storage_quota),
        ) {
            (Some(limit), Some(quota)) if limit > 0 && quota > 0 => {
                new.member_upload_limit = limit;
                new.member_storage_quota = quota;
                None
            }
            _ => {
                Some("Member upload limit and storage quota must be sizes like 100M or 2G.".into())
            }
        }
    });
    let error = error.or_else(|| {
        if new.gpg_public_key.is_empty() {
            return None;
        }
        match crate::checksums::validate_armored(
            &new.gpg_public_key,
            "PGP PUBLIC KEY BLOCK",
            32 * 1024,
        ) {
            Ok(k) => {
                new.gpg_public_key = k;
                None
            }
            Err(e) => Some(format!("Public key: {e}")),
        }
    });
    if let Some(error) = error {
        let page = render(&settings_template(
            &st,
            &admin,
            new,
            Some(sizes),
            Some(error),
            false,
        ))?;
        return Ok((StatusCode::BAD_REQUEST, page).into_response());
    }
    settings::save(&st.db, &st.config, &new).await?;
    st.set_site(new);
    tracing::info!("site settings updated");
    render(&settings_template(&st, &admin, st.site(), None, None, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_input_round_trips() {
        for (bytes, text) in [
            (100 << 20, "100M"),
            (1 << 30, "1G"),
            (3 << 40, "3T"),
            (1536, "1536"),
            (512 << 10, "512K"),
            (0, "0"),
        ] {
            assert_eq!(size_input(bytes), text);
            assert_eq!(parse_size(text), Some(bytes));
        }
    }

    #[test]
    fn contact_email_rules() {
        for ok in ["", "admin@example.com", "files+access@sub.example.org"] {
            assert!(valid_contact_email(ok), "{ok}");
        }
        for bad in [
            "admin",
            "@example.com",
            "admin@localhost",
            "admin@.example.com",
            "a b@example.com",
            "x@example.com\"><script>",
            "javascript:alert(1)@x.y",
        ] {
            assert!(!valid_contact_email(bad), "{bad}");
        }
    }
}
