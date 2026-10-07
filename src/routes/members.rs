//! Member accounts (docs/MEMBERS.md): the admin's review queue and user
//! management (/admin/review, /admin/users), and a member's limits page with
//! requests for a higher upload limit or storage quota (/my/limits).

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{MemberCaps, delete_objects, size_input};
use super::auth::{Actor, AdminUser, hash_password, password_problem, valid_username};
use crate::config::parse_size;
use crate::db::models::{LimitRequest, ReviewItem, UserRow, account, review};
use crate::db::queries::{self, is_unique_violation};
use crate::error::AppError;
use crate::state::AppState;
use crate::util::human_size;
use crate::views::{Layout, render};

/// Longest review / request note an admin can leave.
const MAX_ADMIN_NOTE: usize = 500;
/// A limit request's reason: long enough to say something, short enough to read.
const MIN_REASON: usize = 10;
const MAX_REASON: usize = 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/review", get(review_page))
        .route("/admin/projects/{id}/review", post(project_review))
        .route("/admin/releases/{id}/review", post(release_review))
        .route("/admin/users", get(users_page).post(user_create))
        .route("/admin/users/{id}/{action}", post(user_action))
        .route("/admin/limit-requests/{id}/{action}", post(limit_decision))
        .route("/my/limits", get(limits_page).post(limit_request))
}

#[derive(Deserialize)]
struct MsgQuery {
    msg: Option<String>,
}

/// Trims a note; None when blank, error text when too long.
fn clean_note(note: &str, max: usize) -> Result<Option<String>, String> {
    let note = note.trim();
    if note.chars().count() > max {
        return Err(format!("The note must be at most {max} characters."));
    }
    Ok((!note.is_empty()).then(|| note.to_string()))
}

/// A size field: "" = None, otherwise a positive size like "500M".
fn optional_size(v: &str, what: &str) -> Result<Option<i64>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    parse_size(v)
        .filter(|n| *n > 0)
        .and_then(|n| i64::try_from(n).ok())
        .map(Some)
        .ok_or_else(|| format!("{what} must be a size like 500M or 2G (or blank)."))
}

fn opt_size_text(v: Option<i64>) -> String {
    v.and_then(|v| u64::try_from(v).ok())
        .map(human_size)
        .unwrap_or_default()
}

// ---- review queue ------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin/review.html")]
struct ReviewTemplate {
    l: Layout,
    projects: Vec<ReviewItem>,
    releases: Vec<ReviewItem>,
    review_on: bool,
    flash: Option<&'static str>,
}

async fn review_page(
    admin: AdminUser,
    State(st): State<AppState>,
    Query(q): Query<MsgQuery>,
) -> Result<Response, AppError> {
    let (projects, releases) = queries::pending_reviews(&st.db).await?;
    render(&ReviewTemplate {
        l: st.layout("Review", Some(&admin)),
        projects,
        releases,
        review_on: st.site().review_member_uploads,
        flash: match q.msg.as_deref() {
            Some("approved") => Some("Published."),
            Some("rejected") => Some("Not published; the owner sees your note."),
            _ => None,
        },
    })
}

#[derive(Deserialize)]
struct ReviewForm {
    csrf: String,
    /// "approve" or "reject".
    decision: String,
    #[serde(default)]
    note: String,
    /// Where to go afterwards: "edit", "files" or the review queue.
    #[serde(default)]
    back: String,
}

impl ReviewForm {
    fn decide(&self) -> Result<(&'static str, Option<String>), AppError> {
        let status = match self.decision.as_str() {
            "approve" => review::APPROVED,
            "reject" => review::REJECTED,
            _ => return Err(AppError::BadRequest("Unknown decision.".into())),
        };
        let note = clean_note(&self.note, MAX_ADMIN_NOTE).map_err(AppError::BadRequest)?;
        // An approval needs no note; keep none so an old one does not linger.
        Ok((status, note.filter(|_| status == review::REJECTED)))
    }
}

fn review_redirect(back: &str, edit: String, files: String, status: &str) -> Response {
    let msg = if status == review::APPROVED {
        "approved"
    } else {
        "rejected"
    };
    let to = match back {
        "edit" => edit,
        "files" => files,
        _ => format!("/admin/review?msg={msg}"),
    };
    Redirect::to(&to).into_response()
}

async fn project_review(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<ReviewForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let (status, note) = f.decide()?;
    queries::get_project(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    queries::set_project_review(&st.db, id, status, note.as_deref()).await?;
    tracing::info!(project_id = id, status, "project reviewed");
    Ok(review_redirect(
        &f.back,
        format!("/admin/projects/{id}/edit"),
        format!("/admin/projects/{id}/releases"),
        status,
    ))
}

async fn release_review(
    admin: AdminUser,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(f): Form<ReviewForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let (status, note) = f.decide()?;
    queries::get_release(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    queries::set_release_review(&st.db, id, status, note.as_deref()).await?;
    tracing::info!(release_id = id, status, "release reviewed");
    Ok(review_redirect(
        &f.back,
        format!("/admin/releases/{id}/edit"),
        format!("/admin/releases/{id}/files"),
        status,
    ))
}

// ---- users ---------------------------------------------------------------------

struct UserView {
    id: i64,
    username: String,
    is_admin: bool,
    status: String,
    signup_note: String,
    created: String,
    projects: i64,
    used: String,
    /// Effective values, e.g. "100.0 MiB (default)".
    upload_limit: String,
    storage_quota: String,
    /// Override as input text ("" = default).
    upload_input: String,
    quota_input: String,
}

struct RequestView {
    id: i64,
    username: String,
    upload_limit: String,
    storage_quota: String,
    upload_input: String,
    quota_input: String,
    reason: String,
    created: String,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersTemplate {
    l: Layout,
    pending: Vec<UserView>,
    users: Vec<UserView>,
    requests: Vec<RequestView>,
    registration_open: bool,
    max_upload: String,
    min_len: usize,
    new_username: String,
    flash: Option<&'static str>,
    error: Option<String>,
}

fn user_view(st: &AppState, u: UserRow) -> UserView {
    let site = st.site();
    let effective = |v: Option<i64>, default: u64| match v.and_then(|v| u64::try_from(v).ok()) {
        Some(v) => human_size(v),
        None => format!("{} (default)", human_size(default)),
    };
    let input = |v: Option<i64>| {
        v.and_then(|v| u64::try_from(v).ok())
            .map(size_input)
            .unwrap_or_default()
    };
    UserView {
        id: u.id,
        is_admin: u.role == "admin",
        status: u.status,
        signup_note: u.signup_note.unwrap_or_default(),
        created: u.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        projects: u.projects,
        used: human_size(u64::try_from(u.used_bytes).unwrap_or(0)),
        upload_limit: effective(u.upload_limit_bytes, site.member_upload_limit),
        storage_quota: effective(u.storage_quota_bytes, site.member_storage_quota),
        upload_input: input(u.upload_limit_bytes),
        quota_input: input(u.storage_quota_bytes),
        username: u.username,
    }
}

fn request_view(r: LimitRequest) -> RequestView {
    let input = |v: Option<i64>| {
        v.and_then(|v| u64::try_from(v).ok())
            .map(size_input)
            .unwrap_or_default()
    };
    RequestView {
        id: r.id,
        upload_limit: opt_size_text(r.upload_limit_bytes),
        storage_quota: opt_size_text(r.storage_quota_bytes),
        upload_input: input(r.upload_limit_bytes),
        quota_input: input(r.storage_quota_bytes),
        username: r.username,
        reason: r.reason,
        created: r.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
    }
}

fn users_flash(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "created" => "Member account created. Give them the username and password.",
        "approve" => "Account approved; they can sign in now.",
        "reject" => "Request rejected and removed.",
        "disable" => "Account disabled; their sessions were ended.",
        "enable" => "Account enabled.",
        "limits" => "Limits saved.",
        "password" => "Password set; their sessions were ended.",
        "reset-2fa" => "Two-factor authentication turned off for that account.",
        "delete" => "Account deleted with all its projects and files.",
        "request-approve" => "Request approved; the new limits apply now.",
        "request-deny" => "Request denied.",
        _ => return None,
    })
}

async fn render_users(
    st: &AppState,
    admin: &Actor,
    flash: Option<&'static str>,
    error: Option<String>,
    new_username: String,
) -> Result<Response, AppError> {
    let (pending, users): (Vec<_>, Vec<_>) = queries::list_users(&st.db)
        .await?
        .into_iter()
        .map(|u| user_view(st, u))
        .partition(|u| u.status == account::PENDING);
    let requests = queries::pending_limit_requests(&st.db)
        .await?
        .into_iter()
        .map(request_view)
        .collect();
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&UsersTemplate {
        l: st.layout("Users", Some(admin)),
        pending,
        users,
        requests,
        registration_open: st.site().registration_open,
        max_upload: human_size(st.config.max_upload_bytes),
        min_len: super::auth::MIN_PASSWORD_LEN,
        new_username,
        flash,
        error,
    })?;
    Ok((status, page).into_response())
}

async fn users_page(
    admin: AdminUser,
    State(st): State<AppState>,
    Query(q): Query<MsgQuery>,
) -> Result<Response, AppError> {
    render_users(
        &st,
        &admin,
        users_flash(q.msg.as_deref()),
        None,
        String::new(),
    )
    .await
}

fn users_redirect(msg: &str) -> Response {
    Redirect::to(&format!("/admin/users?msg={msg}")).into_response()
}

#[derive(Deserialize)]
struct CreateUserForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
}

/// The admin creates an (active) member account directly.
async fn user_create(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<CreateUserForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let username = f.username.trim().to_string();
    let error = if !valid_username(&username) {
        Some("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.".to_string())
    } else {
        password_problem(&f.password, &f.password_confirm)
    };
    if let Some(e) = error {
        return render_users(&st, &admin, None, Some(e), username).await;
    }
    let hash = hash_password(&st, f.password).await?;
    match queries::create_member(&st.db, &username, &hash, account::ACTIVE, None).await {
        Ok(_) => {
            tracing::info!("member account created by admin");
            Ok(users_redirect("created"))
        }
        Err(e) if is_unique_violation(&e) => {
            let msg = "That username is already taken.".to_string();
            render_users(&st, &admin, None, Some(msg), username).await
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize)]
struct UserActionForm {
    csrf: String,
    confirm: Option<String>,
    #[serde(default)]
    upload_limit: String,
    #[serde(default)]
    storage_quota: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_confirm: String,
}

/// approve / reject (pending requests), disable / enable, limits,
/// password, reset-2fa, delete. Never applies to administrators.
async fn user_action(
    admin: AdminUser,
    State(st): State<AppState>,
    Path((id, action)): Path<(i64, String)>,
    Form(f): Form<UserActionForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let user = queries::get_user_row(&st.db, id)
        .await?
        .filter(|u| u.role == "member")
        .ok_or(AppError::NotFound)?;
    let fail = |msg: &str| render_users(&st, &admin, None, Some(msg.to_string()), String::new());
    match action.as_str() {
        "approve" => {
            if user.status != account::PENDING {
                return fail("That account is not awaiting approval.").await;
            }
            queries::set_member_status(&st.db, id, account::ACTIVE).await?;
        }
        "reject" => {
            if queries::delete_member(&st.db, id, true).await?.is_none() {
                return fail("That account is not awaiting approval.").await;
            }
        }
        "disable" => {
            queries::set_member_status(&st.db, id, account::DISABLED).await?;
            queries::delete_user_sessions(&st.db, id, None).await?;
        }
        "enable" => {
            if user.status == account::PENDING {
                return fail("Approve the request instead.").await;
            }
            queries::set_member_status(&st.db, id, account::ACTIVE).await?;
        }
        "limits" => {
            let limit = optional_size(&f.upload_limit, "Upload limit");
            let quota = optional_size(&f.storage_quota, "Storage quota");
            match (limit, quota) {
                (Ok(limit), Ok(quota)) => {
                    queries::set_member_limits(&st.db, id, limit, quota).await?
                }
                (Err(e), _) | (_, Err(e)) => return fail(&e).await,
            }
        }
        "password" => {
            if let Some(e) = password_problem(&f.password, &f.password_confirm) {
                return fail(&e).await;
            }
            let hash = hash_password(&st, f.password).await?;
            queries::update_password(&st.db, id, &hash).await?;
            queries::delete_user_sessions(&st.db, id, None).await?;
        }
        "reset-2fa" => {
            queries::reset_totp(&st.db, Some(&user.username)).await?;
        }
        "delete" => {
            if f.confirm.is_none() {
                return fail("Tick the confirmation box to delete the account.").await;
            }
            if let Some(objects) = queries::delete_member(&st.db, id, false).await? {
                delete_objects(&st, objects).await;
            }
        }
        _ => return Err(AppError::NotFound),
    }
    tracing::info!(user_id = id, action = %action, "member account changed");
    Ok(users_redirect(&action))
}

#[derive(Deserialize)]
struct DecisionForm {
    csrf: String,
    #[serde(default)]
    upload_limit: String,
    #[serde(default)]
    storage_quota: String,
    #[serde(default)]
    note: String,
}

/// Approves (with the values as granted, which the admin may adjust) or
/// denies a member's limit request.
async fn limit_decision(
    admin: AdminUser,
    State(st): State<AppState>,
    Path((id, action)): Path<(i64, String)>,
    Form(f): Form<DecisionForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    queries::get_limit_request(&st.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let fail = |msg: String| render_users(&st, &admin, None, Some(msg), String::new());
    let note = match clean_note(&f.note, MAX_ADMIN_NOTE) {
        Ok(n) => n,
        Err(e) => return fail(e).await,
    };
    let approve = match action.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return Err(AppError::NotFound),
    };
    let granted = if approve {
        match (
            optional_size(&f.upload_limit, "Upload limit"),
            optional_size(&f.storage_quota, "Storage quota"),
        ) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return fail(e).await,
        }
    } else {
        (None, None)
    };
    if !queries::decide_limit_request(&st.db, id, approve, granted, note.as_deref()).await? {
        return fail("That request was already decided.".into()).await;
    }
    tracing::info!(request_id = id, approve, "limit request decided");
    Ok(users_redirect(if approve {
        "request-approve"
    } else {
        "request-deny"
    }))
}

// ---- member: limits and requests ---------------------------------------------------

struct OwnRequestView {
    created: String,
    upload_limit: String,
    storage_quota: String,
    reason: String,
    status: String,
    admin_note: String,
}

#[derive(Template)]
#[template(path = "my/limits.html")]
struct LimitsTemplate {
    l: Layout,
    upload_limit: String,
    storage_quota: String,
    used: String,
    max_upload: String,
    has_pending: bool,
    requests: Vec<OwnRequestView>,
    form_upload: String,
    form_quota: String,
    form_reason: String,
    flash: bool,
    error: Option<String>,
}

async fn render_limits(
    st: &AppState,
    actor: &Actor,
    form: (String, String, String),
    flash: bool,
    error: Option<String>,
) -> Result<Response, AppError> {
    let caps = MemberCaps::load(st, actor.id).await?;
    let all = queries::limit_requests_for_user(&st.db, actor.id).await?;
    let has_pending = all.iter().any(|r| r.status == "pending");
    let requests = all
        .into_iter()
        .map(|r| OwnRequestView {
            created: r.created_at.format("%Y-%m-%d").to_string(),
            upload_limit: opt_size_text(r.upload_limit_bytes),
            storage_quota: opt_size_text(r.storage_quota_bytes),
            reason: r.reason,
            status: r.status,
            admin_note: r.admin_note.unwrap_or_default(),
        })
        .collect();
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&LimitsTemplate {
        l: st.layout("Limits", Some(actor)),
        upload_limit: human_size(caps.file_limit),
        storage_quota: human_size(caps.quota),
        used: human_size(caps.used),
        max_upload: human_size(st.config.max_upload_bytes),
        has_pending,
        requests,
        form_upload: form.0,
        form_quota: form.1,
        form_reason: form.2,
        flash,
        error,
    })?;
    Ok((status, page).into_response())
}

async fn limits_page(
    actor: Actor,
    State(st): State<AppState>,
    Query(q): Query<MsgQuery>,
) -> Result<Response, AppError> {
    let flash = q.msg.as_deref() == Some("sent");
    render_limits(&st, &actor, Default::default(), flash, None).await
}

#[derive(Deserialize)]
struct LimitRequestForm {
    csrf: String,
    #[serde(default)]
    upload_limit: String,
    #[serde(default)]
    storage_quota: String,
    #[serde(default)]
    reason: String,
}

async fn limit_request(
    actor: Actor,
    State(st): State<AppState>,
    Form(f): Form<LimitRequestForm>,
) -> Result<Response, AppError> {
    actor.verify_csrf(&f.csrf)?;
    let reason = f.reason.trim().to_string();
    let limit = optional_size(&f.upload_limit, "Upload limit");
    let quota = optional_size(&f.storage_quota, "Storage quota");
    let pending = queries::limit_requests_for_user(&st.db, actor.id)
        .await?
        .iter()
        .any(|r| r.status == "pending");
    let error = match (&limit, &quota) {
        _ if pending => {
            Some("You already have a request waiting; an administrator will decide on it.".into())
        }
        (Err(e), _) | (_, Err(e)) => Some(e.clone()),
        (Ok(None), Ok(None)) => Some("Enter the upload limit and/or quota you need.".into()),
        _ if reason.chars().count() < MIN_REASON => {
            Some("Tell the administrator why you need it (a sentence or two).".into())
        }
        _ if reason.chars().count() > MAX_REASON => Some(format!(
            "The reason must be at most {MAX_REASON} characters."
        )),
        _ => None,
    };
    if let Some(e) = error {
        let form = (f.upload_limit, f.storage_quota, reason);
        return render_limits(&st, &actor, form, false, Some(e)).await;
    }
    let (limit, quota) = (limit.unwrap_or(None), quota.unwrap_or(None));
    queries::create_limit_request(&st.db, actor.id, limit, quota, &reason).await?;
    tracing::info!("limit increase requested");
    Ok(Redirect::to("/my/limits?msg=sent").into_response())
}
