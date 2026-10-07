//! The signed-in user's own account (administrator under /admin, members
//! under /my): password change and (when TOTP_ENABLED) two-factor
//! enrolment, recovery codes and removal. Every change needs the current
//! password; a password change ends all other sessions.

use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use super::auth::{
    Actor, check_current_password, hash_password, password_problem, restart_session,
    second_factor_ok,
};
use crate::db::queries;
use crate::error::AppError;
use crate::net::ClientInfo;
use crate::state::AppState;
use crate::totp;
use crate::views::{Layout, render};

pub fn routes() -> Router<AppState> {
    let mut router = Router::new();
    for base in ["/admin", "/my"] {
        router = router
            .route(
                &format!("{base}/password"),
                get(password_page).post(password_change),
            )
            .route(&format!("{base}/2fa"), get(twofa_page))
            .route(&format!("{base}/2fa/setup"), post(twofa_setup))
            .route(&format!("{base}/2fa/confirm"), post(twofa_confirm))
            .route(&format!("{base}/2fa/recovery-codes"), post(twofa_recovery))
            .route(&format!("{base}/2fa/disable"), post(twofa_disable));
    }
    router
}

// ---- password change ---------------------------------------------------------

#[derive(Template)]
#[template(path = "admin/password.html")]
struct PasswordTemplate {
    l: Layout,
    error: Option<String>,
    done: bool,
}

#[derive(Deserialize)]
struct MsgQuery {
    msg: Option<String>,
}

async fn password_page(
    admin: Actor,
    State(st): State<AppState>,
    Query(q): Query<MsgQuery>,
) -> Result<Response, AppError> {
    render(&PasswordTemplate {
        l: st.layout("Change password", Some(&admin)),
        error: None,
        done: q.msg.as_deref() == Some("changed"),
    })
}

#[derive(Deserialize)]
struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    confirm: String,
}

async fn password_change(
    admin: Actor,
    State(st): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Form(f): Form<PasswordForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let error =
        if !check_current_password(&st, &client, admin.id, &admin.username, &f.current).await? {
            Some("The current password is wrong.".to_string())
        } else if f.new == f.current {
            Some("The new password must differ from the current one.".to_string())
        } else {
            password_problem(&f.new, &f.confirm)
        };
    if let Some(error) = error {
        let page = render(&PasswordTemplate {
            l: st.layout("Change password", Some(&admin)),
            error: Some(error),
            done: false,
        })?;
        return Ok((StatusCode::BAD_REQUEST, page).into_response());
    }
    let hash = hash_password(&st, f.new).await?;
    queries::update_password(&st.db, admin.id, &hash).await?;
    // Every other session ends; this browser gets a fresh one.
    let jar = restart_session(&st, jar, &admin).await?;
    tracing::info!("password changed; other sessions ended");
    Ok((
        jar,
        Redirect::to(&format!("{}/password?msg=changed", admin.base())),
    )
        .into_response())
}

// ---- two-factor authentication ------------------------------------------------

#[derive(Template)]
#[template(path = "admin/twofa.html")]
struct TwofaTemplate {
    l: Layout,
    enabled: bool,
    remaining_codes: i64,
    /// Enrolment in progress: secret (base32) and QR code (inline SVG).
    setup_secret: Option<String>,
    setup_qr: String,
    /// Shown exactly once after enabling / regenerating.
    new_codes: Vec<String>,
    error: Option<String>,
}

fn require_totp(st: &AppState) -> Result<[u8; 32], AppError> {
    match (st.config.security.totp_enabled, st.config.security.totp_key) {
        (true, Some(key)) => Ok(key),
        _ => Err(AppError::NotFound),
    }
}

async fn twofa_render(
    st: &AppState,
    admin: &Actor,
    setup: Option<&[u8]>,
    new_codes: Vec<String>,
    error: Option<String>,
) -> Result<Response, AppError> {
    let t = queries::get_totp(&st.db, admin.id).await?;
    let (setup_secret, setup_qr) = match setup {
        Some(secret) => {
            let uri = totp::otpauth_uri(&st.site().name, &admin.username, secret);
            (Some(totp::base32_encode(secret)), totp::qr_svg(&uri))
        }
        None => (None, String::new()),
    };
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&TwofaTemplate {
        l: st.layout("Two-factor authentication", Some(admin)),
        enabled: t.totp_enabled != 0,
        remaining_codes: queries::unused_recovery_codes(&st.db, admin.id).await?,
        setup_secret,
        setup_qr,
        new_codes,
        error,
    })?;
    Ok((status, page).into_response())
}

async fn twofa_page(admin: Actor, State(st): State<AppState>) -> Result<Response, AppError> {
    require_totp(&st)?;
    twofa_render(&st, &admin, None, Vec::new(), None).await
}

#[derive(Deserialize)]
struct PasswordOnlyForm {
    csrf: String,
    password: String,
}

/// Generates a secret (stored encrypted, not active yet) and shows it.
async fn twofa_setup(
    admin: Actor,
    State(st): State<AppState>,
    client: ClientInfo,
    Form(f): Form<PasswordOnlyForm>,
) -> Result<Response, AppError> {
    let key = require_totp(&st)?;
    admin.verify_csrf(&f.csrf)?;
    if !check_current_password(&st, &client, admin.id, &admin.username, &f.password).await? {
        return twofa_render(
            &st,
            &admin,
            None,
            Vec::new(),
            Some("The password is wrong.".into()),
        )
        .await;
    }
    if queries::get_totp(&st.db, admin.id).await?.totp_enabled != 0 {
        return twofa_render(
            &st,
            &admin,
            None,
            Vec::new(),
            Some("Two-factor authentication is already on.".into()),
        )
        .await;
    }
    let secret = totp::new_secret();
    queries::set_pending_totp(&st.db, admin.id, &totp::encrypt(&key, &secret)).await?;
    twofa_render(&st, &admin, Some(&secret), Vec::new(), None).await
}

#[derive(Deserialize)]
struct ConfirmForm {
    csrf: String,
    code: String,
}

/// Turns 2FA on once a code from the new secret checks out, and shows the
/// recovery codes once.
async fn twofa_confirm(
    admin: Actor,
    State(st): State<AppState>,
    Form(f): Form<ConfirmForm>,
) -> Result<Response, AppError> {
    let key = require_totp(&st)?;
    admin.verify_csrf(&f.csrf)?;
    let t = queries::get_totp(&st.db, admin.id).await?;
    let Some(secret) = t
        .totp_secret_enc
        .as_deref()
        .and_then(|s| totp::decrypt(&key, s))
    else {
        return twofa_render(
            &st,
            &admin,
            None,
            Vec::new(),
            Some("Start the setup again.".into()),
        )
        .await;
    };
    let digits: String = f.code.chars().filter(|c| !c.is_whitespace()).collect();
    let now = chrono::Utc::now().timestamp();
    let ok = match totp::verify(&secret, &digits, now, t.totp_last_step) {
        Some(step) => queries::claim_totp_step(&st.db, admin.id, step).await?,
        None => false,
    };
    if !ok {
        return twofa_render(
            &st,
            &admin,
            Some(&secret),
            Vec::new(),
            Some(
                "That code did not match. Check the time on your device and try the next code."
                    .into(),
            ),
        )
        .await;
    }
    queries::enable_totp(&st.db, admin.id).await?;
    let codes = totp::new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    queries::replace_recovery_codes(&st.db, admin.id, &hashes).await?;
    tracing::info!("two-factor authentication enabled");
    twofa_render(&st, &admin, None, codes, None).await
}

async fn twofa_recovery(
    admin: Actor,
    State(st): State<AppState>,
    client: ClientInfo,
    Form(f): Form<PasswordOnlyForm>,
) -> Result<Response, AppError> {
    require_totp(&st)?;
    admin.verify_csrf(&f.csrf)?;
    if !check_current_password(&st, &client, admin.id, &admin.username, &f.password).await? {
        return twofa_render(
            &st,
            &admin,
            None,
            Vec::new(),
            Some("The password is wrong.".into()),
        )
        .await;
    }
    let codes = totp::new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    queries::replace_recovery_codes(&st.db, admin.id, &hashes).await?;
    tracing::info!("recovery codes regenerated");
    twofa_render(&st, &admin, None, codes, None).await
}

#[derive(Deserialize)]
struct DisableForm {
    csrf: String,
    password: String,
    code: String,
}

async fn twofa_disable(
    admin: Actor,
    State(st): State<AppState>,
    client: ClientInfo,
    Form(f): Form<DisableForm>,
) -> Result<Response, AppError> {
    require_totp(&st)?;
    admin.verify_csrf(&f.csrf)?;
    if !check_current_password(&st, &client, admin.id, &admin.username, &f.password).await?
        || !second_factor_ok(&st, admin.id, &f.code).await?
    {
        return twofa_render(
            &st,
            &admin,
            None,
            Vec::new(),
            Some("Password or code is wrong.".into()),
        )
        .await;
    }
    queries::reset_totp(&st.db, Some(&admin.username)).await?;
    tracing::info!("two-factor authentication disabled");
    Ok(Redirect::to("/login").into_response())
}
