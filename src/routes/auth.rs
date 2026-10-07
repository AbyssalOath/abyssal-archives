//! First-run setup, registration requests, login (with optional TOTP),
//! logout, sessions and CSRF.
//!
//! Roles: the first account is the administrator; every other account is a
//! member (created by the admin, or requested at /register and approved).
//! Administrators can only sign in, and use their session, where
//! [`guard::admin_access_allowed`] (ADMIN_HOST / ADMIN_ALLOWED_CIDRS).
//!
//! Sessions: 256-bit random token (OS CSPRNG) in an HttpOnly,
//! SameSite=Strict cookie, `__Host-` prefixed and Secure when COOKIE_SECURE.
//! The database stores only SHA-256(token). Sessions end after
//! SESSION_IDLE_TIMEOUT_MINS of inactivity or SESSION_ABSOLUTE_TIMEOUT_HOURS,
//! whichever comes first, and are rotated on every login. Each session has
//! its own CSRF token; the pre-login forms use a double-submit cookie.

use std::ops::Deref;
use std::sync::OnceLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use askama::Template;
use axum::Router;
use axum::extract::{Form, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;

use crate::db::models::{SessionUser, account};
use crate::db::queries::{self, is_unique_violation};
use crate::error::AppError;
use crate::guard;
use crate::net::{ClientInfo, client_info, log_ip, peer_ip};
use crate::state::AppState;
use crate::totp;
use crate::util::{ct_eq, random_token, sha256_hex};
use crate::views::{Layout, render};

pub const MIN_PASSWORD_LEN: usize = 12;
/// /register stops taking requests while this many await review.
pub const MAX_PENDING_ACCOUNTS: i64 = 100;
/// Longest note an applicant can leave for the admin.
pub const MAX_SIGNUP_NOTE: usize = 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/setup", get(setup_form).post(setup_submit))
        .route("/login", get(login_form).post(login_submit))
        .route(
            "/login/2fa",
            get(second_factor_form).post(second_factor_submit),
        )
        .route("/logout", post(logout))
        .route("/register", get(register_form).post(register_submit))
}

// ---- cookies -----------------------------------------------------------------

/// `__Host-` cookies must be Secure, Path=/ and host-only, which also stops
/// sibling subdomains from planting a session (cookie tossing).
pub fn session_cookie_name(st: &AppState) -> &'static str {
    if st.config.cookie_secure {
        "__Host-sid"
    } else {
        "sid"
    }
}

fn pre_csrf_cookie_name(st: &AppState) -> &'static str {
    if st.config.cookie_secure {
        "__Host-csrf_pre"
    } else {
        "csrf_pre"
    }
}

fn cookie(st: &AppState, name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(st.config.cookie_secure)
        .build()
}

fn removal(name: &'static str) -> Cookie<'static> {
    Cookie::build(name).path("/").build()
}

// ---- sessions ------------------------------------------------------------------

/// The session behind the request's cookie (hash, user), if still valid.
async fn current_session(
    st: &AppState,
    jar: &CookieJar,
) -> Result<Option<(String, SessionUser)>, AppError> {
    let Some(token) = jar
        .get(session_cookie_name(st))
        .map(|c| c.value().to_string())
    else {
        return Ok(None);
    };
    let hash = sha256_hex(token.as_bytes());
    let idle = st.config.security.session_idle.as_secs();
    Ok(queries::find_session(&st.db, &hash, idle)
        .await?
        .map(|u| (hash, u)))
}

/// Starts a fresh session (rotating away any session the browser had) and
/// returns the jar with the new cookie.
async fn start_session(
    st: &AppState,
    jar: CookieJar,
    user_id: i64,
    mfa_pending: bool,
) -> Result<CookieJar, AppError> {
    if let Some(old) = jar.get(session_cookie_name(st)) {
        queries::delete_session(&st.db, &sha256_hex(old.value().as_bytes())).await?;
    }
    let token = random_token();
    let absolute = st.config.security.session_absolute.as_secs();
    queries::create_session(
        &st.db,
        &sha256_hex(token.as_bytes()),
        user_id,
        &random_token(),
        absolute,
        mfa_pending,
    )
    .await?;
    let mut c = cookie(st, session_cookie_name(st), token);
    c.set_max_age(time::Duration::seconds(absolute as i64));
    Ok(jar.add(c).remove(removal(pre_csrf_cookie_name(st))))
}

/// Starts a new session for the logged-in user after a password change,
/// ending every other session.
pub async fn restart_session(
    st: &AppState,
    jar: CookieJar,
    user: &Actor,
) -> Result<CookieJar, AppError> {
    queries::delete_user_sessions(&st.db, user.id, None).await?;
    start_session(st, jar, user.id, false).await
}

/// The signed-in user of a request (sessions of pending or disabled
/// accounts are never valid). Extracting it also enforces where each role
/// may go:
///
/// * `/admin/...`: administrators only; members get 403.
/// * `/my/...`: members only; administrators are sent to /admin.
/// * anything else (e.g. /logout): any signed-in user.
/// * an administrator's session only works where
///   [`guard::admin_access_allowed`] (404 elsewhere).
///
/// Without a valid session: redirect to /login (to /login/2fa while the
/// second factor is pending).
pub struct Actor {
    pub id: i64,
    pub username: String,
    pub csrf: String,
    pub is_admin: bool,
    session_hash: String,
}

impl Actor {
    /// Checks a submitted CSRF token against this session's token.
    pub fn verify_csrf(&self, token: &str) -> Result<(), AppError> {
        if ct_eq(token, &self.csrf) {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "Your form expired or was submitted from another site. Go back, reload and try again.".into(),
            ))
        }
    }

    /// URL prefix of this user's workspace.
    pub fn base(&self) -> &'static str {
        if self.is_admin { "/admin" } else { "/my" }
    }
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Response> {
        let jar = CookieJar::from_headers(&parts.headers);
        let (hash, u) = match current_session(st, &jar).await {
            Ok(Some((_, u))) if u.mfa_pending != 0 => {
                return Err(Redirect::to("/login/2fa").into_response());
            }
            Ok(Some(found)) => found,
            Ok(None) => return Err(Redirect::to("/login").into_response()),
            Err(e) => return Err(e.into_response()),
        };
        let is_admin = u.role == "admin";
        let path = parts.uri.path();
        if is_admin {
            let client = client_info(peer_ip(parts), &parts.headers, &st.config.security.proxy);
            if !guard::admin_access_allowed(st, client.ip, &parts.headers) {
                return Err(AppError::NotFound.into_response());
            }
            if guard::is_member_path(path) {
                return Err(Redirect::to("/admin").into_response());
            }
        } else if guard::is_admin_path(path) {
            return Err(AppError::Forbidden("Administrators only.".into()).into_response());
        }
        if let Err(e) = queries::touch_session(&st.db, &hash).await {
            tracing::warn!(error = %e, "could not update session activity");
        }
        Ok(Actor {
            id: u.user_id,
            username: u.username,
            csrf: u.csrf_token,
            is_admin,
            session_hash: hash,
        })
    }
}

/// Extractor for admin-only handlers: an [`Actor`] that is an
/// administrator wherever the handler is mounted (403 otherwise).
pub struct AdminUser(pub Actor);

impl Deref for AdminUser {
    type Target = Actor;

    fn deref(&self) -> &Actor {
        &self.0
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Response> {
        let actor = Actor::from_request_parts(parts, st).await?;
        if !actor.is_admin {
            return Err(AppError::Forbidden("Administrators only.".into()).into_response());
        }
        Ok(AdminUser(actor))
    }
}

// ---- passwords -----------------------------------------------------------------

/// Argon2id with the configured parameters (OWASP defaults: 19 MiB, 2
/// iterations, 1 lane; ARGON2_MEMORY_KIB / _ITERATIONS / _PARALLELISM).
fn argon2(st: &AppState) -> Argon2<'static> {
    let s = &st.config.security;
    let params = Params::new(
        s.argon2_memory_kib,
        s.argon2_iterations,
        s.argon2_parallelism,
        None,
    )
    .expect("Argon2 parameters were validated at startup");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub async fn hash_password(st: &AppState, password: String) -> Result<String, AppError> {
    let a = argon2(st);
    tokio::task::spawn_blocking(move || {
        a.hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(AppError::internal)
    })
    .await
    .map_err(AppError::internal)?
}

/// Verifies on a blocking thread. A missing user is checked against a dummy
/// hash with the same parameters, so the response time does not reveal
/// which usernames exist. Returns (valid, hash should be upgraded).
pub async fn verify_password(
    st: &AppState,
    password: String,
    hash: Option<String>,
) -> (bool, bool) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let a = argon2(st);
    let wanted = (
        st.config.security.argon2_memory_kib,
        st.config.security.argon2_iterations,
        st.config.security.argon2_parallelism,
    );
    tokio::task::spawn_blocking(move || {
        let real = hash.is_some();
        let hash = hash.unwrap_or_else(|| {
            DUMMY
                .get_or_init(|| {
                    a.hash_password(random_token().as_bytes())
                        .map(|h| h.to_string())
                        .unwrap_or_default()
                })
                .clone()
        });
        let Ok(parsed) = PasswordHash::new(&hash) else {
            return (false, false);
        };
        let ok = a.verify_password(password.as_bytes(), &parsed).is_ok() && real;
        let current = parsed.algorithm.as_str() == "argon2id"
            && Params::try_from(&parsed)
                .is_ok_and(|p| (p.m_cost(), p.t_cost(), p.p_cost()) == wanted);
        (ok, ok && !current)
    })
    .await
    .unwrap_or((false, false))
}

pub fn valid_username(u: &str) -> bool {
    (1..=64).contains(&u.len())
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Checks a proposed new password; None if acceptable.
pub fn password_problem(new: &str, confirm: &str) -> Option<String> {
    if new.chars().count() < MIN_PASSWORD_LEN || new.len() > 1024 {
        Some(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters."
        ))
    } else if new != confirm {
        Some("Passwords do not match.".into())
    } else {
        None
    }
}

/// Rate-limited password check for an already identified user (password
/// change, 2FA changes). Records failures like a failed login.
pub async fn check_current_password(
    st: &AppState,
    client: &ClientInfo,
    user_id: i64,
    username: &str,
    password: &str,
) -> Result<bool, AppError> {
    if let Err(wait) = st.login_limiter.check(client.ip, username) {
        return Err(AppError::TooManyRequests(format!(
            "Too many failed attempts. Try again in {} seconds.",
            wait.as_secs().max(1)
        )));
    }
    let user = queries::get_user(&st.db, user_id).await?;
    let (ok, _) = verify_password(st, password.to_string(), user.map(|u| u.password_hash)).await;
    if ok {
        st.login_limiter.reset(client.ip, username);
    } else {
        st.login_limiter.record_failure(client.ip, username);
        tracing::info!(client = %log_ip(client.ip, st.config.security.log_ip_mode), "wrong current password");
    }
    Ok(ok)
}

// ---- pre-login CSRF (double-submit cookie) --------------------------------------

/// Returns the jar with a pre-login CSRF cookie (reusing an existing one)
/// and the token to embed in the form.
fn pre_csrf(st: &AppState, jar: CookieJar) -> (CookieJar, String) {
    if let Some(c) = jar
        .get(pre_csrf_cookie_name(st))
        .filter(|c| c.value().len() == 64)
    {
        let v = c.value().to_string();
        return (jar, v);
    }
    let token = random_token();
    (
        jar.add(cookie(st, pre_csrf_cookie_name(st), token.clone())),
        token,
    )
}

fn check_pre_csrf(st: &AppState, jar: &CookieJar, submitted: &str) -> Result<(), AppError> {
    match jar.get(pre_csrf_cookie_name(st)) {
        Some(c) if ct_eq(c.value(), submitted) => Ok(()),
        _ => Err(AppError::Forbidden(
            "Your form expired or cookies are disabled. Reload the page and try again.".into(),
        )),
    }
}

// ---- /setup ----------------------------------------------------------------

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupTemplate {
    l: Layout,
    csrf: String,
    username: String,
    error: Option<String>,
    min_len: usize,
}

/// /setup exists only while no user exists, and never with SETUP_ENABLED=false.
async fn setup_available(st: &AppState) -> Result<(), AppError> {
    if !st.config.security.setup_enabled || queries::count_users(&st.db).await? > 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

async fn setup_form(State(st): State<AppState>, jar: CookieJar) -> Result<Response, AppError> {
    // Once the administrator exists, /setup explains how to get an account.
    if queries::count_users(&st.db).await? > 0 {
        return Ok(Redirect::to("/register").into_response());
    }
    setup_available(&st).await?;
    let (jar, csrf) = pre_csrf(&st, jar);
    let page = render(&SetupTemplate {
        l: st.layout("Setup", None),
        csrf,
        username: String::new(),
        error: None,
        min_len: MIN_PASSWORD_LEN,
    })?;
    Ok((jar, page).into_response())
}

#[derive(Deserialize)]
struct SetupForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
}

async fn setup_submit(
    State(st): State<AppState>,
    jar: CookieJar,
    Form(f): Form<SetupForm>,
) -> Result<Response, AppError> {
    setup_available(&st).await?;
    check_pre_csrf(&st, &jar, &f.csrf)?;
    let username = f.username.trim().to_string();
    let error = if !valid_username(&username) {
        Some("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.".to_string())
    } else {
        password_problem(&f.password, &f.password_confirm)
    };
    if let Some(error) = error {
        let page = render(&SetupTemplate {
            l: st.layout("Setup", None),
            csrf: f.csrf,
            username,
            error: Some(error),
            min_len: MIN_PASSWORD_LEN,
        })?;
        return Ok((StatusCode::BAD_REQUEST, page).into_response());
    }

    let hash = hash_password(&st, f.password).await?;
    let Some(user_id) = queries::create_first_admin(&st.db, &username, &hash).await? else {
        return Err(AppError::NotFound); // lost a race with another setup
    };
    tracing::info!("administrator account created");
    let jar = start_session(&st, jar, user_id, false).await?;
    Ok((jar, Redirect::to("/admin")).into_response())
}

// ---- /login, /login/2fa, /logout --------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    l: Layout,
    csrf: String,
    username: String,
    error: Option<String>,
}

async fn login_form(State(st): State<AppState>, jar: CookieJar) -> Result<Response, AppError> {
    if st.config.security.setup_enabled && queries::count_users(&st.db).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    let (jar, csrf) = pre_csrf(&st, jar);
    let page = render(&LoginTemplate {
        l: st.layout("Sign in", None),
        csrf,
        username: String::new(),
        error: None,
    })?;
    Ok((jar, page).into_response())
}

#[derive(Deserialize)]
struct LoginForm {
    csrf: String,
    username: String,
    password: String,
}

async fn login_submit(
    State(st): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    Form(f): Form<LoginForm>,
) -> Result<Response, AppError> {
    check_pre_csrf(&st, &jar, &f.csrf)?;
    let username = f.username.trim().to_string();
    let fail = |status: StatusCode, msg: String| -> Result<Response, AppError> {
        let page = render(&LoginTemplate {
            l: st.layout("Sign in", None),
            csrf: f.csrf.clone(),
            username: username.clone(),
            error: Some(msg),
        })?;
        Ok((status, page).into_response())
    };
    let who = log_ip(client.ip, st.config.security.log_ip_mode);

    if let Err(wait) = st.login_limiter.check(client.ip, &username) {
        tracing::warn!(client = %who, "login rate limit hit");
        return fail(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Too many failed attempts. Try again in {} seconds.",
                wait.as_secs().max(1)
            ),
        );
    }
    let user = queries::find_user(&st.db, &username).await?;
    let (ok, upgrade) = verify_password(
        &st,
        f.password.clone(),
        user.as_ref().map(|u| u.password_hash.clone()),
    )
    .await;
    // An administrator outside ADMIN_HOST / ADMIN_ALLOWED_CIDRS gets the
    // same answer as a wrong password.
    let admin_refused = user.as_ref().is_some_and(|u| u.role == "admin")
        && !guard::admin_access_allowed(&st, client.ip, &headers);
    if ok && admin_refused {
        tracing::info!(client = %who, "administrator sign-in refused here (ADMIN_HOST / ADMIN_ALLOWED_CIDRS)");
    }
    match user {
        Some(u) if ok && !admin_refused && u.status != account::ACTIVE => {
            // Only someone with the right password learns the account state.
            st.login_limiter.reset(client.ip, &username);
            let msg = if u.status == account::PENDING {
                "Your account is awaiting approval by an administrator. Please try again later."
            } else {
                "This account has been disabled. Contact the site administrator."
            };
            fail(StatusCode::FORBIDDEN, msg.into())
        }
        Some(u) if ok && !admin_refused => {
            st.login_limiter.reset(client.ip, &username);
            if upgrade {
                match hash_password(&st, f.password.clone()).await {
                    Ok(h) => queries::update_password(&st.db, u.id, &h).await?,
                    Err(e) => tracing::warn!(error = ?e, "could not upgrade password hash"),
                }
            }
            let second_factor = st.config.security.totp_enabled && u.totp_enabled != 0;
            tracing::info!(client = %who, second_factor, "password accepted");
            let jar = start_session(&st, jar, u.id, second_factor).await?;
            let next = if second_factor {
                "/login/2fa"
            } else {
                home_for(&u.role)
            };
            Ok((jar, Redirect::to(next)).into_response())
        }
        _ => {
            // Same message and similar timing for unknown users and wrong
            // passwords; neither the username nor the password is logged.
            st.login_limiter.record_failure(client.ip, &username);
            tracing::info!(client = %who, "failed login");
            fail(
                StatusCode::UNAUTHORIZED,
                "Invalid username or password.".into(),
            )
        }
    }
}

/// Where a role lands after signing in.
fn home_for(role: &str) -> &'static str {
    if role == "admin" { "/admin" } else { "/my" }
}

#[derive(Template)]
#[template(path = "login_2fa.html")]
struct SecondFactorTemplate {
    l: Layout,
    csrf: String,
    error: Option<String>,
}

/// The pending (password-checked, second factor missing) session.
async fn pending_session(
    st: &AppState,
    jar: &CookieJar,
) -> Result<Option<(String, SessionUser)>, AppError> {
    Ok(current_session(st, jar)
        .await?
        .filter(|(_, u)| u.mfa_pending != 0))
}

async fn second_factor_form(
    State(st): State<AppState>,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let Some((_, u)) = pending_session(&st, &jar).await? else {
        return Ok(Redirect::to("/login").into_response());
    };
    render(&SecondFactorTemplate {
        l: st.layout("Two-factor authentication", None),
        csrf: u.csrf_token,
        error: None,
    })
}

#[derive(Deserialize)]
struct SecondFactorForm {
    csrf: String,
    code: String,
}

async fn second_factor_submit(
    State(st): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Form(f): Form<SecondFactorForm>,
) -> Result<Response, AppError> {
    let Some((hash, u)) = pending_session(&st, &jar).await? else {
        return Ok(Redirect::to("/login").into_response());
    };
    if !ct_eq(&f.csrf, &u.csrf_token) {
        return Err(AppError::Forbidden(
            "Your form expired. Sign in again.".into(),
        ));
    }
    let fail = |status: StatusCode, msg: String| -> Result<Response, AppError> {
        let page = render(&SecondFactorTemplate {
            l: st.layout("Two-factor authentication", None),
            csrf: u.csrf_token.clone(),
            error: Some(msg),
        })?;
        Ok((status, page).into_response())
    };
    let who = log_ip(client.ip, st.config.security.log_ip_mode);
    if let Err(wait) = st.login_limiter.check(client.ip, &u.username) {
        return fail(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Too many failed attempts. Try again in {} seconds.",
                wait.as_secs().max(1)
            ),
        );
    }
    if second_factor_ok(&st, u.user_id, &f.code).await? {
        st.login_limiter.reset(client.ip, &u.username);
        queries::delete_session(&st.db, &hash).await?;
        let jar = start_session(&st, jar, u.user_id, false).await?;
        tracing::info!(client = %who, "second factor accepted");
        return Ok((jar, Redirect::to(home_for(&u.role))).into_response());
    }
    st.login_limiter.record_failure(client.ip, &u.username);
    tracing::info!(client = %who, "failed second factor");
    fail(StatusCode::UNAUTHORIZED, "Invalid code.".into())
}

/// A current TOTP code (each usable once) or an unused recovery code.
pub async fn second_factor_ok(st: &AppState, user_id: i64, code: &str) -> Result<bool, AppError> {
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != totp::DIGITS as usize {
        return Ok(queries::use_recovery_code(&st.db, user_id, &totp::recovery_hash(code)).await?);
    }
    let (Some(key), t) = (
        st.config.security.totp_key,
        queries::get_totp(&st.db, user_id).await?,
    ) else {
        return Ok(false);
    };
    let Some(secret) = t
        .totp_secret_enc
        .as_deref()
        .and_then(|s| totp::decrypt(&key, s))
    else {
        tracing::error!(
            "TOTP secret cannot be decrypted (TOTP_ENCRYPTION_KEY changed?); use `admin reset-2fa`"
        );
        return Ok(false);
    };
    let now = chrono::Utc::now().timestamp();
    match totp::verify(&secret, &digits, now, t.totp_last_step) {
        Some(step) => Ok(queries::claim_totp_step(&st.db, user_id, step).await?),
        None => Ok(false),
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(
    State(st): State<AppState>,
    user: Actor,
    jar: CookieJar,
    Form(f): Form<CsrfForm>,
) -> Result<Response, AppError> {
    user.verify_csrf(&f.csrf)?;
    queries::delete_session(&st.db, &user.session_hash).await?;
    let jar = jar.remove(removal(session_cookie_name(&st)));
    Ok((jar, Redirect::to("/")).into_response())
}

// ---- /register ------------------------------------------------------------------
// Account requests: only while "Allow registration requests" is on, and every
// account starts 'pending' until an administrator approves it. There is no
// e-mail: the applicant just tries to sign in later.

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    l: Layout,
    open: bool,
    contact_email: String,
    csrf: String,
    username: String,
    note: String,
    error: Option<String>,
    done: bool,
    min_len: usize,
}

impl RegisterTemplate {
    fn new(st: &AppState, csrf: String) -> Self {
        let site = st.site();
        RegisterTemplate {
            l: st.layout("Request an account", None),
            open: site.registration_open,
            contact_email: site.contact_email,
            csrf,
            username: String::new(),
            note: String::new(),
            error: None,
            done: false,
            min_len: MIN_PASSWORD_LEN,
        }
    }
}

async fn register_form(State(st): State<AppState>, jar: CookieJar) -> Result<Response, AppError> {
    if st.config.security.setup_enabled && queries::count_users(&st.db).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    let (jar, csrf) = pre_csrf(&st, jar);
    let page = render(&RegisterTemplate::new(&st, csrf))?;
    Ok((jar, page).into_response())
}

#[derive(Deserialize)]
struct RegisterForm {
    csrf: String,
    username: String,
    password: String,
    password_confirm: String,
    #[serde(default)]
    note: String,
}

async fn register_submit(
    State(st): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Form(f): Form<RegisterForm>,
) -> Result<Response, AppError> {
    if !st.site().registration_open {
        return Err(AppError::NotFound);
    }
    check_pre_csrf(&st, &jar, &f.csrf)?;
    let username = f.username.trim().to_string();
    let note = f.note.trim().to_string();
    let mut page = RegisterTemplate::new(&st, f.csrf.clone());
    page.username = username.clone();
    page.note = note.clone();

    let error = if let Err(wait) = st.signup_limiter.check(client.ip) {
        Some(format!(
            "Too many requests from your address. Try again in {} seconds.",
            wait.as_secs().max(1)
        ))
    } else if !valid_username(&username) {
        Some("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.".to_string())
    } else if note.chars().count() > MAX_SIGNUP_NOTE {
        Some(format!(
            "The note must be at most {MAX_SIGNUP_NOTE} characters."
        ))
    } else if queries::count_pending_users(&st.db).await? >= MAX_PENDING_ACCOUNTS {
        Some("Too many requests are waiting for review. Please try again later.".to_string())
    } else {
        password_problem(&f.password, &f.password_confirm)
    };
    if let Some(error) = error {
        page.error = Some(error);
        return Ok((StatusCode::BAD_REQUEST, render(&page)?).into_response());
    }

    // Counted before the (expensive) hash, so a flood is throttled early.
    st.signup_limiter.record(client.ip);
    let hash = hash_password(&st, f.password).await?;
    let note = (!note.is_empty()).then_some(note.as_str());
    match queries::create_member(&st.db, &username, &hash, account::PENDING, note).await {
        Ok(_) => {
            tracing::info!(client = %log_ip(client.ip, st.config.security.log_ip_mode), "account requested");
            page.done = true;
            render(&page)
        }
        Err(e) if is_unique_violation(&e) => {
            page.error = Some("That username is already taken. Choose another.".into());
            Ok((StatusCode::BAD_REQUEST, render(&page)?).into_response())
        }
        Err(e) => Err(e.into()),
    }
}
