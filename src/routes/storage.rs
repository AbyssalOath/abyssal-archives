//! /admin/storage: set up the optional Cloudflare R2 download origin
//! (src/r2.rs, docs/DOWNLOADS.md), test it, and watch the sync.

use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::audit;
use super::auth::AdminUser;
use crate::db::queries;
use crate::error::AppError;
use crate::r2::{self, R2Settings};
use crate::state::AppState;
use crate::util::human_size;
use crate::views::{Layout, render};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/storage", get(storage_page).post(storage_save))
        .route("/admin/storage/test", post(storage_test))
        .route("/admin/storage/sync", post(storage_sync))
        .route("/admin/storage/remove", post(storage_remove))
}

#[derive(Template)]
#[template(path = "admin/storage.html")]
struct StorageTemplate {
    l: Layout,
    /// The form (secret never included).
    account_id: String,
    bucket: String,
    access_key_id: String,
    public_url: String,
    jurisdiction: String,
    sync: bool,
    serve: bool,
    has_secret: bool,
    configured: bool,
    /// TOTP_ENCRYPTION_KEY is set (needed to store the secret).
    key_available: bool,
    published_files: usize,
    published_size: String,
    uploaded_files: usize,
    uploaded_size: String,
    failed_files: usize,
    running: bool,
    current: String,
    last_finished: String,
    last_result: String,
    failures: Vec<(String, String, String)>,
    test_steps: Vec<String>,
    test_error: Option<String>,
    flash: Option<&'static str>,
    error: Option<String>,
}

struct Extra {
    form: Option<R2Settings>,
    test_steps: Vec<String>,
    test_error: Option<String>,
    flash: Option<&'static str>,
    error: Option<String>,
}

async fn render_storage(st: &AppState, admin: &AdminUser, x: Extra) -> Result<Response, AppError> {
    let saved = st.r2();
    let form = x.form.unwrap_or_else(|| saved.clone());
    let wanted = queries::public_files_for_sync(&st.db).await?;
    let have = queries::r2_objects(&st.db).await?;
    let wanted_ids: std::collections::HashSet<i64> = wanted.iter().map(|w| w.id).collect();
    let uploaded: Vec<_> = have
        .iter()
        .filter(|o| o.status == "uploaded" && wanted_ids.contains(&o.file_id))
        .collect();
    let failures = queries::r2_failures(&st.db, 20)
        .await?
        .into_iter()
        .map(|(key, err, at)| (key, err, at.format("%Y-%m-%d %H:%M UTC").to_string()))
        .collect();
    let status = st.r2_status.lock().unwrap().clone();
    let mut l = st.layout("Download storage", Some(admin));
    if status.running {
        l.refresh = Some(10);
    }
    let code = if x.error.is_some() || x.test_error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = render(&StorageTemplate {
        l,
        has_secret: !saved.secret.is_empty(),
        configured: saved.complete(),
        key_available: st.config.security.totp_key.is_some(),
        published_files: wanted.len(),
        published_size: human_size(wanted.iter().map(|w| w.size_bytes as u64).sum()),
        uploaded_files: uploaded.len(),
        uploaded_size: human_size(uploaded.iter().map(|o| o.size_bytes as u64).sum()),
        failed_files: have.iter().filter(|o| o.status == "failed").count(),
        running: status.running,
        current: status.current.unwrap_or_default(),
        last_finished: status
            .last_finished
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_default(),
        last_result: status.last_result,
        failures,
        account_id: form.account_id,
        bucket: form.bucket,
        access_key_id: form.access_key_id,
        public_url: form.public_url,
        jurisdiction: form.jurisdiction,
        sync: form.sync,
        serve: form.serve,
        test_steps: x.test_steps,
        test_error: x.test_error,
        flash: x.flash,
        error: x.error,
    })?;
    Ok((code, page).into_response())
}

#[derive(Deserialize)]
struct MsgQuery {
    msg: Option<String>,
}

async fn storage_page(
    admin: AdminUser,
    State(st): State<AppState>,
    Query(q): Query<MsgQuery>,
) -> Result<Response, AppError> {
    let flash = match q.msg.as_deref() {
        Some("saved") => Some("Saved. The sync job starts within a minute (or use Sync now)."),
        Some("sync") => Some("Sync started. This page refreshes while it runs."),
        Some("removed") => Some(
            "R2 is off and its settings are removed. Objects already in the bucket stay there until you delete them in the Cloudflare dashboard.",
        ),
        _ => None,
    };
    let x = Extra {
        form: None,
        test_steps: Vec::new(),
        test_error: None,
        flash,
        error: None,
    };
    render_storage(&st, &admin, x).await
}

#[derive(Deserialize)]
struct StorageForm {
    csrf: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    access_key_id: String,
    /// Blank keeps the stored secret.
    #[serde(default)]
    secret: String,
    #[serde(default)]
    public_url: String,
    #[serde(default)]
    jurisdiction: String,
    sync: Option<String>,
    serve: Option<String>,
}

impl StorageForm {
    fn settings(&self, current: &R2Settings) -> R2Settings {
        let secret = self.secret.trim();
        R2Settings {
            account_id: self.account_id.trim().to_ascii_lowercase(),
            bucket: self.bucket.trim().to_string(),
            access_key_id: self.access_key_id.trim().to_string(),
            secret: if secret.is_empty() {
                current.secret.clone()
            } else {
                secret.to_string()
            },
            public_url: self.public_url.trim().trim_end_matches('/').to_string(),
            jurisdiction: self.jurisdiction.trim().to_string(),
            sync: self.sync.is_some(),
            serve: self.serve.is_some(),
        }
    }
}

async fn storage_save(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<StorageForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let new = f.settings(&st.r2());
    let error = match st.config.security.totp_key {
        None => Some(
            "TOTP_ENCRYPTION_KEY is not set in .env, so the secret cannot be stored safely. \
             Run ./install.sh (it adds the key) and restart the app."
                .to_string(),
        ),
        Some(_) => r2::validate(&new).err(),
    };
    if let Some(error) = error {
        let x = Extra {
            form: Some(new),
            test_steps: Vec::new(),
            test_error: None,
            flash: None,
            error: Some(error),
        };
        return render_storage(&st, &admin, x).await;
    }
    let key = st.config.security.totp_key.expect("checked above");
    r2::save(&st.db, &key, &new).await?;
    let detail = format!(
        "bucket {}, {}, uploads {}, serving {}",
        new.bucket,
        new.public_url,
        if new.sync { "on" } else { "off" },
        if new.serve { "on" } else { "off" }
    );
    st.set_r2(new);
    audit(
        &st,
        &admin,
        "r2-settings",
        "download storage",
        Some(&detail),
    )
    .await;
    Ok(Redirect::to("/admin/storage?msg=saved").into_response())
}

/// Tests the settings in the form (falling back to the stored secret)
/// without saving them.
async fn storage_test(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<StorageForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    let s = f.settings(&st.r2());
    let mut x = Extra {
        form: Some(s.clone()),
        test_steps: Vec::new(),
        test_error: None,
        flash: None,
        error: None,
    };
    if let Err(e) = r2::validate(&s).and_then(|()| {
        if s.complete() {
            Ok(())
        } else {
            Err("Fill in every field first.".into())
        }
    }) {
        x.error = Some(e);
        return render_storage(&st, &admin, x).await;
    }
    match r2::test_connection(&s).await {
        Ok(steps) => x.test_steps = steps,
        Err((steps, e)) => {
            x.test_steps = steps;
            x.test_error = Some(e);
        }
    }
    render_storage(&st, &admin, x).await
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

/// Runs the sync now, retrying failed uploads at once.
async fn storage_sync(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    st.r2_status.lock().unwrap().force = true;
    r2::wake(&st);
    Ok(Redirect::to("/admin/storage?msg=sync").into_response())
}

#[derive(Deserialize)]
struct RemoveForm {
    csrf: String,
    confirm: Option<String>,
}

/// Turns R2 off and forgets its settings (downloads are served from here
/// again at once). Objects in the bucket are left alone.
async fn storage_remove(
    admin: AdminUser,
    State(st): State<AppState>,
    Form(f): Form<RemoveForm>,
) -> Result<Response, AppError> {
    admin.verify_csrf(&f.csrf)?;
    if f.confirm.is_none() {
        return Err(AppError::BadRequest(
            "Tick the confirmation box to stop using R2.".into(),
        ));
    }
    let empty = R2Settings::default();
    let key = st.config.security.totp_key.unwrap_or([0; 32]);
    r2::save(&st.db, &key, &empty).await?;
    st.set_r2(empty);
    sqlx::query("DELETE FROM r2_objects")
        .execute(&st.db)
        .await?;
    audit(&st, &admin, "r2-remove", "download storage", None).await;
    Ok(Redirect::to("/admin/storage?msg=removed").into_response())
}
