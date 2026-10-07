//! Shared helpers for the database-backed tests (tests/integration.rs,
//! tests/security.rs).
#![allow(dead_code)]

use std::collections::HashMap;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use filehost::config::Config;
use filehost::state::AppState;
use tower::ServiceExt;

pub struct Client {
    pub app: Router,
    pub cookies: HashMap<String, String>,
    /// Send POSTs without an Origin header (CSRF tests).
    pub no_origin: bool,
    /// Socket peer to simulate (None = no ConnectInfo, i.e. loopback).
    pub peer: Option<std::net::SocketAddr>,
}

impl Client {
    pub fn new(app: Router) -> Self {
        Self {
            app,
            cookies: HashMap::new(),
            no_origin: false,
            peer: None,
        }
    }
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_string()
    }
}

impl Client {
    pub async fn send(&mut self, mut req: Request<Body>) -> Resp {
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie.is_empty() {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
        }
        // Behave like a browser on http://localhost: Host always, Origin on
        // POSTs (tests that need otherwise set the headers themselves).
        if !req.headers().contains_key(header::HOST) {
            req.headers_mut()
                .insert(header::HOST, "localhost".parse().unwrap());
        }
        if req.method() == axum::http::Method::POST
            && !req.headers().contains_key(header::ORIGIN)
            && !self.no_origin
        {
            req.headers_mut()
                .insert(header::ORIGIN, "http://localhost".parse().unwrap());
        }
        if let Some(peer) = self.peer {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
        }
        let resp = self.app.clone().oneshot(req).await.unwrap();
        for sc in resp.headers().get_all(header::SET_COOKIE) {
            let sc = sc.to_str().unwrap();
            let (pair, attrs) = sc.split_once(';').unwrap_or((sc, ""));
            let (k, v) = pair.split_once('=').unwrap();
            if v.is_empty() || attrs.contains("Max-Age=0") {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.to_string(), v.to_string());
            }
        }
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn get(&mut self, uri: &str) -> Resp {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    pub async fn get_with(&mut self, uri: &str, name: &str, value: &str) -> Resp {
        self.send(
            Request::get(uri)
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    pub async fn post_form(&mut self, uri: &str, fields: &[(&str, &str)]) -> Resp {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = Request::post(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }

    pub async fn post_multipart(
        &mut self,
        uri: &str,
        csrf: &str,
        filename: &str,
        data: &[u8],
    ) -> Resp {
        let boundary = "XtestBOUNDARYx";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let req = Request::post(uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }
}

pub fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Extracts the value of the first `name="csrf"` hidden input.
pub fn csrf_from(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("csrf field") + marker.len();
    html[start..start + 64].to_string()
}

pub async fn reset_db(url: &str) {
    let pool = sqlx::MySqlPool::connect(url)
        .await
        .expect("connect TEST_DATABASE_URL");
    sqlx::raw_sql(
        "SET FOREIGN_KEY_CHECKS = 0; \
         DROP TABLE IF EXISTS r2_objects, audit_log, import_items, import_batches, limit_requests, user_recovery_codes, file_mirrors, files, releases, projects, sessions, users, site_settings, _sqlx_migrations; \
         SET FOREIGN_KEY_CHECKS = 1;",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

/// The environment the test app runs with (also used to run the binary).
pub fn test_env(dir: &std::path::Path, extra: &[(&str, String)]) -> HashMap<String, String> {
    let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_default();
    let mut env: HashMap<String, String> = HashMap::from([
        ("DATABASE_URL".to_string(), db_url),
        ("SITE_NAME".to_string(), "Security Test".to_string()),
        (
            "STORAGE_PATH".to_string(),
            dir.join("storage").display().to_string(),
        ),
        (
            "INCOMING_PATH".to_string(),
            dir.join("incoming").display().to_string(),
        ),
        ("IMPORT_MIN_AGE_SECS".to_string(), "0".to_string()),
        ("STORAGE_MIN_FREE_BYTES".to_string(), "0".to_string()),
    ]);
    for (k, v) in extra {
        env.insert(k.to_string(), v.clone());
    }
    env
}

/// Regular files under `dir`, recursively.
pub fn count_files(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => count_files(&e.path()),
                    Ok(t) if t.is_file() => 1,
                    _ => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

/// Builds the app against TEST_DATABASE_URL (wiped first) with `env`
/// settings, or None (test skipped) when TEST_DATABASE_URL is unset.
pub async fn test_app(
    extra: &[(&str, String)],
) -> Option<(Router, sqlx::MySqlPool, tempfile::TempDir)> {
    let db_url = std::env::var("TEST_DATABASE_URL").ok()?;
    reset_db(&db_url).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("incoming")).unwrap();
    let env = test_env(dir.path(), extra);
    let config = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let state = AppState::init(config).await.unwrap();
    let db = state.db.clone();
    Some((filehost::app(state), db, dir))
}
