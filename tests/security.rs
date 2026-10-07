//! Security regression tests against a real MariaDB (TEST_DATABASE_URL, wiped
//! first; skipped when unset). One sequential test, because each section
//! rebuilds the app with a different configuration on the same database.

mod common;

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Client, Resp, csrf_from, test_app};
use tower::ServiceExt;

const PW: &str = "correct horse battery";
const TOTP_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn peer(s: &str) -> Option<SocketAddr> {
    Some(SocketAddr::new(s.parse().unwrap(), 40000))
}

async fn setup_admin(c: &mut Client) {
    let page = c.get("/setup").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let pre = csrf_from(&page.text());
    let r = c
        .post_form(
            "/setup",
            &[
                ("csrf", &pre),
                ("username", "admin"),
                ("password", PW),
                ("password_confirm", PW),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

async fn login(c: &mut Client, user: &str, pw: &str) -> Resp {
    let page = c.get("/login").await;
    let pre = csrf_from(&page.text());
    c.post_form(
        "/login",
        &[("csrf", &pre), ("username", user), ("password", pw)],
    )
    .await
}

async fn admin_csrf(c: &mut Client) -> String {
    let page = c.get("/admin").await;
    assert_eq!(page.status, StatusCode::OK);
    csrf_from(&page.text())
}

fn assert_security_headers(r: &Resp, what: &str) {
    let h = &r.headers;
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    for part in [
        "default-src 'none'",
        "img-src 'self'",
        "font-src 'none'",
        "connect-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ] {
        assert!(csp.contains(part), "{what}: CSP lacks {part}");
    }
    assert!(
        !csp.contains("https:") && !csp.contains("data:"),
        "{what}: CSP too broad"
    );
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{what}");
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{what}");
    // Public pages: no-referrer. Pages with forms: same-origin, because under
    // no-referrer real browsers submit forms with `Origin: null` and no
    // Referer, which the Origin check (rightly) refuses.
    let expected = if filehost::guard::is_private_path(what) {
        "same-origin"
    } else {
        "no-referrer"
    };
    assert_eq!(h[header::REFERRER_POLICY], expected, "{what}");
    assert_eq!(h["cross-origin-opener-policy"], "same-origin", "{what}");
    assert_eq!(h["cross-origin-resource-policy"], "same-origin", "{what}");
    assert!(
        h["permissions-policy"]
            .to_str()
            .unwrap()
            .contains("camera=()"),
        "{what}"
    );
    assert!(!h.contains_key(header::SERVER), "{what}: Server header");
    assert!(
        !h.contains_key(header::STRICT_TRANSPORT_SECURITY),
        "{what}: HSTS is opt-in"
    );
}

#[tokio::test]
async fn security_suite() {
    if std::env::var("TEST_DATABASE_URL").is_err() {
        eprintln!("TEST_DATABASE_URL not set; skipping security tests");
        return;
    }
    defaults().await;
    login_rate_limit_and_spoofing().await;
    admin_surface_restrictions().await;
    totp_flow().await;
    secure_cookies_and_hsts().await;
}

/// Default configuration: headers, unauthenticated access, setup, session
/// fixation/rotation/expiry, CSRF + Origin, password change, XSS, hostile
/// names, Range abuse, import path checks, signatures, download limits.
async fn defaults() {
    let (app, db, dir) = test_app(&[
        ("SIGN_CHECKSUMS", "true".into()),
        ("DOWNLOAD_MAX_PER_IP", "1".into()),
        ("MAX_UPLOAD_BYTES", "65536".into()),
    ])
    .await
    .unwrap();
    let mut anon = Client::new(app.clone());

    // Security headers on every response type.
    for path in [
        "/",
        "/static/style.css",
        "/healthz",
        "/p/missing",
        "/download/99999",
        "/login",
        "/gpg.pub",
        "/setup",
        "/register",
    ] {
        let r = anon.get(path).await;
        assert_security_headers(&r, path);
    }
    assert_eq!(
        anon.get("/login").await.headers[header::CACHE_CONTROL],
        "no-store"
    );

    // /setup works once; afterwards it points at /register (requests to
    // join) and can never create an account again.
    let mut c = Client::new(app.clone());
    setup_admin(&mut c).await;
    let gone = anon.get("/setup").await;
    assert_eq!(gone.status, StatusCode::SEE_OTHER);
    assert_eq!(gone.location(), "/register");
    let r = anon
        .post_form(
            "/setup",
            &[
                ("csrf", "x"),
                ("username", "evil"),
                ("password", PW),
                ("password_confirm", PW),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(users, 1);

    // Every admin route refuses anonymous visitors.
    for path in [
        "/admin",
        "/admin/projects",
        "/admin/projects/1/edit",
        "/admin/projects/1/releases",
        "/admin/releases/1/edit",
        "/admin/releases/1/files",
        "/admin/files/1/mirrors",
        "/admin/settings",
        "/admin/password",
        "/admin/2fa",
    ] {
        let r = anon.get(path).await;
        assert!(
            r.status == StatusCode::SEE_OTHER && r.location() == "/login",
            "GET {path}: {}",
            r.status
        );
        assert_eq!(r.headers[header::CACHE_CONTROL], "no-store", "{path}");
    }
    for path in [
        "/admin/projects",
        "/admin/projects/1/edit",
        "/admin/projects/1/delete",
        "/admin/projects/1/releases",
        "/admin/releases/1/edit",
        "/admin/releases/1/delete",
        "/admin/releases/1/import",
        "/admin/releases/1/signature",
        "/admin/files/1/mirror",
        "/admin/files/1/mirrors",
        "/admin/files/1/rehash",
        "/admin/files/1/delete",
        "/admin/mirrors/1/verify",
        "/admin/settings",
        "/admin/integrity",
        "/admin/password",
        "/logout",
    ] {
        let r = anon.post_form(path, &[("csrf", "x")]).await;
        assert!(
            r.status == StatusCode::SEE_OTHER && r.location() == "/login",
            "POST {path}: {}",
            r.status
        );
    }

    // Session fixation: a cookie planted before login is never adopted.
    let mut victim = Client::new(app.clone());
    victim.cookies.insert("sid".into(), "a".repeat(64));
    assert_eq!(
        login(&mut victim, "admin", PW).await.status,
        StatusCode::SEE_OTHER
    );
    let sid1 = victim.cookies["sid"].clone();
    assert_ne!(sid1, "a".repeat(64));
    let mut attacker = Client::new(app.clone());
    attacker.cookies.insert("sid".into(), "a".repeat(64));
    assert_eq!(attacker.get("/admin").await.status, StatusCode::SEE_OTHER);
    // Rotation: logging in again replaces (and kills) the old session.
    assert_eq!(
        login(&mut victim, "admin", PW).await.status,
        StatusCode::SEE_OTHER
    );
    assert_ne!(victim.cookies["sid"], sid1);
    let mut old = Client::new(app.clone());
    old.cookies.insert("sid".into(), sid1);
    assert_eq!(
        old.get("/admin").await.status,
        StatusCode::SEE_OTHER,
        "old session dead"
    );

    // Idle and absolute expiry.
    let mut idle = Client::new(app.clone());
    login(&mut idle, "admin", PW).await;
    sqlx::query("UPDATE sessions SET last_seen_at = NOW() - INTERVAL 31 MINUTE")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        idle.get("/admin").await.status,
        StatusCode::SEE_OTHER,
        "idle timeout"
    );
    let mut abs = Client::new(app.clone());
    login(&mut abs, "admin", PW).await;
    sqlx::query("UPDATE sessions SET expires_at = NOW() - INTERVAL 1 SECOND")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        abs.get("/admin").await.status,
        StatusCode::SEE_OTHER,
        "absolute timeout"
    );

    // CSRF token AND Origin are both required.
    let mut a = Client::new(app.clone());
    login(&mut a, "admin", PW).await;
    let csrf = admin_csrf(&mut a).await;
    let r = a
        .post_form("/admin/projects", &[("csrf", "wrong"), ("name", "X")])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "bad CSRF token");
    for origin in [
        "https://evil.example",
        "null",
        "http://localhost.evil.example",
    ] {
        let req = Request::post("/admin/projects")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf={csrf}&name=X")))
            .unwrap();
        assert_eq!(
            a.send(req).await.status,
            StatusCode::FORBIDDEN,
            "Origin {origin}"
        );
    }
    a.no_origin = true;
    assert_eq!(
        a.post_form("/admin/projects", &[("csrf", &csrf), ("name", "X")])
            .await
            .status,
        StatusCode::FORBIDDEN,
        "no Origin, no Referer"
    );
    let req = Request::post("/admin/projects")
        .header(header::REFERER, "http://localhost/admin/projects")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={csrf}&name=Referer+OK&description_md=%3Cscript%3Ealert(1)%3C%2Fscript%3E%0A%0A![x](https://tracker.example/p.gif)%0A%0A[l](javascript:alert(1))")))
        .unwrap();
    assert_eq!(
        a.send(req).await.status,
        StatusCode::SEE_OTHER,
        "same-origin Referer accepted"
    );
    a.no_origin = false;

    // Stored XSS / remote images in Markdown.
    let page = anon.get("/p/referer-ok").await.text();
    assert!(!page.contains("<script"), "script");
    assert!(!page.contains("tracker.example/p.gif\""), "remote image");
    assert!(!page.contains("javascript:"), "javascript: link");
    assert!(page.contains("&lt;script&gt;"), "raw HTML shown as text");

    // Release + hostile filename upload + Range abuse + download limits.
    let r = a
        .post_form(
            "/admin/projects/1/releases",
            &[("csrf", &csrf), ("version", "1.0")],
        )
        .await;
    let files_url = r.location();
    let up = a
        .post_multipart(
            "/admin/releases/1/upload",
            &csrf,
            "evil\";x=1 näme.iso",
            b"payload",
        )
        .await;
    assert_eq!(up.status, StatusCode::SEE_OTHER, "{}", up.text());
    let file_id: i64 = sqlx::query_scalar("SELECT id FROM files")
        .fetch_one(&db)
        .await
        .unwrap();
    let dl = anon.get(&format!("/download/{file_id}")).await;
    let cd = dl.headers[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(
        cd.starts_with("attachment; filename=\"") && cd.contains("filename*=UTF-8''"),
        "{cd}"
    );
    assert_eq!(dl.headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(dl.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let multi = anon
        .get_with(
            &format!("/download/{file_id}"),
            "range",
            "bytes=0-0,1-1,2-2",
        )
        .await;
    assert_eq!(multi.status, StatusCode::RANGE_NOT_SATISFIABLE);
    // DOWNLOAD_MAX_PER_IP=1: a second download while the first streams.
    let held = app
        .clone()
        .oneshot(
            Request::get(format!("/download/{file_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(held.status(), StatusCode::OK);
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(held);
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::OK,
        "slot released"
    );

    // Import path checks: traversal, absolute, symlink and hard link out.
    let incoming = dir.path().join("incoming");
    let outside = dir.path().join("secret.txt");
    std::fs::write(&outside, b"secret").unwrap();
    std::os::unix::fs::symlink(&outside, incoming.join("link.iso")).unwrap();
    std::fs::hard_link(&outside, incoming.join("hard.iso")).unwrap();
    for bad in ["../secret.txt", "/etc/passwd", "link.iso", "hard.iso"] {
        let r = a
            .post_form(
                "/admin/releases/1/import",
                &[("csrf", &csrf), ("path", bad)],
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "import {bad}");
    }
    let imported: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(imported, 1, "nothing imported");

    // Signed checksums: only a signature for the current SHA256SUMS is served.
    let asc = "/p/referer-ok/1.0/SHA256SUMS.asc";
    assert_eq!(anon.get(asc).await.status, StatusCode::NOT_FOUND);
    let sig =
        "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEtest\n=abcd\n-----END PGP SIGNATURE-----";
    let bad = a
        .post_form(
            "/admin/releases/1/signature",
            &[("csrf", &csrf), ("signature", "not armor")],
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let ok = a
        .post_form(
            "/admin/releases/1/signature",
            &[("csrf", &csrf), ("signature", sig)],
        )
        .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    let served = anon.get(asc).await;
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.text().starts_with("-----BEGIN PGP SIGNATURE-----\n"));
    assert!(
        anon.get("/p/referer-ok")
            .await
            .text()
            .contains("SHA256SUMS.asc")
    );
    a.post_multipart("/admin/releases/1/upload", &csrf, "second.iso", b"more")
        .await;
    assert_eq!(
        anon.get(asc).await.status,
        StatusCode::NOT_FOUND,
        "stale signature not served"
    );
    assert!(a.get(&files_url).await.text().contains("older file set"));

    // Password change: needs the current password, ends other sessions.
    let mut other = Client::new(app.clone());
    login(&mut other, "admin", PW).await;
    let wrong = a
        .post_form(
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current", "nope"),
                ("new", "a brand new passphrase"),
                ("confirm", "a brand new passphrase"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let changed = a
        .post_form(
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current", PW),
                ("new", "a brand new passphrase"),
                ("confirm", "a brand new passphrase"),
            ],
        )
        .await;
    assert_eq!(changed.status, StatusCode::SEE_OTHER);
    assert_eq!(
        a.get("/admin").await.status,
        StatusCode::OK,
        "this browser keeps a fresh session"
    );
    assert_eq!(
        other.get("/admin").await.status,
        StatusCode::SEE_OTHER,
        "other sessions ended"
    );
    assert_eq!(
        login(&mut Client::new(app.clone()), "admin", PW)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(
            &mut Client::new(app.clone()),
            "admin",
            "a brand new passphrase"
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
}

/// Login backoff per IP and per username; X-Forwarded-For from untrusted
/// peers cannot be used to dodge it; the generic per-IP request limit.
async fn login_rate_limit_and_spoofing() {
    let (app, _db, _dir) = test_app(&[("RATE_LIMIT_PER_MINUTE", "40".into())])
        .await
        .unwrap();
    let mut c = Client::new(app.clone());
    setup_admin(&mut c).await;

    // Untrusted peer rotating fake X-Forwarded-For values.
    let mut attacker = Client::new(app.clone());
    attacker.peer = peer("203.0.113.5");
    let mut last = StatusCode::OK;
    for i in 0..7 {
        let page = attacker.get("/login").await;
        let pre = csrf_from(&page.text());
        let req = Request::post("/login")
            .header("x-forwarded-for", format!("198.51.100.{i}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "csrf={pre}&username=nosuchuser{i}&password=guess"
            )))
            .unwrap();
        last = attacker.send(req).await.status;
    }
    assert_eq!(
        last,
        StatusCode::TOO_MANY_REQUESTS,
        "spoofed XFF must not reset the per-IP limit"
    );

    // Distributed guessing against one username (different real IPs behind
    // a trusted proxy) is stopped by the per-username limit.
    for i in 0..6 {
        let mut proxied = Client::new(app.clone());
        proxied.peer = peer("172.18.0.2");
        let page = proxied.get("/login").await;
        let pre = csrf_from(&page.text());
        let req = Request::post("/login")
            .header("x-forwarded-for", format!("192.0.2.{}", 10 + i))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "csrf={pre}&username=admin&password=wrong"
            )))
            .unwrap();
        last = proxied.send(req).await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS, "per-username backoff");
    // Even the right password waits out the lockout.
    let mut fresh = Client::new(app.clone());
    fresh.peer = peer("192.0.2.200");
    assert_eq!(
        login(&mut fresh, "admin", PW).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Generic per-IP request limit (40/min), not bypassable via XFF.
    let mut flood = Client::new(app.clone());
    flood.peer = peer("203.0.113.77");
    let mut limited = false;
    for i in 0..60 {
        let req = Request::get("/")
            .header("x-forwarded-for", format!("10.9.8.{i}"))
            .body(Body::empty())
            .unwrap();
        let r = flood.send(req).await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(r.headers[header::RETRY_AFTER], "60");
            limited = true;
            break;
        }
    }
    assert!(limited, "request rate limit");
}

/// ADMIN_ALLOWED_CIDRS, ADMIN_HOST and SETUP_ENABLED=false. The allowlist
/// and host guard the /admin pages and the administrator's sign-in and
/// session; /login itself is open (members sign in from anywhere).
async fn admin_surface_restrictions() {
    let (app, _db, _dir) = test_app(&[
        ("ADMIN_ALLOWED_CIDRS", "10.0.0.0/8".into()),
        ("SETUP_ENABLED", "false".into()),
    ])
    .await
    .unwrap();
    let mut outsider = Client::new(app.clone());
    outsider.peer = peer("203.0.113.5");
    for path in ["/admin", "/admin/settings", "/admin/users", "/setup"] {
        assert_eq!(
            outsider.get(path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(outsider.get("/login").await.status, StatusCode::OK);
    assert_eq!(
        outsider.get("/").await.status,
        StatusCode::OK,
        "public pages unaffected"
    );
    let mut insider = Client::new(app.clone());
    insider.peer = peer("10.1.2.3");
    assert_eq!(insider.get("/login").await.status, StatusCode::OK);
    assert_eq!(
        insider.get("/setup").await.status,
        StatusCode::NOT_FOUND,
        "SETUP_ENABLED=false"
    );

    // The administrator, with the right password, from outside the list:
    // the same answer as a wrong password. From inside: signed in, and that
    // session is worthless from outside.
    let (app, _db, _dir) = test_app(&[("ADMIN_ALLOWED_CIDRS", "10.0.0.0/8".into())])
        .await
        .unwrap();
    let mut insider = Client::new(app.clone());
    insider.peer = peer("10.1.2.3");
    setup_admin(&mut insider).await;
    let mut outsider = Client::new(app.clone());
    outsider.peer = peer("203.0.113.5");
    let refused = login(&mut outsider, "admin", PW).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(refused.text().contains("Invalid username or password"));
    let wrong = login(&mut outsider, "admin", "wrong password here").await;
    assert_eq!(wrong.status, refused.status);
    let mut admin = Client::new(app.clone());
    admin.peer = peer("10.4.5.6");
    assert_eq!(login(&mut admin, "admin", PW).await.location(), "/admin");
    assert_eq!(admin.get("/admin").await.status, StatusCode::OK);
    admin.peer = peer("203.0.113.9");
    assert_eq!(admin.get("/admin").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        admin.get("/my/projects").await.status,
        StatusCode::NOT_FOUND
    );

    let (app, _db, _dir) = test_app(&[("ADMIN_HOST", "admin.example.com".into())])
        .await
        .unwrap();
    let mut c = Client::new(app.clone());
    let on_public = c
        .send(
            Request::get("/login")
                .header(header::HOST, "files.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    // Not hidden any more (members sign in anywhere); with no account yet
    // it sends the visitor to /setup, which only the admin host serves.
    assert_eq!(on_public.status, StatusCode::SEE_OTHER);
    let on_admin = c
        .send(
            Request::get("/setup")
                .header(header::HOST, "admin.example.com:443")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(on_admin.status, StatusCode::OK);
    let home = c
        .send(
            Request::get("/")
                .header(header::HOST, "files.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !home.text().contains("href=\"/admin\""),
        "public footer must not point at the admin host"
    );
    assert!(home.text().contains("href=\"/login\">Login</a>"));
}

/// TOTP: enrolment, login with second factor, replay, recovery codes, CLI reset.
async fn totp_flow() {
    let (app, db, _dir) = test_app(&[
        ("TOTP_ENABLED", "true".into()),
        ("TOTP_ENCRYPTION_KEY", TOTP_KEY.into()),
    ])
    .await
    .unwrap();
    let mut c = Client::new(app.clone());
    setup_admin(&mut c).await;
    let csrf = admin_csrf(&mut c).await;
    let page = c
        .post_form("/admin/2fa/setup", &[("csrf", &csrf), ("password", PW)])
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("<svg") && !page.text().contains("<script"));

    use base64::Engine;
    let key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(TOTP_KEY)
        .unwrap()
        .try_into()
        .unwrap();
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT totp_secret_enc FROM users")
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(
        !sealed.windows(4).any(|w| w == b"\0\0\0\0"),
        "stored encrypted"
    );
    let secret = filehost::totp::decrypt(&key, &sealed).unwrap();
    let code_at = |offset: i64| {
        let step = (chrono::Utc::now().timestamp() / 30 + offset) as u64;
        format!("{:06}", filehost::totp::hotp(&secret, step))
    };
    let confirm = c
        .post_form(
            "/admin/2fa/confirm",
            &[("csrf", &csrf), ("code", &code_at(-1))],
        )
        .await;
    assert_eq!(confirm.status, StatusCode::OK);
    let html = confirm.text();
    let codes: Vec<String> = html
        .match_indices("<li><code class=\"hash\">")
        .map(|(i, m)| html[i + m.len()..i + m.len() + 19].to_string())
        .collect();
    assert_eq!(codes.len(), 10);

    // Password alone now only reaches the second-factor page.
    let mut b = Client::new(app.clone());
    let r = login(&mut b, "admin", PW).await;
    assert_eq!(r.location(), "/login/2fa");
    assert_eq!(
        b.get("/admin").await.location(),
        "/login/2fa",
        "pending session cannot use admin"
    );
    let page = b.get("/login/2fa").await;
    let pending_csrf = csrf_from(&page.text());
    let wrong = b
        .post_form("/login/2fa", &[("csrf", &pending_csrf), ("code", "000000")])
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let replay = b
        .post_form(
            "/login/2fa",
            &[("csrf", &pending_csrf), ("code", &code_at(-1))],
        )
        .await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "code already used at enrolment"
    );
    let ok = b
        .post_form(
            "/login/2fa",
            &[("csrf", &pending_csrf), ("code", &code_at(0))],
        )
        .await;
    assert_eq!(ok.location(), "/admin");
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);

    // Recovery codes: single use.
    for (attempt, expected) in [(&codes[0], "/admin"), (&codes[0], "")] {
        let mut r = Client::new(app.clone());
        login(&mut r, "admin", PW).await;
        let p = r.get("/login/2fa").await;
        let pc = csrf_from(&p.text());
        let resp = r
            .post_form("/login/2fa", &[("csrf", &pc), ("code", attempt)])
            .await;
        if expected.is_empty() {
            assert_eq!(
                resp.status,
                StatusCode::UNAUTHORIZED,
                "recovery code reused"
            );
        } else {
            assert_eq!(resp.location(), expected);
        }
    }

    // CLI recovery: `filehost admin reset-2fa` turns 2FA off.
    assert_eq!(
        filehost::db::queries::reset_totp(&db, Some("admin"))
            .await
            .unwrap(),
        1
    );
    let mut d = Client::new(app.clone());
    assert_eq!(login(&mut d, "admin", PW).await.location(), "/admin");
    assert_eq!(
        b.get("/admin").await.status,
        StatusCode::SEE_OTHER,
        "reset ended existing sessions"
    );
}

/// COOKIE_SECURE: __Host- cookies with Secure/HttpOnly/SameSite=Strict;
/// HSTS only when enabled AND a trusted proxy reports HTTPS.
async fn secure_cookies_and_hsts() {
    let (app, _db, _dir) = test_app(&[
        ("COOKIE_SECURE", "true".into()),
        ("HSTS_ENABLED", "true".into()),
        ("PUBLIC_URL", "https://files.example.com".into()),
    ])
    .await
    .unwrap();
    let mut c = Client::new(app.clone());
    let setup = c.get("/setup").await;
    let set_cookie = setup.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("__Host-csrf_pre="), "{set_cookie}");
    for attr in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(set_cookie.contains(attr), "{attr} in {set_cookie}");
    }
    assert!(!set_cookie.contains("Domain="));

    let mut proxied = Client::new(app.clone());
    proxied.peer = peer("172.18.0.2");
    let r = proxied
        .send(
            Request::get("/")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        r.headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=31536000"
    );
    let r = proxied
        .send(Request::get("/").body(Body::empty()).unwrap())
        .await;
    assert!(
        !r.headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
        "plain HTTP"
    );
    let mut direct = Client::new(app.clone());
    direct.peer = peer("203.0.113.9");
    let r = direct
        .send(
            Request::get("/")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !r.headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
        "untrusted X-Forwarded-Proto"
    );
}
