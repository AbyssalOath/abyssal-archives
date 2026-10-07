//! Member accounts against a real MariaDB (TEST_DATABASE_URL): registration
//! requests and approval, the member workspace and its isolation, review
//! before publishing, upload limits and quota, limit requests, disabling
//! and deleting accounts. Skipped when TEST_DATABASE_URL is unset.

mod common;

use axum::http::StatusCode;
use common::{Client, Resp, csrf_from, test_app};

const PW: &str = "correct horse battery staple";

async fn setup_admin(c: &mut Client) {
    let page = c.get("/setup").await;
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

async fn register(c: &mut Client, user: &str, note: &str) -> Resp {
    let page = c.get("/register").await;
    let pre = csrf_from(&page.text());
    c.post_form(
        "/register",
        &[
            ("csrf", &pre),
            ("username", user),
            ("password", PW),
            ("password_confirm", PW),
            ("note", note),
        ],
    )
    .await
}

async fn csrf_of(c: &mut Client, page: &str) -> String {
    let r = c.get(page).await;
    assert_eq!(r.status, StatusCode::OK, "{page}: {}", r.text());
    csrf_from(&r.text())
}

/// Saves settings with the member fields given (everything else default).
async fn settings(admin: &mut Client, extra: &[(&str, &str)]) {
    let csrf = csrf_of(admin, "/admin/settings").await;
    let mut fields = vec![("csrf", csrf.as_str()), ("site_name", "Members Test")];
    fields.extend_from_slice(extra);
    let r = admin.post_form("/admin/settings", &fields).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

async fn user_id(db: &sqlx::MySqlPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(name)
        .fetch_one(db)
        .await
        .unwrap()
}

/// Regular files under `dir`, recursively.
fn count_files(dir: &std::path::Path) -> usize {
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

/// Number after `prefix` in a Location header, e.g. ".../projects/7/releases".
fn id_in(location: &str, prefix: &str) -> i64 {
    let rest = &location[location.find(prefix).unwrap() + prefix.len()..];
    rest.split('/').next().unwrap().parse().unwrap()
}

#[tokio::test]
async fn members() {
    let Some((app, db, _dir)) = test_app(&[("MAX_UPLOAD_BYTES", "1M".into())]).await else {
        eprintln!("TEST_DATABASE_URL not set; skipping member tests");
        return;
    };
    let mut admin = Client::new(app.clone());
    setup_admin(&mut admin).await;
    let mut anon = Client::new(app.clone());

    // ---- footer, /setup and the closed /register page
    let home = anon.get("/").await.text();
    assert!(home.contains("<a href=\"/login\">Login</a>"));
    assert!(!home.contains(">Admin</a>"));
    assert_eq!(anon.get("/setup").await.location(), "/register");
    let closed = anon.get("/register").await.text();
    assert!(closed.contains("Requests to join are suspended"));
    assert!(closed.contains("contact the site administrator"));
    settings(&mut admin, &[("contact_email", "access@example.org")]).await;
    let closed = anon.get("/register").await.text();
    assert!(closed.contains("mailto:access@example.org"));
    assert!(
        !closed.contains("name=\"password\""),
        "no form while closed"
    );
    let r = anon
        .post_form(
            "/register",
            &[
                ("csrf", "x"),
                ("username", "sneaky"),
                ("password", PW),
                ("password_confirm", PW),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "POST refused while closed");
    let bad = anon.get("/admin/settings").await;
    assert_eq!(bad.status, StatusCode::SEE_OTHER);
    let scsrf = csrf_of(&mut admin, "/admin/settings").await;
    let r = admin
        .post_form(
            "/admin/settings",
            &[
                ("csrf", &scsrf),
                ("site_name", "Members Test"),
                ("contact_email", "not an address"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // ---- registration requests
    settings(
        &mut admin,
        &[
            ("registration_open", "1"),
            ("review_member_uploads", "1"),
            ("member_upload_limit", "64K"),
            ("member_storage_quota", "100K"),
        ],
    )
    .await;
    let r = register(&mut anon, "alice", "I make distro spins").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains("Request received"));
    let dup = register(&mut anon, "ALICE", "").await;
    assert_eq!(dup.status, StatusCode::BAD_REQUEST);
    assert!(
        dup.text().contains("already taken"),
        "case-insensitive names"
    );
    let dup = register(&mut anon, "admin", "").await;
    assert!(dup.text().contains("already taken"));
    let (status, note): (String, Option<String>) =
        sqlx::query_as("SELECT status, signup_note FROM users WHERE username = 'alice'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(status, "pending");
    assert_eq!(note.as_deref(), Some("I make distro spins"));

    // Pending: the right password learns why, a wrong one learns nothing.
    let mut alice = Client::new(app.clone());
    let r = login(&mut alice, "alice", PW).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.text().contains("awaiting approval"));
    assert!(!alice.cookies.contains_key("sid"));
    let r = login(&mut alice, "alice", "wrong password guess").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(!r.text().contains("awaiting"));

    let users = admin.get("/admin/users").await.text();
    assert!(users.contains("I make distro spins"));
    let alice_id = user_id(&db, "alice").await;
    let csrf = csrf_of(&mut admin, "/admin/users").await;
    let r = admin
        .post_form(
            &format!("/admin/users/{alice_id}/approve"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.location(), "/admin/users?msg=approve");

    // ---- the member workspace
    let r = login(&mut alice, "alice", PW).await;
    assert_eq!(r.location(), "/my");
    assert_eq!(alice.get("/my").await.location(), "/my/projects");
    assert_eq!(alice.get("/admin").await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        alice.get("/admin/users").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(admin.get("/my/projects").await.location(), "/admin");
    let page = alice.get("/my/projects").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("href=\"/my/limits\""));
    assert!(!page.text().contains("href=\"/admin"), "no admin links");
    let acsrf = csrf_from(&page.text());

    let r = alice
        .post_form(
            "/my/projects",
            &[
                ("csrf", &acsrf),
                ("name", "Alice Spin"),
                ("slug", "alice-spin"),
            ],
        )
        .await;
    let project_id = id_in(&r.location(), "/my/projects/");
    let r = alice
        .post_form(
            &format!("/my/projects/{project_id}/releases"),
            &[("csrf", &acsrf), ("version", "1.0")],
        )
        .await;
    let release_id = id_in(&r.location(), "/my/releases/");
    let files_url = format!("/my/releases/{release_id}/files");
    let r = alice
        .post_multipart(
            &format!("/my/releases/{release_id}/upload"),
            &acsrf,
            "spin.iso",
            &[7u8; 2048],
        )
        .await;
    assert_eq!(r.location(), format!("{files_url}?msg=uploaded"));
    let file_id: i64 = sqlx::query_scalar("SELECT id FROM files WHERE release_id = ?")
        .bind(release_id)
        .fetch_one(&db)
        .await
        .unwrap();
    let files = alice.get(&files_url).await.text();
    assert!(files.contains("awaiting review"));
    assert!(!files.contains("incoming folder"), "no import for members");
    assert!(!files.contains("Storage key"));
    assert!(files.contains(&format!("/my/files/{file_id}/download")));

    // Nothing of it is public before review.
    assert!(!anon.get("/").await.text().contains("Alice Spin"));
    for path in [
        "/p/alice-spin".to_string(),
        format!("/download/{file_id}"),
        format!("/download/{file_id}/sha256"),
        format!("/download/{file_id}/sha512"),
        "/p/alice-spin/1.0/SHA256SUMS".to_string(),
    ] {
        assert_eq!(
            anon.get(&path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // The owner and the admin can fetch it; nobody else.
    let own = alice.get(&format!("/my/files/{file_id}/download")).await;
    assert_eq!(own.status, StatusCode::OK);
    assert_eq!(own.body.len(), 2048);
    let r = admin.get(&format!("/admin/files/{file_id}/download")).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = anon.get(&format!("/my/files/{file_id}/download")).await;
    assert_eq!(r.location(), "/login");

    // ---- another member cannot see or touch it
    let mut bob = Client::new(app.clone());
    register(&mut bob, "bob", "").await;
    let bob_id = user_id(&db, "bob").await;
    let csrf = csrf_of(&mut admin, "/admin/users").await;
    admin
        .post_form(
            &format!("/admin/users/{bob_id}/approve"),
            &[("csrf", &csrf)],
        )
        .await;
    login(&mut bob, "bob", PW).await;
    let bcsrf = csrf_of(&mut bob, "/my/projects").await;
    assert!(!bob.get("/my/projects").await.text().contains("Alice Spin"));
    for path in [
        format!("/my/projects/{project_id}/releases"),
        format!("/my/projects/{project_id}/edit"),
        format!("/my/releases/{release_id}/files"),
        format!("/my/releases/{release_id}/edit"),
        format!("/my/files/{file_id}/download"),
    ] {
        assert_eq!(bob.get(&path).await.status, StatusCode::NOT_FOUND, "{path}");
    }
    let r = bob
        .post_form(
            &format!("/my/files/{file_id}/delete"),
            &[("csrf", &bcsrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = bob
        .post_multipart(
            &format!("/my/releases/{release_id}/upload"),
            &bcsrf,
            "evil.bin",
            b"x",
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = bob
        .post_form(
            &format!("/my/projects/{project_id}/delete"),
            &[("csrf", &bcsrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Admin-only actions are not reachable from the member area at all.
    let r = bob
        .post_form(
            &format!("/admin/projects/{project_id}/review"),
            &[("csrf", &bcsrf), ("decision", "approve")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // ---- review
    let queue = admin.get("/admin/review").await.text();
    assert!(queue.contains("Alice Spin"));
    let csrf = csrf_of(&mut admin, "/admin/review").await;
    let r = admin
        .post_form(
            &format!("/admin/releases/{release_id}/review"),
            &[("csrf", &csrf), ("decision", "approve")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::NOT_FOUND,
        "release approved, project still pending"
    );
    admin
        .post_form(
            &format!("/admin/projects/{project_id}/review"),
            &[("csrf", &csrf), ("decision", "approve")],
        )
        .await;
    let public = anon.get("/p/alice-spin").await;
    assert_eq!(public.status, StatusCode::OK);
    assert!(public.text().contains("spin.iso"));
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::OK
    );
    assert!(anon.get("/").await.text().contains("Alice Spin"));

    // A member's change goes back for review (and off the public site).
    let r = alice
        .post_form(
            &format!("/my/releases/{release_id}/edit"),
            &[
                ("csrf", &acsrf),
                ("version", "1.0"),
                ("notes_md", "now with more stuff"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        anon.get("/p/alice-spin").await.status,
        StatusCode::OK,
        "the project itself stays published"
    );
    // Rejected with a note the member sees.
    admin
        .post_form(
            &format!("/admin/releases/{release_id}/review"),
            &[
                ("csrf", &csrf),
                ("decision", "reject"),
                ("note", "Please add a README"),
            ],
        )
        .await;
    assert!(
        alice
            .get(&format!("/my/projects/{project_id}/releases"))
            .await
            .text()
            .contains("Please add a README")
    );
    // An admin's edit does not change the review state.
    admin
        .post_form(
            &format!("/admin/releases/{release_id}/edit"),
            &[("csrf", &csrf), ("version", "1.0"), ("notes_md", "x")],
        )
        .await;
    let status: String = sqlx::query_scalar("SELECT review_status FROM releases WHERE id = ?")
        .bind(release_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(status, "rejected");

    // ---- limits: per-file limit and quota are enforced while uploading
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files")
        .fetch_one(&db)
        .await
        .unwrap();
    let r = alice
        .post_multipart(
            &format!("/my/releases/{release_id}/upload"),
            &acsrf,
            "big.bin",
            &[1u8; 70 * 1024],
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        r.text().contains("upload limit of 64.0 KiB"),
        "{}",
        r.text()
    );
    let csrf = csrf_of(&mut admin, "/admin/users").await;
    admin
        .post_form(
            &format!("/admin/users/{alice_id}/limits"),
            &[
                ("csrf", &csrf),
                ("upload_limit", "512K"),
                ("storage_quota", ""),
            ],
        )
        .await;
    let r = alice
        .post_multipart(
            &format!("/my/releases/{release_id}/upload"),
            &acsrf,
            "big.bin",
            &[1u8; 120 * 1024],
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(r.text().contains("storage quota"), "{}", r.text());
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(before, after, "nothing stored for refused uploads");
    assert_eq!(
        count_files(&_dir.path().join("storage")),
        after as usize,
        "no leftover partial objects"
    );

    // ---- limit requests
    let lcsrf = csrf_of(&mut alice, "/my/limits").await;
    let r = alice
        .post_form(
            "/my/limits",
            &[
                ("csrf", &lcsrf),
                ("storage_quota", "10G"),
                ("reason", "short"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "reason too short");
    let r = alice
        .post_form(
            "/my/limits",
            &[
                ("csrf", &lcsrf),
                ("storage_quota", "10G"),
                ("reason", "I publish weekly ISO builds of my spin."),
            ],
        )
        .await;
    assert_eq!(r.location(), "/my/limits?msg=sent");
    let r = alice
        .post_form(
            "/my/limits",
            &[
                ("csrf", &lcsrf),
                ("storage_quota", "20G"),
                ("reason", "Another one while the first is pending."),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "one pending request");
    let users = admin.get("/admin/users").await.text();
    assert!(users.contains("I publish weekly ISO builds"));
    let req_id: i64 = sqlx::query_scalar("SELECT id FROM limit_requests WHERE user_id = ?")
        .bind(alice_id)
        .fetch_one(&db)
        .await
        .unwrap();
    let csrf = csrf_of(&mut admin, "/admin/users").await;
    let r = admin
        .post_form(
            &format!("/admin/limit-requests/{req_id}/approve"),
            &[
                ("csrf", &csrf),
                ("storage_quota", "5G"),
                ("note", "5G for now"),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin/users?msg=request-approve");
    let (limit, quota): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT upload_limit_bytes, storage_quota_bytes FROM users WHERE id = ?")
            .bind(alice_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(limit, Some(512 << 10), "limit untouched");
    assert_eq!(quota, Some(5 << 30), "granted value, not the requested one");
    let limits = alice.get("/my/limits").await.text();
    assert!(limits.contains("5G for now"));
    assert!(limits.contains("5.0 GiB"));
    let r = admin
        .post_form(
            &format!("/admin/limit-requests/{req_id}/deny"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "already decided");
    // Now it fits.
    let r = alice
        .post_multipart(
            &format!("/my/releases/{release_id}/upload"),
            &acsrf,
            "big.bin",
            &[1u8; 120 * 1024],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    // The member limit can never exceed MAX_UPLOAD_BYTES (1M here).
    admin
        .post_form(
            &format!("/admin/users/{alice_id}/limits"),
            &[
                ("csrf", &csrf),
                ("upload_limit", "10G"),
                ("storage_quota", ""),
            ],
        )
        .await;
    assert!(
        alice
            .get("/my/limits")
            .await
            .text()
            .contains("1.0 MiB</span> largest upload")
    );

    // ---- review off: members publish directly
    settings(
        &mut admin,
        &[("registration_open", "1"), ("contact_email", "")],
    )
    .await;
    let r = bob
        .post_form(
            "/my/projects",
            &[
                ("csrf", &bcsrf),
                ("name", "Bob Tools"),
                ("slug", "bob-tools"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(anon.get("/p/bob-tools").await.status, StatusCode::OK);
    // ...but an admin's "do not publish" stands through their edits.
    let bob_project = id_in(&r.location(), "/my/projects/");
    let csrf = csrf_of(&mut admin, "/admin/review").await;
    admin
        .post_form(
            &format!("/admin/projects/{bob_project}/review"),
            &[("csrf", &csrf), ("decision", "reject")],
        )
        .await;
    bob.post_form(
        &format!("/my/projects/{bob_project}/edit"),
        &[
            ("csrf", &bcsrf),
            ("name", "Bob Tools 2"),
            ("slug", "bob-tools"),
        ],
    )
    .await;
    assert_eq!(anon.get("/p/bob-tools").await.status, StatusCode::NOT_FOUND);

    // ---- disable, password reset, delete
    let csrf = csrf_of(&mut admin, "/admin/users").await;
    admin
        .post_form(
            &format!("/admin/users/{bob_id}/disable"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(
        bob.get("/my/projects").await.location(),
        "/login",
        "session ended"
    );
    let r = login(&mut bob, "bob", PW).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.text().contains("disabled"));
    admin
        .post_form(&format!("/admin/users/{bob_id}/enable"), &[("csrf", &csrf)])
        .await;
    let newpw = "another long password";
    admin
        .post_form(
            &format!("/admin/users/{bob_id}/password"),
            &[
                ("csrf", &csrf),
                ("password", newpw),
                ("password_confirm", newpw),
            ],
        )
        .await;
    assert_eq!(login(&mut bob, "bob", newpw).await.location(), "/my");
    // The admin account itself cannot be changed through these actions.
    let admin_id = user_id(&db, "admin").await;
    let r = admin
        .post_form(
            &format!("/admin/users/{admin_id}/disable"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let r = admin
        .post_form(
            &format!("/admin/users/{alice_id}/delete"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "confirmation required");
    let r = admin
        .post_form(
            &format!("/admin/users/{alice_id}/delete"),
            &[("csrf", &csrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.location(), "/admin/users?msg=delete");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE slug = 'alice-spin'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(alice.get("/my/projects").await.location(), "/login");

    // ---- admin-created accounts are active at once; rejecting a request
    let r = admin
        .post_form(
            "/admin/users",
            &[
                ("csrf", &csrf),
                ("username", "carol"),
                ("password", PW),
                ("password_confirm", PW),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin/users?msg=created");
    let mut carol = Client::new(app.clone());
    assert_eq!(login(&mut carol, "carol", PW).await.location(), "/my");
    register(&mut anon, "dave", "").await;
    let dave = user_id(&db, "dave").await;
    let r = admin
        .post_form(&format!("/admin/users/{dave}/reject"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.location(), "/admin/users?msg=reject");
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'dave'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(gone, 0);
    let carol_id = user_id(&db, "carol").await;
    let r = admin
        .post_form(
            &format!("/admin/users/{carol_id}/reject"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "only pending requests");

    // ---- registration requests are throttled per address
    let mut flood = Client::new(app.clone());
    flood.peer = Some("198.51.100.20:4000".parse().unwrap());
    let mut throttled = false;
    for i in 0..8 {
        let r = register(&mut flood, &format!("spam{i}"), "").await;
        if r.text().contains("Too many requests from your address") {
            throttled = true;
            break;
        }
        assert_eq!(r.status, StatusCode::OK);
    }
    assert!(throttled);
}
