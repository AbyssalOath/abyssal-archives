//! End-to-end test of the full router against a real MariaDB.
//!
//! Runs only when TEST_DATABASE_URL is set (CI provides a MariaDB service);
//! otherwise it prints a notice and passes. The database is wiped first, so
//! never point this at real data.
//!
//!   TEST_DATABASE_URL=mysql://root:pw@127.0.0.1:3306/filehost_test cargo test

mod common;

use std::collections::HashMap;
use std::time::Duration;

use axum::http::{StatusCode, header};
use common::{Client, csrf_from, reset_db};
use filehost::config::Config;
use filehost::state::AppState;
use sha2::{Digest, Sha256, Sha512};

#[tokio::test]
async fn full_flow() {
    let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping integration test");
        return;
    };
    reset_db(&db_url).await;

    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("storage");
    let incoming = dir.path().join("incoming");
    std::fs::create_dir_all(incoming.join("isos")).unwrap();
    let env: HashMap<&str, String> = HashMap::from([
        ("DATABASE_URL", db_url.clone()),
        ("SITE_NAME", "Test Site $HOME #1".into()),
        ("SITE_TAGLINE", "Files & more".into()),
        ("STORAGE_PATH", storage.display().to_string()),
        ("INCOMING_PATH", incoming.display().to_string()),
        ("IMPORT_MIN_AGE_SECS", "0".into()),
        ("MAX_UPLOAD_BYTES", "4096".into()),
        ("STORAGE_MIN_FREE_BYTES", "0".into()),
    ]);
    let config = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let state = AppState::init(config).await.unwrap();
    let db = state.db.clone();
    let mut c = Client::new(filehost::app(state));
    let mut pages = Vec::new();

    // Public basics.
    assert_eq!(c.get("/healthz").await.status, StatusCode::OK);
    let home = c.get("/").await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("Test Site $HOME #1"));
    assert!(
        home.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    pages.push(home.text());
    let css = c.get("/static/style.css").await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.text().contains("prefers-reduced-motion"));
    let missing = c.get("/p/nope").await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.text().contains("Test Site $HOME #1"), "themed 404");

    // First-run setup.
    let login = c.get("/login").await;
    assert_eq!(login.location(), "/setup");
    let setup = c.get("/setup").await;
    assert_eq!(setup.status, StatusCode::OK);
    let pre = csrf_from(&setup.text());
    let bad = c
        .post_form(
            "/setup",
            &[
                ("csrf", "x"),
                ("username", "admin"),
                ("password", "a"),
                ("password_confirm", "a"),
            ],
        )
        .await;
    assert_eq!(bad.status, StatusCode::FORBIDDEN);
    let short = c
        .post_form(
            "/setup",
            &[
                ("csrf", &pre),
                ("username", "admin"),
                ("password", "short"),
                ("password_confirm", "short"),
            ],
        )
        .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    let pw = "correct horse battery";
    let done = c
        .post_form(
            "/setup",
            &[
                ("csrf", &pre),
                ("username", "admin"),
                ("password", pw),
                ("password_confirm", pw),
            ],
        )
        .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert_eq!(done.location(), "/admin");
    assert!(c.cookies.contains_key("sid"));
    assert_eq!(c.get("/setup").await.location(), "/register");

    // Admin area.
    let dash = c.get("/admin").await;
    assert_eq!(dash.status, StatusCode::OK);
    let csrf = csrf_from(&dash.text());
    pages.push(dash.text());

    let forged = c
        .post_form("/admin/projects", &[("csrf", "nope"), ("name", "X")])
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let created = c
        .post_form(
            "/admin/projects",
            &[
                ("csrf", &csrf),
                ("name", "Cool Distro"),
                ("summary", "A distro"),
                ("description_md", "# Hello\n<script>x</script>"),
            ],
        )
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER);
    let releases_url = created.location();
    let dup = c
        .post_form(
            "/admin/projects",
            &[("csrf", &csrf), ("name", "Cool Distro")],
        )
        .await;
    assert_eq!(dup.status, StatusCode::BAD_REQUEST);
    assert!(dup.text().contains("already taken"));

    let rel = c
        .post_form(
            &releases_url,
            &[
                ("csrf", &csrf),
                ("version", "1.0"),
                ("released_at", "2026-01-02"),
                ("notes_md", "First!"),
            ],
        )
        .await;
    assert_eq!(rel.status, StatusCode::SEE_OTHER);
    let files_url = rel.location();
    let release_id: i64 = files_url.split('/').nth(3).unwrap().parse().unwrap();

    // Import from the incoming folder.
    let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(incoming.join("isos/cool distro.iso"), &content).unwrap();
    std::fs::write(incoming.join(".hidden.iso"), b"x").unwrap();
    std::fs::write(incoming.join("half.iso.part"), b"x").unwrap();
    let page = c.get(&files_url).await;
    assert!(page.text().contains("isos/cool distro.iso"));
    assert!(!page.text().contains(".hidden.iso"));
    assert!(!page.text().contains("half.iso.part"));
    pages.push(page.text());

    let import_url = format!("/admin/releases/{release_id}/import");
    for bad in ["../secret", "/etc/passwd", ".hidden.iso", "half.iso.part"] {
        let r = c
            .post_form(&import_url, &[("csrf", &csrf), ("path", bad)])
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let started = c
        .post_form(
            &import_url,
            &[("csrf", &csrf), ("path", "isos/cool distro.iso")],
        )
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    assert!(started.location().ends_with("msg=import-started"));

    let mut file_id = 0i64;
    for _ in 0..100 {
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT id, status FROM files WHERE release_id = ? AND filename = 'cool distro.iso'",
        )
        .bind(release_id)
        .fetch_optional(&db)
        .await
        .unwrap();
        if let Some((id, status)) = row {
            file_id = id;
            if status == "ready" {
                break;
            }
            assert_ne!(status, "failed");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sha = hex::encode(Sha256::digest(&content));
    let row: (String, i64, String) =
        sqlx::query_as("SELECT status, size_bytes, sha256 FROM files WHERE id = ?")
            .bind(file_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        row,
        ("ready".to_string(), content.len() as i64, sha.clone())
    );
    assert!(
        !incoming.join("isos/cool distro.iso").exists(),
        "moved out of incoming"
    );

    // Public project page (folders summarized), release page and download.
    let public = c.get("/p/cool-distro").await;
    assert_eq!(public.status, StatusCode::OK);
    assert!(public.text().contains(">isos/</a>"), "folder summary");
    pages.push(public.text());
    let release_page = c.get("/p/cool-distro/1.0").await;
    assert_eq!(release_page.status, StatusCode::OK);
    let html = release_page.text();
    assert!(html.contains("isos/cool distro.iso"));
    assert!(html.contains(&sha));
    assert!(html.contains("href=\"/p/cool-distro/1.0/isos/cool%20distro.iso\""));
    assert!(!html.contains("<script"), "markdown is sanitized");
    assert!(!html.contains("Mirror"));
    assert!(!html.contains("Torrent"));
    pages.push(html);

    let mut anon = Client::new(c.app.clone());
    let dl = anon.get(&format!("/download/{file_id}")).await;
    assert_eq!(dl.status, StatusCode::OK);
    assert_eq!(dl.body, content);
    assert_eq!(
        dl.headers[header::CONTENT_LENGTH],
        content.len().to_string().as_str()
    );
    assert_eq!(
        dl.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"cool distro.iso\"; filename*=UTF-8''cool%20distro.iso"
    );
    assert_eq!(dl.headers[header::ACCEPT_RANGES], "bytes");

    let part = anon
        .get_with(&format!("/download/{file_id}"), "range", "bytes=1000-")
        .await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.body, content[1000..]);
    assert_eq!(
        part.headers[header::CONTENT_RANGE],
        format!("bytes 1000-{}/{}", content.len() - 1, content.len()).as_str()
    );
    let tail = anon
        .get_with(&format!("/download/{file_id}"), "range", "bytes=-10")
        .await;
    assert_eq!(tail.body, content[content.len() - 10..]);
    let past = anon
        .get_with(&format!("/download/{file_id}"), "range", "bytes=99999999-")
        .await;
    assert_eq!(past.status, StatusCode::RANGE_NOT_SATISFIABLE);
    let count: i64 = sqlx::query_scalar("SELECT download_count FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 1, "resumed ranges are not counted");
    assert_eq!(
        anon.get(&format!("/download/{file_id}/torrent"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        anon.get("/download/999999").await.status,
        StatusCode::NOT_FOUND
    );

    // Imported bytes are stored unchanged (STRIP_METADATA unset).
    let key: String = sqlx::query_scalar("SELECT storage_key FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_one(&db)
        .await
        .unwrap();
    let stored = std::fs::read(storage.join(&key[..2]).join(&key)).unwrap();
    assert!(stored == content, "stored bytes differ from the original");
    let sha512 = hex::encode(Sha512::digest(&content));
    let db_sha512: Option<String> = sqlx::query_scalar("SELECT sha512 FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(db_sha512.as_deref(), Some(sha512.as_str()));

    // Checksum files. Add rows the app would not create itself: a legacy
    // file without SHA-512, a hostile filename, and non-ready files.
    for (name, status, s512) in [
        ("legacy.iso", "ready", None),
        ("evil\nffff  /etc/passwd", "ready", Some("e".repeat(128))),
        ("importing.iso", "importing", Some("c".repeat(128))),
        ("failed.iso", "failed", Some("c".repeat(128))),
        ("hashing.iso", "hashing", Some("c".repeat(128))),
    ] {
        sqlx::query(
            "INSERT INTO files (release_id, filename, path, size_bytes, sha256, sha512, storage_backend, storage_key, status) \
             VALUES (?, ?, ?, 1, ?, ?, 'local', UUID(), ?)",
        )
        .bind(release_id)
        .bind(name)
        .bind(name)
        .bind("d".repeat(64))
        .bind(s512)
        .bind(status)
        .execute(&db)
        .await
        .unwrap();
    }
    let sums = anon.get("/p/cool-distro/1.0/SHA256SUMS").await;
    assert_eq!(sums.status, StatusCode::OK);
    assert_eq!(
        sums.headers[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(sums.headers[header::CACHE_CONTROL], "no-cache");
    let d = "d".repeat(64);
    // Paths (folders kept), sorted.
    assert_eq!(
        sums.text(),
        format!("{d}  evil_ffff  /etc/passwd\n{sha}  isos/cool distro.iso\n{d}  legacy.iso\n")
    );
    let sums512 = anon.get("/p/cool-distro/1.0/SHA512SUMS").await.text();
    assert_eq!(
        sums512,
        format!(
            "{}  evil_ffff  /etc/passwd\n{sha512}  isos/cool distro.iso\n",
            "e".repeat(128)
        ),
        "legacy rows without SHA-512 are omitted"
    );
    let one = anon.get(&format!("/download/{file_id}/sha512")).await;
    assert_eq!(one.text(), format!("{sha512}  cool distro.iso\n"));
    assert_eq!(one.headers[header::CACHE_CONTROL], "no-cache");
    let one = anon.get(&format!("/download/{file_id}/sha256")).await;
    assert_eq!(one.text(), format!("{sha}  cool distro.iso\n"));
    assert_eq!(
        anon.get("/p/cool-distro/9.9/SHA256SUMS").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        anon.get("/p/cool-distro/1.0/SHA256SUMS.asc").await.status,
        StatusCode::NOT_FOUND
    );
    let public = c.get("/p/cool-distro/1.0").await.text();
    assert!(public.contains(&sha512));
    assert!(public.contains("href=\"/p/cool-distro/1.0/SHA256SUMS\""));
    assert!(public.contains("href=\"/p/cool-distro/1.0/SHA512SUMS\""));
    assert!(public.contains(&format!("href=\"/download/{file_id}/sha256\"")));
    assert!(public.contains("sha256sum -c SHA256SUMS"));
    assert!(public.contains("n/a"), "legacy file shows n/a for SHA-512");
    sqlx::query("DELETE FROM files WHERE release_id = ? AND filename <> 'cool distro.iso'")
        .bind(release_id)
        .execute(&db)
        .await
        .unwrap();

    // Recompute hashes backfills SHA-512 on an old row.
    sqlx::query("UPDATE files SET sha512 = NULL WHERE id = ?")
        .bind(file_id)
        .execute(&db)
        .await
        .unwrap();
    let rehash = c
        .post_form(
            &format!("/admin/files/{file_id}/rehash"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(rehash.status, StatusCode::SEE_OTHER);
    let mut row: (String, Option<String>) = Default::default();
    for _ in 0..100 {
        row = sqlx::query_as("SELECT status, sha512 FROM files WHERE id = ?")
            .bind(file_id)
            .fetch_one(&db)
            .await
            .unwrap();
        if row.0 != "hashing" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(row, ("ready".to_string(), Some(sha512.clone())));

    // Small web upload, and the size limit.
    let upload_url = format!("/admin/releases/{release_id}/upload");
    let up = c
        .post_multipart(&upload_url, &csrf, "../../notes.txt", b"hello upload")
        .await;
    assert_eq!(up.status, StatusCode::SEE_OTHER, "{}", up.text());
    let (up_id, up_sha): (i64, String) = sqlx::query_as(
        "SELECT id, sha256 FROM files WHERE filename = 'notes.txt' AND status = 'ready'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(up_sha, hex::encode(Sha256::digest(b"hello upload")));
    let up_sha512: Option<String> = sqlx::query_scalar("SELECT sha512 FROM files WHERE id = ?")
        .bind(up_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        up_sha512,
        Some(hex::encode(Sha512::digest(b"hello upload")))
    );
    assert_eq!(
        anon.get(&format!("/download/{up_id}")).await.body,
        b"hello upload"
    );

    // Recompute on a size mismatch marks the file failed.
    sqlx::query("UPDATE files SET size_bytes = 999 WHERE id = ?")
        .bind(up_id)
        .execute(&db)
        .await
        .unwrap();
    c.post_form(&format!("/admin/files/{up_id}/rehash"), &[("csrf", &csrf)])
        .await;
    let mut st = String::new();
    for _ in 0..100 {
        st = sqlx::query_scalar("SELECT status FROM files WHERE id = ?")
            .bind(up_id)
            .fetch_one(&db)
            .await
            .unwrap();
        if st != "hashing" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(st, "failed");
    let msg: Option<String> = sqlx::query_scalar("SELECT error_message FROM files WHERE id = ?")
        .bind(up_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(msg.unwrap().contains("size mismatch"));
    let big = c
        .post_multipart(&upload_url, &csrf, "big.bin", &[0u8; 10_000])
        .await;
    assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(big.text().contains("incoming folder"));
    let forged = c.post_multipart(&upload_url, "bad", "x.txt", b"x").await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    // Mirrors. The old single-mirror form still works as an alias.
    let legacy = format!("/admin/files/{file_id}/mirror");
    let bad = c
        .post_form(
            &legacy,
            &[("csrf", &csrf), ("mirror_url", "javascript:alert(1)")],
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let ok = c
        .post_form(
            &legacy,
            &[
                ("csrf", &csrf),
                ("mirror_url", "https://mirror.example.org/x.iso"),
            ],
        )
        .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    let mirrors_url = format!("/admin/files/{file_id}/mirrors");
    let torrent = c
        .post_form(
            &mirrors_url,
            &[
                ("csrf", &csrf),
                ("kind", "torrent"),
                (
                    "url",
                    "https://archive.org/download/cool-1.0/cool-1.0_archive.torrent",
                ),
                ("label", "Archive.org"),
            ],
        )
        .await;
    assert_eq!(torrent.status, StatusCode::SEE_OTHER);
    let bad_kind = c
        .post_form(
            &mirrors_url,
            &[
                ("csrf", &csrf),
                ("kind", "http"),
                ("url", "magnet:?xt=urn:btih:abc"),
            ],
        )
        .await;
    assert_eq!(bad_kind.status, StatusCode::BAD_REQUEST);
    // Rows that must never show publicly: pending (e.g. discovered) and failed.
    for (url, status, source) in [
        ("https://pending.example.org/x.iso", "pending", "discovered"),
        ("https://failed.example.org/x.iso", "failed", "admin"),
        ("https://rejected.example.org/x.iso", "rejected", "admin"),
    ] {
        sqlx::query("INSERT INTO file_mirrors (file_id, url, label, kind, status, source) VALUES (?, ?, 'x', 'http', ?, ?)")
            .bind(file_id)
            .bind(url)
            .bind(status)
            .bind(source)
            .execute(&db)
            .await
            .unwrap();
    }
    // Sharing off (default): no mirror links at all.
    let public = c.get("/p/cool-distro/1.0").await.text();
    assert!(!public.contains("mirror.example.org"));
    assert!(!public.contains("Torrent ("));
    // Turn on EXTERNAL_MIRRORS_ENABLED in settings.
    let on = c
        .post_form(
            "/admin/settings",
            &[
                ("csrf", &csrf),
                ("site_name", "Test Site $HOME #1"),
                ("site_tagline", "Files & more"),
                ("external_mirrors_enabled", "1"),
            ],
        )
        .await;
    assert_eq!(on.status, StatusCode::OK);
    let public = c.get("/p/cool-distro/1.0").await.text();
    assert!(public.contains(
        "href=\"https://mirror.example.org/x.iso\" rel=\"noopener noreferrer nofollow\">Mirror (mirror.example.org)</a>"
    ));
    assert!(public.contains(">Torrent (Archive.org)</a>"));
    for hidden in [
        "pending.example.org",
        "failed.example.org",
        "rejected.example.org",
    ] {
        assert!(!public.contains(hidden), "{hidden} must not be public");
    }
    // Quick add only builds URLs and asks for confirmation.
    let quick = c
        .post_form(
            &format!("{mirrors_url}/quick"),
            &[
                ("csrf", &csrf),
                ("source", "archive"),
                ("identifier", "cool-1.0"),
                ("filename", ""),
            ],
        )
        .await;
    assert_eq!(quick.status, StatusCode::OK);
    assert!(
        quick
            .text()
            .contains("https://archive.org/download/cool-1.0/cool%20distro.iso")
    );
    assert!(
        quick
            .text()
            .contains("https://archive.org/download/cool-1.0/cool-1.0_archive.torrent")
    );
    // Verify refuses internal addresses (and marks the mirror failed).
    let internal: i64 = sqlx::query_scalar(
        "INSERT INTO file_mirrors (file_id, url, label, kind, status, source) \
         VALUES (?, 'http://127.0.0.1/x.iso', 'local', 'http', 'approved', 'admin') RETURNING id",
    )
    .bind(file_id)
    .fetch_one(&db)
    .await
    .unwrap();
    let v = c
        .post_form(
            &format!("/admin/mirrors/{internal}/verify"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(v.status, StatusCode::SEE_OTHER);
    let mut row: (String, Option<String>) = Default::default();
    for _ in 0..100 {
        row = sqlx::query_as("SELECT status, last_error FROM file_mirrors WHERE id = ?")
            .bind(internal)
            .fetch_one(&db)
            .await
            .unwrap();
        if row.0 == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(row.0, "failed");
    assert!(row.1.unwrap().contains("internal address"));
    let t: i64 = sqlx::query_scalar("SELECT id FROM file_mirrors WHERE kind = 'torrent'")
        .fetch_one(&db)
        .await
        .unwrap();
    let tv = c
        .post_form(&format!("/admin/mirrors/{t}/verify"), &[("csrf", &csrf)])
        .await;
    assert_eq!(
        tv.status,
        StatusCode::BAD_REQUEST,
        "torrent mirrors are not verified"
    );
    // Reject hides a mirror again.
    let m: i64 = sqlx::query_scalar(
        "SELECT id FROM file_mirrors WHERE url = 'https://mirror.example.org/x.iso'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    c.post_form(&format!("/admin/mirrors/{m}/reject"), &[("csrf", &csrf)])
        .await;
    assert!(
        !c.get("/p/cool-distro/1.0")
            .await
            .text()
            .contains("mirror.example.org")
    );

    // Settings: site name and download base URL change everywhere.
    let bad = c
        .post_form(
            "/admin/settings",
            &[
                ("csrf", &csrf),
                ("site_name", "X"),
                ("download_base_url", "https://dl.example.com/path"),
            ],
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let saved = c
        .post_form(
            "/admin/settings",
            &[
                ("csrf", &csrf),
                ("site_name", "Renamed Site"),
                ("site_tagline", ""),
                ("footer_text", "Footer!"),
                ("download_base_url", "https://dl.example.com/"),
            ],
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let public = c.get("/p/cool-distro").await.text();
    assert!(public.contains("<title>Cool Distro · Renamed Site</title>"));
    assert!(public.contains("Footer!"));
    let release_page = c.get("/p/cool-distro/1.0").await.text();
    assert!(
        release_page
            .contains("href=\"https://dl.example.com/p/cool-distro/1.0/isos/cool%20distro.iso\"")
    );
    assert!(!public.contains("Test Site"));
    let override_set: Option<String> =
        sqlx::query_scalar("SELECT `value` FROM site_settings WHERE `key` = 'override.site_name'")
            .fetch_optional(&db)
            .await
            .unwrap();
    assert_eq!(override_set.as_deref(), Some("1"));

    // Deleting a file removes the stored object too.
    let del = c
        .post_form(
            &format!("/admin/files/{up_id}/delete"),
            &[("csrf", &csrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(del.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anon.get(&format!("/download/{up_id}")).await.status,
        StatusCode::NOT_FOUND
    );

    // No JavaScript anywhere.
    for p in &pages {
        assert!(
            !p.to_ascii_lowercase().contains("<script"),
            "page contains a script tag"
        );
    }

    // Logout ends the session.
    let out = c.post_form("/logout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    let after = c.get("/admin").await;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    assert_eq!(after.location(), "/login");
}
