//! Large-release features against a real MariaDB (TEST_DATABASE_URL):
//! folder paths in releases, duplicate refusal, bulk import (web and CLI)
//! with safe reruns, stable download URLs with Range, recommended file and
//! latest links, files.json, the free-space reserve, unpublishing, and
//! typed, logged deletion. Skipped when TEST_DATABASE_URL is unset.

mod common;

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Client, csrf_from, test_app};
use sha2::{Digest, Sha256};

const PW: &str = "correct horse battery staple";

async fn setup_admin(c: &mut Client) -> String {
    let page = c.get("/setup").await;
    let pre = csrf_from(&page.text());
    c.post_form(
        "/setup",
        &[
            ("csrf", &pre),
            ("username", "admin"),
            ("password", PW),
            ("password_confirm", PW),
        ],
    )
    .await;
    csrf_from(&c.get("/admin").await.text())
}

/// Creates project `slug` with release `version`; returns the release id.
async fn release(c: &mut Client, csrf: &str, slug: &str, version: &str) -> i64 {
    let r = c
        .post_form(
            "/admin/projects",
            &[("csrf", csrf), ("name", slug), ("slug", slug)],
        )
        .await;
    let releases_url = r.location();
    let r = c
        .post_form(
            &releases_url,
            &[
                ("csrf", csrf),
                ("version", version),
                ("notes_md", "## Changes\n\n| a | b |\n|---|---|\n| 1 | 2 |"),
            ],
        )
        .await;
    r.location().split('/').nth(3).unwrap().parse().unwrap()
}

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Waits for an import batch to finish; returns (done, skipped, failed).
async fn wait_batch(db: &sqlx::MySqlPool, batch: i64) -> (i64, i64, i64) {
    for _ in 0..1200 {
        let finished: Option<chrono::NaiveDateTime> =
            sqlx::query_scalar("SELECT finished_at FROM import_batches WHERE id = ?")
                .bind(batch)
                .fetch_one(db)
                .await
                .unwrap();
        if finished.is_some() {
            return sqlx::query_as(
                "SELECT CAST(SUM(status = 'done') AS SIGNED), CAST(SUM(status = 'skipped') AS SIGNED), \
                 CAST(SUM(status = 'failed') AS SIGNED) FROM import_items WHERE batch_id = ?",
            )
            .bind(batch)
            .fetch_one(db)
            .await
            .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("import batch {batch} did not finish");
}

/// POSTs "Import all" for `folder`; returns the batch id.
async fn import_all(c: &mut Client, csrf: &str, release_id: i64, folder: &str) -> i64 {
    let r = c
        .post_form(
            &format!("/admin/releases/{release_id}/import-all"),
            &[("csrf", csrf), ("folder", folder)],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    r.location()
        .strip_prefix("/admin/imports/")
        .unwrap()
        .parse()
        .unwrap()
}

/// One test: every part wipes and reuses the same database.
#[tokio::test]
async fn releases() {
    if std::env::var("TEST_DATABASE_URL").is_err() {
        eprintln!("TEST_DATABASE_URL not set; skipping release tests");
        return;
    }
    release_features().await;
    free_space_reserve().await;
    r2_settings_and_redirects().await;
}

const EXTRA: [(&str, &str); 1] = [("PUBLIC_URL", "https://files.example.com")];

async fn release_features() {
    let extra: Vec<(&str, String)> = EXTRA.iter().map(|(k, v)| (*k, v.to_string())).collect();
    let (app, db, dir) = test_app(&extra).await.unwrap();
    let incoming = dir.path().join("incoming");
    let mut c = Client::new(app.clone());
    let csrf = setup_admin(&mut c).await;
    let rid = release(&mut c, &csrf, "sanctum", "v0.1.0").await;
    let mut anon = Client::new(app.clone());

    // ---- folder paths are kept; sources/SHA256SUMS does not clash
    let iso: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    let tar_a = b"source a".repeat(100);
    let tar_extra = b"another a.tar.gz".to_vec();
    let sums = format!("{}  a.tar.gz\n", sha(&tar_a)).into_bytes();
    write(&incoming, "sanctum-v0.1.0.iso", &iso);
    write(&incoming, "sources/a.tar.gz", &tar_a);
    write(&incoming, "sources/SHA256SUMS", &sums);
    write(&incoming, "extra/deep/er/a.tar.gz", &tar_extra);
    let page = c.get(&format!("/admin/releases/{rid}/files")).await.text();
    assert!(page.contains("Import all (4 files)"));
    assert!(page.contains("Import all in sources/ (2)"));
    let batch = import_all(&mut c, &csrf, rid, "").await;
    assert_eq!(wait_batch(&db, batch).await, (4, 0, 0));
    let progress = c.get(&format!("/admin/imports/{batch}")).await.text();
    assert!(progress.contains("sources/a.tar.gz"));
    let mut paths: Vec<String> =
        sqlx::query_scalar("SELECT path FROM files WHERE release_id = ? ORDER BY path")
            .bind(rid)
            .fetch_all(&db)
            .await
            .unwrap();
    paths.sort();
    assert_eq!(
        paths,
        [
            "extra/deep/er/a.tar.gz",
            "sanctum-v0.1.0.iso",
            "sources/SHA256SUMS",
            "sources/a.tar.gz"
        ],
        "same file name in another folder is fine"
    );
    let sums_url = "/p/sanctum/v0.1.0/SHA256SUMS";
    let release_sums = anon.get(sums_url).await.text();
    assert_eq!(
        release_sums,
        format!(
            "{}  extra/deep/er/a.tar.gz\n{}  sanctum-v0.1.0.iso\n{}  sources/SHA256SUMS\n{}  sources/a.tar.gz\n",
            sha(&tar_extra),
            sha(&iso),
            sha(&sums),
            sha(&tar_a)
        )
    );
    let got = anon.get("/p/sanctum/v0.1.0/sources/SHA256SUMS").await;
    assert_eq!(got.body, sums, "the uploaded one, not the generated one");
    let got = anon.get("/p/sanctum/v0.1.0/sources/a.tar.gz").await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body, tar_a);
    assert_eq!(
        got.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        got.headers[header::CONTENT_LENGTH],
        tar_a.len().to_string().as_str()
    );
    assert_eq!(got.headers[header::ACCEPT_RANGES], "bytes");
    assert!(got.headers.get(header::SET_COOKIE).is_none());

    // ---- the release page: folders collapsed, notes rendered, hashes shown
    let page = anon.get("/p/sanctum/v0.1.0").await.text();
    assert!(page.contains("<details><summary><span class=\"folder-name\">sources/</span>"));
    assert!(!page.contains("<details open"), "collapsed by default");
    assert!(page.contains("<table>"), "Markdown tables in notes");
    assert!(page.contains(&sha(&tar_a)));
    assert!(
        page.contains("href=\"https://files.example.com/p/sanctum/v0.1.0/files.json\"")
            || page.contains("href=\"/p/sanctum/v0.1.0/files.json\"")
    );
    let main_pos = page.find("sanctum-v0.1.0.iso").unwrap();
    let folder_pos = page.find("folder-name\">extra/").unwrap();
    assert!(main_pos < folder_pos, "main downloads first");
    let project_page = anon.get("/p/sanctum").await.text();
    assert!(project_page.contains(">sources/</a>"));
    assert!(
        !project_page.contains("sources/a.tar.gz"),
        "folders summarized"
    );

    // ---- Range: curl -r 0-99
    let r = anon
        .send(
            Request::get("/p/sanctum/v0.1.0/sanctum-v0.1.0.iso")
                .header(header::RANGE, "bytes=0-99")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.body.len(), 100);
    assert_eq!(r.body, iso[..100]);
    assert_eq!(r.headers[header::CONTENT_LENGTH], "100");
    assert_eq!(
        r.headers[header::CONTENT_RANGE],
        format!("bytes 0-99/{}", iso.len()).as_str()
    );
    let head = anon
        .send(
            Request::head("/p/sanctum/v0.1.0/sanctum-v0.1.0.iso")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(
        head.headers[header::CONTENT_LENGTH],
        iso.len().to_string().as_str()
    );

    // ---- duplicates: refused (never overwritten); identical reruns skipped
    write(
        &incoming,
        "sources/a.tar.gz",
        b"different content, other size",
    );
    write(&incoming, "sources/SHA256SUMS", &sums);
    let batch = import_all(&mut c, &csrf, rid, "sources").await;
    assert_eq!(wait_batch(&db, batch).await, (0, 1, 1));
    let msg: String = sqlx::query_scalar(
        "SELECT message FROM import_items WHERE batch_id = ? AND status = 'failed'",
    )
    .bind(batch)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(msg.contains("sources/a.tar.gz already exists"), "{msg}");
    assert!(msg.contains("never overwritten"));
    assert_eq!(
        anon.get("/p/sanctum/v0.1.0/sources/a.tar.gz").await.body,
        tar_a,
        "original untouched"
    );
    assert!(
        incoming.join("sources/a.tar.gz").exists(),
        "refused file left in place"
    );
    assert!(
        !incoming.join("sources/SHA256SUMS").exists(),
        "skipped duplicate removed"
    );
    // Same size, different content: also refused (after hashing).
    let same_size: Vec<u8> = tar_a.iter().map(|b| b ^ 1).collect();
    write(&incoming, "sources/a.tar.gz", &same_size);
    let batch = import_all(&mut c, &csrf, rid, "sources").await;
    assert_eq!(wait_batch(&db, batch).await, (0, 0, 1));
    std::fs::remove_file(incoming.join("sources/a.tar.gz")).unwrap();
    // A generated root name cannot be imported.
    write(&incoming, "SHA256SUMS", b"x");
    let r = c
        .post_form(
            &format!("/admin/releases/{rid}/import"),
            &[("csrf", &csrf), ("path", "SHA256SUMS")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.text().contains("generated by the release itself"));
    std::fs::remove_file(incoming.join("SHA256SUMS")).unwrap();

    // ---- recommended file and latest links
    let iso_id: i64 = sqlx::query_scalar(
        "SELECT id FROM files WHERE release_id = ? AND path = 'sanctum-v0.1.0.iso'",
    )
    .bind(rid)
    .fetch_one(&db)
    .await
    .unwrap();
    let r = anon.get("/p/sanctum/latest/download").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "no recommended file yet");
    let r = c
        .post_form(
            &format!("/admin/files/{iso_id}/recommend"),
            &[("csrf", &csrf)],
        )
        .await;
    assert!(r.location().ends_with("msg=recommended"));
    let r = anon.get("/p/sanctum/latest").await;
    assert_eq!(r.location(), "/p/sanctum/v0.1.0");
    let r = anon.get("/p/sanctum/latest/download").await;
    assert_eq!(r.location(), "/p/sanctum/v0.1.0/sanctum-v0.1.0.iso");
    assert_eq!(
        anon.get(&r.location()).await.body,
        iso,
        "one hop to the file"
    );
    assert!(
        anon.get("/p/sanctum/v0.1.0")
            .await
            .text()
            .contains("Download the recommended file")
    );
    // A newer release becomes "latest"; "latest" itself is not a version.
    let r = c
        .post_form(
            &format!(
                "/admin/projects/{}/releases",
                project_id(&db, "sanctum").await
            ),
            &[("csrf", &csrf), ("version", "Latest")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // ---- files.json matches the files
    let r = anon.get("/p/sanctum/v0.1.0/files.json").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    let json: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(json["project"], "sanctum");
    assert_eq!(json["version"], "v0.1.0");
    assert_eq!(json["recommended"], "sanctum-v0.1.0.iso");
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 4);
    for (path, data) in [
        ("sanctum-v0.1.0.iso", iso.as_slice()),
        ("sources/a.tar.gz", tar_a.as_slice()),
        ("sources/SHA256SUMS", sums.as_slice()),
        ("extra/deep/er/a.tar.gz", tar_extra.as_slice()),
    ] {
        let f = files.iter().find(|f| f["path"] == path).unwrap();
        assert_eq!(f["sha256"], sha(data).as_str(), "{path}");
        assert_eq!(f["size"], data.len() as u64, "{path}");
        let url = f["url"].as_str().unwrap();
        assert!(url.starts_with("https://files.example.com/p/sanctum/v0.1.0/"));
        let local = url.strip_prefix("https://files.example.com").unwrap();
        assert_eq!(anon.get(local).await.body, data, "{path}");
    }

    // ---- bulk: 600 small files, then a rerun skips them all
    let bulk = |i: usize| format!("file {i}").into_bytes();
    for i in 0..600 {
        write(&incoming, &format!("bulk/f{i:03}.bin"), &bulk(i));
    }
    let batch = import_all(&mut c, &csrf, rid, "bulk").await;
    assert_eq!(wait_batch(&db, batch).await, (600, 0, 0));
    for i in 0..600 {
        write(&incoming, &format!("bulk/f{i:03}.bin"), &bulk(i));
    }
    let batch = import_all(&mut c, &csrf, rid, "bulk").await;
    assert_eq!(wait_batch(&db, batch).await, (0, 600, 0));
    assert_eq!(
        std::fs::read_dir(incoming.join("bulk")).unwrap().count(),
        0,
        "skipped duplicates removed from incoming"
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE release_id = ?")
        .bind(rid)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(n, 604);
    let r = anon.get("/p/sanctum/v0.1.0/bulk/f599.bin").await;
    assert_eq!(r.body, bulk(599));

    // ---- the command line: same pipeline, safe to rerun
    for i in 0..3 {
        write(&incoming, &format!("cli/c{i}.bin"), &bulk(1000 + i));
    }
    let run = |args: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_filehost"));
        cmd.arg("import").args(args).env_clear();
        for (k, v) in common::test_env(dir.path(), &extra) {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };
    let out = run(&["--release", "sanctum/v0.1.0", "cli"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("Done: 3 imported, 0 skipped, 0 failed"),
        "{text}"
    );
    assert!(text.contains("[3/3] OK"));
    for i in 0..3 {
        write(&incoming, &format!("cli/c{i}.bin"), &bulk(1000 + i));
    }
    let abs = incoming.join("cli").display().to_string();
    let out = run(&["--release=sanctum/v0.1.0", &abs]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("Done: 0 imported, 3 skipped, 0 failed"),
        "{text}"
    );
    let out = run(&["--release", "sanctum/v9.9", "cli"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        anon.get("/p/sanctum/v0.1.0/cli/c2.bin").await.body,
        bulk(1002)
    );

    // ---- unpublishing hides the release but keeps its files
    let r = c
        .post_form(
            &format!("/admin/releases/{rid}/review"),
            &[("csrf", &csrf), ("decision", "reject"), ("back", "files")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    for path in [
        "/p/sanctum/v0.1.0",
        "/p/sanctum/v0.1.0/sources/a.tar.gz",
        "/p/sanctum/v0.1.0/files.json",
        "/p/sanctum/latest",
    ] {
        assert_eq!(anon.get(path).await.status, StatusCode::NOT_FOUND, "{path}");
    }
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE release_id = ?")
        .bind(rid)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(kept, 607);
    c.post_form(
        &format!("/admin/releases/{rid}/review"),
        &[("csrf", &csrf), ("decision", "approve"), ("back", "files")],
    )
    .await;
    assert_eq!(
        anon.get("/p/sanctum/v0.1.0/sources/a.tar.gz").await.body,
        tar_a
    );

    // ---- deleting published things needs the typed name, and is logged
    let tar_id: i64 = sqlx::query_scalar(
        "SELECT id FROM files WHERE release_id = ? AND path = 'sources/a.tar.gz'",
    )
    .bind(rid)
    .fetch_one(&db)
    .await
    .unwrap();
    let del = format!("/admin/files/{tar_id}/delete");
    let r = c
        .post_form(&del, &[("csrf", &csrf), ("confirm", "yes")])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "checkbox is not enough");
    assert!(r.text().contains("type sources/a.tar.gz exactly"));
    let r = c
        .post_form(&del, &[("csrf", &csrf), ("typed", "sources/a.tar.gz")])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anon.get("/p/sanctum/v0.1.0/sources/a.tar.gz").await.status,
        StatusCode::NOT_FOUND
    );
    let r = c
        .post_form(
            &format!("/admin/releases/{rid}/delete"),
            &[("csrf", &csrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = c
        .post_form(
            &format!("/admin/releases/{rid}/delete"),
            &[("csrf", &csrf), ("typed", "v0.1.0")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let log = c.get("/admin/log").await.text();
    assert!(log.contains("delete-file"));
    assert!(log.contains("sanctum/v0.1.0/sources/a.tar.gz"));
    assert!(log.contains("delete-release"));
    assert!(log.contains("unpublish-release"));
    let stored = common::count_files(&dir.path().join("storage"));
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, rows as usize, "deleted objects are gone too");
}

async fn project_id(db: &sqlx::MySqlPool, slug: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM projects WHERE slug = ?")
        .bind(slug)
        .fetch_one(db)
        .await
        .unwrap()
}

/// The free-space reserve refuses a batch before anything is copied.
async fn free_space_reserve() {
    let (app, db, dir) = test_app(&[("STORAGE_MIN_FREE_BYTES", "1000T".into())])
        .await
        .unwrap();
    let incoming = dir.path().join("incoming");
    let mut c = Client::new(app);
    let csrf = setup_admin(&mut c).await;
    let rid = release(&mut c, &csrf, "big", "1").await;
    write(&incoming, "huge.iso", b"pretend this is 3 GB");
    let r = c
        .post_form(
            &format!("/admin/releases/{rid}/import-all"),
            &[("csrf", &csrf), ("folder", "")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.text().contains("Import refused before copying anything"));
    assert!(r.text().contains("STORAGE_MIN_FREE_BYTES"));
    let batches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_batches")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(batches, 0, "nothing recorded");
    assert!(incoming.join("huge.iso").exists());
}

/// The R2 admin page and the download redirect (no network: the sync job
/// only runs in the real server; uploads are simulated by a row).
async fn r2_settings_and_redirects() {
    let key = (
        "TOTP_ENCRYPTION_KEY",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string(),
    );
    let (app, db, _dir) = test_app(&[key]).await.unwrap();
    let mut c = Client::new(app.clone());
    let csrf = setup_admin(&mut c).await;
    let rid = release(&mut c, &csrf, "sanctum", "v1").await;
    let data = b"iso bytes".repeat(50);
    let r = c
        .post_multipart(
            &format!("/admin/releases/{rid}/upload"),
            &csrf,
            "s.iso",
            &data,
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let file_id: i64 = sqlx::query_scalar("SELECT id FROM files WHERE release_id = ?")
        .bind(rid)
        .fetch_one(&db)
        .await
        .unwrap();
    let mut anon = Client::new(app.clone());
    assert_eq!(anon.get("/admin/storage").await.location(), "/login");
    assert!(
        c.get("/admin/storage")
            .await
            .text()
            .contains("This server</strong> serves every download")
    );

    // Validation: https custom domain only; secret required.
    let r = save_r2(&mut c, &csrf, "s3cret-value", "http://dl.example.com", true).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = save_r2(&mut c, &csrf, "s3cret-value", "https://pub-1.r2.dev", true).await;
    assert!(r.text().contains("custom domain"));
    let r = save_r2(&mut c, &csrf, "", "https://dl.example.com", true).await;
    assert!(r.text().contains("secret access key"));
    // Saved: the secret is encrypted at rest and never shown again.
    let r = save_r2(
        &mut c,
        &csrf,
        "s3cret-value",
        "https://dl.example.com/",
        true,
    )
    .await;
    assert_eq!(r.location(), "/admin/storage?msg=saved");
    let sealed: String =
        sqlx::query_scalar("SELECT `value` FROM site_settings WHERE `key` = 'r2.secret_enc'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(!sealed.is_empty() && !sealed.contains("s3cret"));
    let page = c.get("/admin/storage").await.text();
    assert!(!page.contains("s3cret-value"));
    assert!(page.contains("leave blank to keep it"));
    assert!(page.contains("0 / 1</span> published files on R2"));

    // Not uploaded yet: served from here.
    let url = "/p/sanctum/v1/s.iso";
    assert_eq!(anon.get(url).await.body, data);
    // Uploaded: one redirect to the copy, never cached; counted from byte 0.
    sqlx::query("INSERT INTO r2_objects (file_id, object_key, size_bytes, status) VALUES (?, 'sanctum/v1/s.iso', ?, 'uploaded')")
        .bind(file_id)
        .bind(data.len() as i64)
        .execute(&db)
        .await
        .unwrap();
    let r = anon.get(url).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.location(), "https://dl.example.com/sanctum/v1/s.iso");
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        anon.get(&format!("/download/{file_id}")).await.location(),
        r.location()
    );
    c.post_form(
        &format!("/admin/files/{file_id}/recommend"),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(
        anon.get("/p/sanctum/latest/download").await.location(),
        "https://dl.example.com/sanctum/v1/s.iso",
        "straight to R2, no chain"
    );
    let counted: i64 = sqlx::query_scalar("SELECT download_count FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(counted, 3, "one local download, two redirects");
    // A failed upload is never redirected to.
    sqlx::query("UPDATE r2_objects SET status = 'failed'")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(anon.get(url).await.status, StatusCode::OK);
    sqlx::query("UPDATE r2_objects SET status = 'uploaded'")
        .execute(&db)
        .await
        .unwrap();
    // Unpublished: 404, never a redirect to the (soon deleted) copy.
    c.post_form(
        &format!("/admin/releases/{rid}/review"),
        &[("csrf", &csrf), ("decision", "reject")],
    )
    .await;
    assert_eq!(anon.get(url).await.status, StatusCode::NOT_FOUND);
    c.post_form(
        &format!("/admin/releases/{rid}/review"),
        &[("csrf", &csrf), ("decision", "approve")],
    )
    .await;
    // Serving off (secret left blank = kept): served from here again.
    let r = save_r2(&mut c, &csrf, "", "https://dl.example.com", false).await;
    assert_eq!(r.location(), "/admin/storage?msg=saved");
    assert_eq!(anon.get(url).await.status, StatusCode::OK);
    let still: String =
        sqlx::query_scalar("SELECT `value` FROM site_settings WHERE `key` = 'r2.secret_enc'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(!still.is_empty(), "blank secret keeps the stored one");
    // Stop using R2: needs the box; forgets everything.
    let r = c
        .post_form("/admin/storage/remove", &[("csrf", &csrf)])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = c
        .post_form(
            "/admin/storage/remove",
            &[("csrf", &csrf), ("confirm", "yes")],
        )
        .await;
    assert_eq!(r.location(), "/admin/storage?msg=removed");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM r2_objects")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    assert!(c.get("/admin/log").await.text().contains("r2-settings"));
}

/// Saves the R2 form (Sync on; Serve as given).
async fn save_r2(c: &mut Client, csrf: &str, secret: &str, url: &str, serve: bool) -> common::Resp {
    let mut fields = vec![
        ("csrf", csrf),
        ("account_id", "0123456789ABCDEF0123456789abcdef"),
        ("bucket", "abyssal-downloads"),
        ("access_key_id", "AKID123"),
        ("secret", secret),
        ("public_url", url),
        ("sync", "1"),
    ];
    if serve {
        fields.push(("serve", "1"));
    }
    c.post_form("/admin/storage", &fields).await
}
