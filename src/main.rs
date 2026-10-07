#![forbid(unsafe_code)]

use std::process::ExitCode;

use filehost::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return if filehost::healthcheck() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    // Commands print their own progress; only warnings are logged then.
    let default_filter = match std::env::args().nth(1).as_deref() {
        Some("import" | "admin") => "warn",
        _ => "info,sqlx=warn,tower_http=info",
    };
    // Colors only on a terminal, so `docker compose logs` stays plain text.
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("admin") {
        return admin_command(&args[1..]).await;
    }
    if args.first().map(String::as_str) == Some("import") {
        return import_command(&args[1..]).await;
    }

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match filehost::serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");
            ExitCode::FAILURE
        }
    }
}

/// Maintenance commands, run inside the app container, e.g.
/// `docker compose exec app /app/filehost admin reset-2fa`.
async fn admin_command(args: &[String]) -> ExitCode {
    let usage = "usage: filehost admin reset-2fa [username]\n  \
                 Turns off two-factor authentication (all admins, or one user), deletes the\n  \
                 TOTP secret and recovery codes, and signs those users out.";
    match args.first().map(String::as_str) {
        Some("reset-2fa") => {}
        _ => {
            eprintln!("{usage}");
            return ExitCode::FAILURE;
        }
    }
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let result = async {
        let db = filehost::db::connect_and_migrate(&config.database_url).await?;
        Ok::<u64, anyhow::Error>(
            filehost::db::queries::reset_totp(&db, args.get(1).map(String::as_str)).await?,
        )
    }
    .await;
    match result {
        Ok(0) => {
            eprintln!("No matching user.");
            ExitCode::FAILURE
        }
        Ok(n) => {
            println!("Two-factor authentication reset for {n} user(s); their sessions were ended.");
            println!("Sign in with the password only, then set up 2FA again at /admin/2fa.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("reset-2fa failed: {e}");
            ExitCode::FAILURE
        }
    }
}

const IMPORT_USAGE: &str = "usage: filehost import --release <project>/<version> [<folder>]\n  \
    Imports every file under <folder> of the incoming folder (default: all of it)\n  \
    into the release, one file at a time, keeping paths relative to the incoming\n  \
    folder (sources/a.tar.gz stays sources/a.tar.gz). Existing paths are never\n  \
    overwritten; files already imported with the same SHA-256 are skipped, so\n  \
    reruns are safe. <folder> is relative to INCOMING_PATH (an absolute path\n  \
    inside it works too). Exit status: 0 all imported or skipped, 1 some\n  \
    failed, 2 nothing done.\n  \
    e.g. docker compose exec app /app/filehost import --release abyssal-sanctum/v0.1.0 sources";

/// Parses `--release <project>/<version> [<folder>]`.
fn parse_import_args(args: &[String]) -> Result<(String, String, String), String> {
    let mut release = None;
    let mut folder = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" | "-r" => release = it.next().cloned(),
            s if s.starts_with("--release=") => release = Some(s["--release=".len()..].to_string()),
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s if folder.is_none() => folder = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    let release = release.ok_or("--release <project>/<version> is required")?;
    let (project, version) = release
        .split_once('/')
        .filter(|(p, v)| !p.is_empty() && !v.is_empty())
        .ok_or("--release must look like <project>/<version>")?;
    Ok((
        project.to_string(),
        version.to_string(),
        folder.unwrap_or_default(),
    ))
}

/// `filehost import`: the command-line "Import all" (docs/IMPORT.md). Runs
/// in the foreground and prints a line per file and a summary.
async fn import_command(args: &[String]) -> ExitCode {
    let (slug, version, folder) = match parse_import_args(args) {
        Ok(v) => v,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            eprintln!("{IMPORT_USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    // An absolute folder must be inside the incoming folder.
    let folder = match std::path::Path::new(&folder).strip_prefix(&config.incoming_path) {
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) if folder.starts_with('/') => {
            eprintln!(
                "{folder} is not inside the incoming folder ({}).",
                config.incoming_path.display()
            );
            return ExitCode::from(2);
        }
        Err(_) => folder,
    };
    let st = match filehost::state::AppState::init_for_command(config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let release = match filehost::db::queries::find_release(&st.db, &slug, &version).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!("No release {version} in project {slug}. Create it in the admin first.");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("database: {e}");
            return ExitCode::from(2);
        }
    };
    let selection = filehost::importer::Selection::Folder(folder);
    let batch = match filehost::importer::queue(&st, release.id, None, "cli", selection).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let batch_id = batch.batch_id;
    for (path, why) in &batch.refused {
        println!("REFUSED  {path}: {why}");
    }
    println!(
        "Import #{batch_id}: {} file(s) to import or check, {} refused.",
        batch.len(),
        batch.refused.len()
    );
    let (mut done, mut skipped, mut failed) = (0usize, 0usize, batch.refused.len());
    filehost::importer::run(st.clone(), batch, |r| {
        let tag = match r.status {
            "done" => {
                done += 1;
                "OK     "
            }
            "skipped" => {
                skipped += 1;
                "SKIPPED"
            }
            _ => {
                failed += 1;
                "FAILED "
            }
        };
        println!(
            "[{}/{}] {tag}  {} ({}): {}",
            r.index,
            r.total,
            r.path,
            filehost::util::human_size(r.size),
            r.message
        );
    })
    .await;
    println!(
        "Done: {done} imported, {skipped} skipped, {failed} failed. Details: /admin/imports/{batch_id}"
    );
    if failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
