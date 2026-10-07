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

    // Colors only on a terminal, so `docker compose logs` stays plain text.
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("admin") {
        return admin_command(&args[1..]).await;
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
