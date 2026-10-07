//! Database access: connection, embedded migrations, models and queries.
//! All queries are runtime-checked (`sqlx::query*`), so builds never need a
//! live database.

pub mod models;
pub mod queries;

use std::time::Duration;

use sqlx::MySqlPool;
use sqlx::mysql::MySqlPoolOptions;

/// Connects, retrying for up to ~60s while the database starts, then applies
/// the embedded migrations from ./migrations.
pub async fn connect_and_migrate(url: &str) -> anyhow::Result<MySqlPool> {
    let mut attempt = 0;
    let pool = loop {
        attempt += 1;
        match MySqlPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
        {
            Ok(pool) => break pool,
            Err(e) if attempt < 30 => {
                tracing::warn!(attempt, error = %e, "database not reachable yet, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(anyhow::anyhow!("could not connect to the database: {e}")),
        }
    };
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
