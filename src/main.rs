//! Hosted DNS server. Configuration comes from the environment; see `.env.example`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hosted_dns::{AppState, Config, MIGRATOR, Route53, reap, router};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

const REAP_EVERY: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&required("DATABASE_URL")?)
        .await?;
    MIGRATOR.run(&db).await?;
    let aws = aws_config::load_from_env().await;
    let zone = Route53::new(&aws, required("HOSTED_ZONE_ID")?);
    let config = Config {
        apex: required("APEX_DOMAIN")?,
        mints_per_hour: optional("MINTS_PER_HOUR")?.unwrap_or(30),
        client_ip_header: optional("CLIENT_IP_HEADER")?,
    };
    let state = Arc::new(AppState::new(db, zone, config));

    let reaper = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REAP_EVERY);
        loop {
            tick.tick().await;
            if let Err(error) = reap(&reaper).await {
                tracing::error!(%error, "reap failed");
            }
        }
    });

    let port: u16 = optional("PORT")?.unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("::", port)).await?;
    tracing::info!(port, "listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn required(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is not set"))
}

fn optional<T: std::str::FromStr>(key: &str) -> Result<Option<T>, String> {
    std::env::var(key)
        .ok()
        .map(|value| value.parse().map_err(|_| format!("{key} is invalid")))
        .transpose()
}
