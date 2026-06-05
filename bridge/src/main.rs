//! Gatewarden Bridge — language-agnostic HTTP sidecar for Gatewarden validation.
//!
//! Starts an HTTP server (default: 127.0.0.1:4760) that exposes Gatewarden
//! license validation via a simple JSON API, enabling TypeScript, Python,
//! Go, and any other language to use hardened Keygen validation without
//! reimplementing Ed25519 signature verification.
//!
//! # Usage
//!
//! ```bash
//! gatewarden-bridge bridge.toml
//! ```
//!
//! # Config format (bridge.toml)
//!
//! ```toml
//! port = 4760
//! bind = "127.0.0.1"   # loopback-only; never expose to the internet
//!
//! [profiles.myapp-pro]
//! account_id        = "your-keygen-account-uuid"
//! public_key_hex    = "64-hex-char-ed25519-verify-key-from-keygen-dashboard"
//! required_entitlements = ["PRO"]
//! offline_grace_secs    = 86400
//! ```

mod auth;
mod config;
mod routes;
mod state;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "gatewarden-bridge",
    about = "Language-agnostic HTTP bridge for Gatewarden license validation",
    version
)]
struct Cli {
    /// Path to bridge.toml config file
    #[arg(default_value = "bridge.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging (RUST_LOG=info by default)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();

    tracing::info!("Loading config from '{}'", cli.config);
    let bridge_config = config::BridgeConfig::load(&cli.config)?;
    let addr = bridge_config.listen_addr();

    tracing::info!(
        "Starting Gatewarden Bridge v{} with {} profile(s)",
        env!("CARGO_PKG_VERSION"),
        bridge_config.profiles.len()
    );

    let state = Arc::new(
        tokio::task::spawn_blocking(move || state::AppState::new(bridge_config))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize bridge state: {}", e))??,
    );

    // Log FSE plan stats for each profile
    for (profile_name, manager) in &state.managers {
        let plan = manager.fse_plan();
        tracing::info!(
            "Profile '{}': {} rules, {} unique selectors",
            profile_name,
            plan.rules.len(),
            plan.selectors.len()
        );
    }

    // Authenticated sub-router — bearer token + rate limit applied here.
    let authed_token = state.bearer_token.clone();
    let authed_state = state.clone();
    let authed = Router::new()
        .route("/v1/health", get(routes::health))
        .route("/v1/validate-key", post(routes::validate_key))
        .route("/v1/check-access", post(routes::check_access))
        .layer(middleware::from_fn(move |headers, req, next| {
            let token = authed_token.clone();
            auth::require_bearer_token(headers, token, req, next)
        }))
        .layer(middleware::from_fn_with_state(
            authed_state.clone(),
            routes::rate_limit_layer,
        ))
        .with_state(authed_state);

    let app = Router::new()
        .merge(authed)
        // OpenAPI spec is public (no secrets, just schema).
        .route("/.well-known/openapi.json", get(routes::openapi_spec));

    tracing::info!("Listening on http://{}", addr);

    // Spawn background task to prune stale rate-limiter buckets every 60 seconds.
    let prune_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            prune_state.rate_limiter.prune();
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("Cannot bind to {}: {}", addr, e))?;

    axum::serve(listener, app).await?;

    Ok(())
}
