//! Binary entry point -- see `src/lib.rs`'s crate doc for what this is and isn't.

use keycloak_it::{AppState, build_router};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bearer_token = std::env::var("SCIM_IT_BEARER_TOKEN")
        .expect("SCIM_IT_BEARER_TOKEN must be set -- this server refuses to guess a shared secret");
    let port: u16 = std::env::var("SCIM_IT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8087);

    let app = build_router(AppState::new(bearer_token));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("failed to bind 0.0.0.0:{port}: {e}"));
    tracing::info!("scim-it-server listening on 0.0.0.0:{port}");
    axum::serve(listener, app).await.expect("server error");
}
