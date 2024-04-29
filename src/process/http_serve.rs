use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use tower_http::services::ServeDir;
use tracing::info;

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    // axum router

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving directory {:?} on port {}", path, port);

    // create a state to pass to the handler
    let state = HttpServeState { path: path.clone() };

    let router = Router::new()
        .route("/*path", get(file_handler))
        .nest_service("/tower", ServeDir::new(path))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, router).await.unwrap();

    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    info!("Serving directory {:?}", state.path);
    info!("Requested path {:?}", path);

    let p = std::path::Path::new(&state.path).join(path);

    if !p.exists() {
        (StatusCode::NOT_FOUND, "Not found".to_string())
    } else {
        match std::fs::read_to_string(p) {
            Ok(content) => (StatusCode::OK, content),
            Err(e) => {
                info!("Error reading file: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error reading file".to_string(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = HttpServeState {
            path: PathBuf::from("."),
        };
        let state = Arc::new(state);

        let (status, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;

        assert_eq!(status, StatusCode::OK);
        assert!(content.contains("[package]\nname = \"rcli\"\nversion = \"0.1.0\""));
    }
}
