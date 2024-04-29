use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
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
) -> (StatusCode, Html<String>) {
    info!("Serving directory {:?}", state.path);
    info!("Requested path {:?}", path);

    let p = std::path::Path::new(&state.path).join(path);

    if !p.exists() {
        (StatusCode::NOT_FOUND, Html("Not found".to_string()))
    } else {
        // Coursework 3 Directory

        // Check if the path is a directory
        // If it is, list all files/subdirectories in the directory
        // as <li><a href="/path/to/file">file</a></li>
        // return <html><body><ul>...</ul></body></html>
        if p.is_dir() {
            let mut content = String::new();
            content.push_str("<html><body><ul>");
            for entry in std::fs::read_dir(p).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let path = path.strip_prefix(&state.path).unwrap();
                let path = path.to_str().unwrap();
                content.push_str(&format!(r#"<li><a href="/{0}">{0}</a></li>"#, path));
            }
            content.push_str("</ul></body></html>");
            return (StatusCode::OK, Html(content));
        }
        match std::fs::read_to_string(p) {
            Ok(content) => (StatusCode::OK, Html(content)),
            Err(e) => {
                info!("Error reading file: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("Error reading file".to_string()),
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
        // test html content
        assert!(content.0.contains("name = \"rcli\""));
    }

    #[tokio::test]
    async fn test_file_handler_for_directory() {
        let state = HttpServeState {
            path: PathBuf::from("."),
        };
        let state = Arc::new(state);

        let (status, content) = file_handler(State(state.clone()), Path("src".to_string())).await;

        assert_eq!(status, StatusCode::OK);

        // Check that the HTML content lists the directory and file
        assert!(content
            .0
            .contains("<li><a href=\"/src/main.rs\">src/main.rs</a></li>"));
        assert!(content
            .0
            .contains("<li><a href=\"/src/process\">src/process</a></li>"));
    }
}
