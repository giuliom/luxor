use axum::{
    extract::Query,
    http::{header, HeaderValue},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::env;

pub fn app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/script.js", get(script))
        .route("/api/health", get(health))
        .route("/api/hello", get(hello))
        .route("/api/time", get(time))
}

pub fn bind_address_from_env() -> String {
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    format!("127.0.0.1:{port}")
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}

async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/css"))],
        include_str!("../public/styles.css"),
    )
}

async fn script() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/javascript"),
        )],
        include_str!("../public/script.js"),
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "luxor",
    })
}

async fn hello(Query(params): Query<HelloParams>) -> Json<HelloResponse> {
    let name = params
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("world");

    Json(HelloResponse {
        message: format!("Hello, {name}!"),
    })
}

async fn time() -> Json<TimeResponse> {
    Json(TimeResponse {
        server_time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Deserialize)]
struct HelloParams {
    name: Option<String>,
}

#[derive(Serialize)]
struct HelloResponse {
    message: String,
}

#[derive(Serialize)]
struct TimeResponse {
    server_time: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_index_html() {
        let response = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "text/html");
        assert!(body_text(response).await.contains("Hello, world!"));
    }

    #[tokio::test]
    async fn returns_health_json() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "application/json");
        assert_eq!(body_text(response).await, r#"{"status":"ok","service":"luxor"}"#);
    }

    #[tokio::test]
    async fn returns_named_hello_json() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/hello?name=Ada")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, r#"{"message":"Hello, Ada!"}"#);
    }

    #[tokio::test]
    async fn defaults_hello_name() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/hello")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, r#"{"message":"Hello, world!"}"#);
    }

    #[tokio::test]
    async fn returns_server_time_json() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/time")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "application/json");

        let body = body_text(response).await;
        assert!(body.starts_with(r#"{"server_time":""#));
        assert!(body.ends_with(r#"Z"}"#));
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn assert_header_starts_with(
        response: &axum::response::Response,
        header_name: &str,
        expected_prefix: &str,
    ) {
        let value = response
            .headers()
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        assert!(
            value.starts_with(expected_prefix),
            "expected {header_name} to start with {expected_prefix}, got {value}"
        );
    }
}