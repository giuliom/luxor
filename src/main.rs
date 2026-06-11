use axum::{
    http::{header, HeaderValue},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // build our application with a route
    let app = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/script.js", get(script));

    // run it
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let address = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
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