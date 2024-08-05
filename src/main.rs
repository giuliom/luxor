use axum::{extract::Query, response::Html, routing::get, Router};
use serde::Deserialize;

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new().route("/", get(handler));

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct Parameters {
    name: String,
}

async fn handler(Query(args): Query<Parameters>) -> Html<String> {
    let name = args.name;
    Html(format!("<h1>Hello, {name}!</h1>"))
}