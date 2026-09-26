use luxor::{app::App, bootstrap};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bootstrap::run(App).await
}
