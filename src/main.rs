use luxor::{app::App, bootstrap};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    bootstrap::run(App).await
}
