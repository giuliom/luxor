use luxor::server::{app, bind_address_from_env};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = bind_address_from_env();
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app()).await?;

    Ok(())
}