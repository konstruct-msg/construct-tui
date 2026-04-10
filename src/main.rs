mod app;
mod auth;
mod bridge;
mod config;
mod event;
mod grpc;
mod screens;
mod storage;
mod streaming;
mod tui;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let mut terminal = tui::init()?;
    let result = app::App::new().run(&mut terminal).await;
    tui::restore()?;
    result
}
