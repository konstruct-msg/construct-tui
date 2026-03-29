mod app;
mod event;
mod tui;
mod screens;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let mut terminal = tui::init()?;
    let result = app::App::new().run(&mut terminal).await;
    tui::restore()?;
    result
}
