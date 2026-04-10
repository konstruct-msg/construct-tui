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
use clap::{Parser, Subcommand};

use app::{App, AppConfig};
use config::{TransportConfig, load_config};

#[derive(Parser)]
#[command(name = "construct-tui", about = "Construct — E2EE messenger for the terminal")]
struct Cli {
    /// Override the server URL from config (e.g. https://ams.konstruct.cc:443)
    #[arg(long)]
    server: Option<String>,

    /// obfs4 bridge line — enables ICE (obfs4) DPI-bypass transport.
    /// Format: "cert=BASE64 iat-mode=0" or full bridge string.
    #[arg(long)]
    bridge: Option<String>,

    /// SNI hostname for the outer TLS wrapper (requires --bridge).
    /// Use with a CDN SNI to defeat SNI-based blocking.
    #[arg(long)]
    bridge_tls_sni: Option<String>,

    /// Disable session encryption at-rest (for headless / systemd deployments).
    /// Has the same effect as the CONSTRUCT_NO_ENCRYPT environment variable.
    #[arg(long)]
    no_encrypt: bool,

    /// Run as a headless daemon — receive messages without a terminal UI.
    #[arg(long)]
    headless: bool,

    /// Path to a custom config file (default: ~/.config/construct-tui/config.json).
    #[arg(long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Delete the local session and all keys, then exit.
    Logout,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle the `logout` subcommand before touching the TUI.
    if let Some(Commands::Logout) = cli.command {
        config::clear_session()?;
        eprintln!("Session cleared. All local keys deleted.");
        return Ok(());
    }

    // Load persisted config and apply CLI overrides.
    let file_config = load_config().unwrap_or_default();

    let transport = if let Some(bridge_line) = cli.bridge {
        if let Some(sni) = cli.bridge_tls_sni {
            TransportConfig::Obfs4Tls { bridge_line, tls_server_name: sni }
        } else {
            TransportConfig::Obfs4 { bridge_line }
        }
    } else {
        file_config.transport.clone()
    };

    let server_url = cli.server.unwrap_or(file_config.server);
    let no_encrypt = cli.no_encrypt
        || std::env::var("CONSTRUCT_NO_ENCRYPT").is_ok();

    let cfg = AppConfig { server_url, transport, no_encrypt, headless: cli.headless };

    let mut terminal = tui::init()?;
    let result = App::new(cfg).run(&mut terminal).await;
    tui::restore()?;
    result
}
