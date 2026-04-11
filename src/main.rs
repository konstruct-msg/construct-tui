mod app;
mod auth;
mod bridge;
mod config;
mod event;
mod grpc;
mod orchestrator_task;
mod screens;
mod storage;
mod streaming;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

use app::{App, AppConfig};
use config::{TransportConfig, load_config};

#[derive(Parser)]
#[command(
    name = "construct-tui",
    about = "Construct — E2EE messenger for the terminal"
)]
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

    /// Force post-quantum (Kyber-768 PQXDH) key agreement.
    ///
    /// This binary must be built with the 'post-quantum' feature to use this option.
    /// If not compiled in, the flag will print a rebuild hint and exit.
    ///
    /// To build a PQ-enabled binary:
    ///   cargo build --profile release-pq --features post-quantum
    #[arg(long)]
    post_quantum: bool,

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
    // rustls 0.23+ requires explicit CryptoProvider installation.
    // Install ring as the process-level provider before any TLS is used.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    let cli = Cli::parse();

    // Handle the `logout` subcommand before touching the TUI.
    if let Some(Commands::Logout) = cli.command {
        config::clear_session()?;
        eprintln!("Session cleared. All local keys deleted.");
        return Ok(());
    }

    // --post-quantum: verify the feature is compiled in; show a helpful error if not.
    if cli.post_quantum {
        #[cfg(not(feature = "post-quantum"))]
        {
            eprintln!(
                "error: this binary was not compiled with post-quantum support.\n\
                 \n\
                 To build a PQ-enabled binary, run:\n\
                 \n  cargo build --profile release-pq --features post-quantum\n\
                 \n\
                 RPi 3B+ and newer handle Kyber-768 handshake in ~2–3 s.\n\
                 RPi Zero W may take up to 60 s — this is expected."
            );
            std::process::exit(1);
        }
        #[cfg(feature = "post-quantum")]
        {
            eprintln!("Post-quantum (Kyber-768 PQXDH) is active.");
        }
    }

    // Load persisted config and apply CLI overrides.
    let file_config = load_config().unwrap_or_default();

    let transport = if let Some(bridge_line) = cli.bridge {
        if let Some(sni) = cli.bridge_tls_sni {
            TransportConfig::Obfs4Tls {
                bridge_line,
                tls_server_name: sni,
            }
        } else {
            TransportConfig::Obfs4 { bridge_line }
        }
    } else {
        file_config.transport.clone()
    };

    let server_url = cli.server.unwrap_or(file_config.server);
    let no_encrypt = cli.no_encrypt || std::env::var("CONSTRUCT_NO_ENCRYPT").is_ok();

    let cfg = AppConfig {
        server_url,
        transport,
        no_encrypt,
        headless: cli.headless,
        pq_active: cli.post_quantum,
    };

    let mut terminal = tui::init()?;
    let result = App::new(cfg).run(&mut terminal).await;
    tui::restore()?;
    result
}
