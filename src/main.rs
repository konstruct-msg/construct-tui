mod app;
mod auth;
mod bridge;
mod config;
mod event;
mod grpc;
mod invite;
mod orchestrator_task;
mod screens;
mod storage;
mod streaming;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

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

    /// Log level: error, warn, info, debug, trace (default: info).
    /// Logs are written to ~/.local/share/construct-tui/konstrukt.log.
    /// Also respects the RUST_LOG environment variable.
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Delete the local session and all keys, then exit.
    Logout,
    /// Print the path to the log file and exit.
    LogPath,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23+ requires explicit CryptoProvider installation.
    // Install ring as the process-level provider before any TLS is used.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    let cli = Cli::parse();

    // Handle subcommands before touching the TUI.
    match cli.command {
        Some(Commands::Logout) => {
            config::clear_session()?;
            eprintln!("Session cleared. All local keys deleted.");
            return Ok(());
        }
        Some(Commands::LogPath) => {
            let path = log_file_path();
            println!("{}", path.display());
            return Ok(());
        }
        None => {}
    }

    // ── Logging ──────────────────────────────────────────────────────────────
    // TUI owns the terminal so we can't print to stderr — write to a log file.
    let log_path = log_file_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let level: LevelFilter = cli.log_level.parse().unwrap_or(LevelFilter::INFO);

    // RUST_LOG overrides --log-level when set
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(log_file)
        .with_ansi(false)
        .init();

    tracing::info!(
        log_file = %log_path.display(),
        version = env!("CARGO_PKG_VERSION"),
        "konstrukt starting"
    );

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
            tracing::info!("post-quantum mode: Kyber-768 PQXDH active");
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

    tracing::info!("konstrukt exiting");
    result
}

fn log_file_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("construct-tui")
        .join("konstrukt.log")
}
