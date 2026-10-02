//! The client layer: account, session keys, the orchestrator, the message stream, storage and
//! contacts — everything this program is, apart from how it is shown.
//!
//! Nothing here knows the terminal, the drawing library, the screens or `App`;
//! `boundary_tests` fails if it starts to. A front end calls the methods below and reads [`ClientEvent`]s from the channel it
//! handed over; the terminal UI is the first such front end, a desktop window the second
//! (`decisions/desktop-is-the-tui-client-with-a-second-shell.md`).

mod auth;
mod contacts;
mod identity;
mod inbound;
mod messages;
mod orchestrator;
mod tokens;

pub(crate) use auth::{AuthMsg, AuthOutcome};
pub(crate) use contacts::{FindStarted, SearchResult};

use tokio::sync::mpsc;

use crate::{
    auth::RegistrationStep,
    bridge::{BridgeEvent, TokenRefreshMsg},
    config::{Session, SessionKey, TransportConfig},
    grpc::GrpcClient,
};

/// Results of background work, delivered to the front end over one channel.
pub(crate) enum ClientEvent {
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    Bridge(BridgeEvent),
    /// Result of a FindUser search.
    ContactSearchResult(Vec<SearchResult>),
    /// A search or an invite redemption failed.
    ContactSearchError(String),
    /// An invite was redeemed — the front end confirms with [`Client::add_contact`].
    InviteAccepted {
        user_id: String,
        username: String,
    },
    /// A registration step completed.
    RegistrationStep(RegistrationStep),
    /// MessageStream got gRPC 16 — refresh the bearer, do not wipe keys.
    StreamAuthRequired,
}

/// Configuration derived from the config file and CLI overrides.
pub struct ClientConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub pq_active: bool,
}

pub(crate) struct Client {
    server_url: String,
    transport: TransportConfig,
    /// Skip at-rest encryption (headless / `--no-encrypt`).
    no_encrypt: bool,
    pq_active: bool,
    grpc: GrpcClient,
    events: mpsc::UnboundedSender<ClientEvent>,
    /// Derived key material for the active session (zeroized on drop / logout). `None` in
    /// `--no-encrypt` mode or before a passphrase is entered.
    session_key: Option<SessionKey>,
    /// The decrypted session in memory — re-saved on token refresh without a disk read.
    current_session: Option<Session>,
    /// A new session waiting for its passphrase before it is saved.
    pending_session: Option<Session>,
    user_id: String,
    device_id: String,
    access_token: String,
    /// Our identity public key, captured at orchestrator start; for safety numbers and export.
    our_identity_key: Option<Vec<u8>>,
    orch_handle: Option<crate::orchestrator_task::OrchestratorHandle>,
    stream_tx: Option<mpsc::Sender<crate::streaming::StreamCmd>>,
    /// Read connection for queries (messages, contacts); the orchestrator holds the writer.
    read_storage: Option<crate::storage::Storage>,
    /// The people the stream is subscribed for, in the order they were added.
    contact_ids: Vec<String>,
}

impl Client {
    pub(crate) fn new(cfg: ClientConfig, events: mpsc::UnboundedSender<ClientEvent>) -> Self {
        Self {
            grpc: GrpcClient::new(&cfg.server_url),
            server_url: cfg.server_url,
            transport: cfg.transport,
            no_encrypt: cfg.no_encrypt,
            pq_active: cfg.pq_active,
            events,
            session_key: None,
            current_session: None,
            pending_session: None,
            user_id: String::new(),
            device_id: String::new(),
            access_token: String::new(),
            our_identity_key: None,
            orch_handle: None,
            stream_tx: None,
            read_storage: None,
            contact_ids: Vec::new(),
        }
    }

    // ── Read-only state ─────────────────────────────────────────────────────────

    pub(crate) fn server_url(&self) -> &str {
        &self.server_url
    }
    pub(crate) fn transport_label(&self) -> &'static str {
        transport_label(&self.transport)
    }
    pub(crate) fn pq_active(&self) -> bool {
        self.pq_active
    }
    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }
    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }
    /// A passphrase has unlocked or created the session key.
    pub(crate) fn has_session_key(&self) -> bool {
        self.session_key.is_some()
    }
    pub(crate) fn signing_key_hex(&self) -> &str {
        self.current_session
            .as_ref()
            .map(|s| s.signing_key_hex.as_str())
            .unwrap_or("")
    }
}

pub(crate) fn transport_label(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Direct => "direct",
        TransportConfig::Obfs4 { .. } => "obfs4",
        TransportConfig::Obfs4Tls { .. } => "obfs4+tls",
        TransportConfig::CdnFront { .. } => "cdn-front",
    }
}

/// The client layer must not know how it is shown. A front-end type here would tie the desktop
/// shell to the terminal one, which is the coupling this module exists to remove.
#[cfg(test)]
mod boundary_tests {
    const SOURCES: &[(&str, &str)] = &[
        ("client/mod.rs", include_str!("mod.rs")),
        ("client/auth.rs", include_str!("auth.rs")),
        ("client/contacts.rs", include_str!("contacts.rs")),
        ("client/identity.rs", include_str!("identity.rs")),
        ("client/inbound.rs", include_str!("inbound.rs")),
        ("client/messages.rs", include_str!("messages.rs")),
        ("client/orchestrator.rs", include_str!("orchestrator.rs")),
        ("client/tokens.rs", include_str!("tokens.rs")),
    ];
    const FORBIDDEN: &[&str] = &[
        "ratatui",
        "crossterm",
        "crate::screens",
        "crate::app",
        "crate::tui",
    ];

    #[test]
    fn the_client_layer_imports_no_front_end() {
        for (file, source) in SOURCES {
            // Only code above the test modules counts — the list itself names the forbidden.
            let code = source.split("#[cfg(test)]").next().unwrap_or(source);
            for needle in FORBIDDEN {
                assert!(!code.contains(needle), "{file} mentions `{needle}`");
            }
        }
    }

    /// A file added to `client/` and not to `SOURCES` would sit outside the check above.
    #[test]
    fn every_client_file_is_checked() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/client");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".rs"))
            .map(|n| format!("client/{n}"))
            .collect();
        let mut listed: Vec<String> = SOURCES.iter().map(|(f, _)| f.to_string()).collect();
        on_disk.sort();
        listed.sort();
        assert_eq!(on_disk, listed, "add the new file to SOURCES");
    }
}
