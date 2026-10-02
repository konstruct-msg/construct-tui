use anyhow::Result;
use base64::Engine as _;
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use prost::Message;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{
    auth::RegistrationStep,
    bridge::{BridgeEvent, TokenRefreshMsg},
    config::{self, Session, SessionKey, SessionState, TransportConfig},
    event::{Event, EventHandler, is_quit},
    grpc::GrpcClient,
    screens::onboarding::OnboardingField,
    screens::{
        ChatListPane, ChatViewPane, ConnectionState, ContactSearchScreen, DeviceLinkScreen,
        OnboardingScreen, RegistrationScreen, SafetyNumberScreen, SettingsAction, SettingsScreen,
        StatusBar, UnlockMode, UnlockScreen, chat_list::Contact, contact_search::SearchResult,
        qr_widget::QrWidget,
    },
    theme::ThemeMode,
    tui::Tui,
};

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    /// Checking for saved session on startup.
    Startup,
    /// Existing encrypted session found — enter passphrase to unlock.
    Unlock,
    /// New session created — choose a passphrase to protect it.
    SetPassphrase,
    /// Onboarding form (first run or after logout).
    Onboarding,
    /// Device link form — enter link token from another device.
    DeviceLink,
    /// Registration in progress — animated checklist.
    Registering,
    /// Auth request in flight — show spinner message.
    Connecting(String),
    /// Auth failed — show error, return to onboarding.
    AuthError(String),
    /// Authenticated — show main chat UI.
    Main,
    /// Settings (server, transport, device ID, logout, safety number…).
    Settings,
    /// Full-screen identity QR code (any key to dismiss).
    IdentityQr,
    /// Add-contact search overlay.
    ContactSearch,
    /// Safety number verification for the currently selected contact.
    SafetyNumber,
}

#[derive(Debug, Clone, PartialEq)]
enum Focus {
    ContactList,
    ChatView,
    Compose,
}

/// Messages sent from background auth tasks back to the UI event loop.
#[derive(Debug)]
pub(crate) enum AuthMsg {
    /// Authentication succeeded.
    Success(Box<AuthSuccess>),
    Failure(String),
}

#[derive(Debug)]
pub(crate) struct AuthSuccess {
    user_id: String,
    device_id: String,
    access_token: String,
    /// Full session including private keys — used to construct the Orchestrator.
    full_session: config::Session,
    /// When `Some`, this session must be persisted to disk (new/updated).
    pending_save: Option<config::Session>,
}

/// Unified internal event type — all background tasks funnel through this.
#[allow(dead_code)]
pub(crate) enum InternalEvent {
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    Bridge(BridgeEvent),
    /// Result of a gRPC FindUser search, delivered back to the UI.
    ContactSearchResult(Vec<SearchResult>),
    /// gRPC search failed.
    ContactSearchError(String),
    /// Invite link redeemed — add this person.
    InviteAccepted {
        user_id: String,
        username: String,
    },
    /// Registration step completed — advance the checklist.
    RegistrationStep(RegistrationStep),
    /// Periodic tick for spinner animation on the registration screen.
    Tick,
    /// MessageStream got gRPC 16 — refresh the bearer, do not wipe keys.
    StreamAuthRequired,
    /// P2P connection status update.
    P2PStatus {
        peer_id: String,
        connected: bool,
        latency_ms: Option<u32>,
        is_relay: bool,
    },
}

/// Type alias referenced by `orchestrator_task` to send bridge events back to the UI.
pub(crate) type InternalEventProxy = InternalEvent;

/// Configuration derived from config file + CLI overrides.
/// Passed to `App::new()` at startup.
pub struct AppConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    #[allow(dead_code)]
    pub headless: bool,
    pub pq_active: bool,
    pub theme: ThemeMode,
}

pub struct App {
    screen: Screen,
    onboarding: OnboardingScreen,
    device_link: DeviceLinkScreen,
    unlock_screen: UnlockScreen,
    registration: RegistrationScreen,
    /// Handle to the spinner ticker task — present only while Screen::Registering is active.
    ticker_handle: Option<tokio::task::AbortHandle>,
    /// Derived key material for the active session (zeroized on drop / logout).
    /// `None` in `--no-encrypt` mode or before the user has entered their passphrase.
    session_key: Option<SessionKey>,
    /// The fully decrypted session currently in memory — used for token refresh
    /// re-saves without requiring a disk re-read.
    current_session: Option<Session>,
    /// New session awaiting passphrase before being saved.
    pending_session: Option<Session>,
    /// When true: skip encryption (headless / --no-encrypt mode).
    no_encrypt: bool,
    focus: Focus,
    chat_list: ChatListPane,
    chat_view: ChatViewPane,
    status: String,
    running: bool,
    /// All background tasks send events through this unified channel.
    internal_tx: mpsc::UnboundedSender<InternalEvent>,
    internal_rx: mpsc::UnboundedReceiver<InternalEvent>,
    server_url: String,
    grpc: GrpcClient,
    transport: TransportConfig,
    /// Authenticated user ID (set after successful auth).
    user_id: String,
    /// Whether Kyber-768 PQXDH is active for this session.
    pq_active: bool,
    theme: ThemeMode,
    /// Live connection state shown in the status bar.
    connection: ConnectionState,
    settings_screen: SettingsScreen,
    contact_search: ContactSearchScreen,
    /// Safety number widget for the currently selected contact.
    safety_number: Option<SafetyNumberScreen>,
    /// Handle to the E2EE Orchestrator task (set after successful auth).
    orch_handle: Option<crate::orchestrator_task::OrchestratorHandle>,
    /// Command channel to the gRPC stream worker.
    stream_tx: Option<mpsc::Sender<crate::streaming::StreamCmd>>,
    /// Read-only storage connection for UI queries (messages, contacts).
    /// Separate connection from orchestrator's write connection.
    read_storage: Option<crate::storage::Storage>,
    /// Device ID of the authenticated device (set after successful auth).
    device_id: String,
    /// Bearer token for gRPC calls (set after successful auth, refreshed on token refresh).
    access_token: String,
    /// Our X3DH identity public key bytes — captured at orchestrator startup, used for
    /// safety number display and key export. None before first login.
    our_identity_key: Option<Vec<u8>>,
    /// When `Some`, a delete-confirmation dialog is shown for the given contact id.
    delete_confirm: Option<String>,
}

impl App {
    pub fn new(cfg: AppConfig) -> Self {
        let chat_list = ChatListPane::new();
        let initial_name = chat_list
            .selected_contact()
            .map(|c| c.display_name.clone())
            .unwrap_or_default();

        let (internal_tx, internal_rx) = mpsc::unbounded_channel();

        let settings_screen = SettingsScreen::new(
            &cfg.server_url,
            transport_label(&cfg.transport),
            "—",
            "—",
            cfg.pq_active,
            "",
        );

        Self {
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
            unlock_screen: UnlockScreen::new(UnlockMode::Unlock),
            registration: RegistrationScreen::new(),
            ticker_handle: None,
            session_key: None,
            current_session: None,
            pending_session: None,
            no_encrypt: cfg.no_encrypt,
            focus: Focus::ContactList,
            chat_list,
            chat_view: ChatViewPane::new(initial_name),
            status: "Ready".into(),
            running: true,
            internal_tx,
            internal_rx,
            server_url: cfg.server_url.clone(),
            grpc: GrpcClient::new(&cfg.server_url),
            transport: cfg.transport,
            user_id: String::new(),
            pq_active: cfg.pq_active,
            theme: cfg.theme,
            connection: ConnectionState::default(),
            settings_screen,
            contact_search: ContactSearchScreen::new(),
            safety_number: None,
            orch_handle: None,
            stream_tx: None,
            read_storage: None,
            device_id: String::new(),
            access_token: String::new(),
            our_identity_key: None,
            delete_confirm: None,
        }
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Detect session state and set initial screen / kick off auth.
        self.startup_check();

        let mut events = EventHandler::new();
        while self.running {
            terminal.draw(|frame| self.render(frame))?;

            // Block until either a keyboard event or an internal async event arrives.
            // No 100ms sleep — zero CPU when idle.
            tokio::select! {
                Some(event) = events.next() => self.handle_event(event),
                Some(internal) = self.internal_rx.recv() => self.handle_internal(internal),
            }
        }
        Ok(())
    }

    // ── Auth task management ────────────────────────────────────────────────────

    /// Detect session state on disk and set the initial screen accordingly.
    fn startup_check(&mut self) {
        match config::detect_session() {
            SessionState::Encrypted => {
                self.screen = Screen::Unlock;
            }
            SessionState::Plaintext => {
                self.start_auth_restore_from_disk();
            }
            SessionState::None => {
                self.screen = Screen::Onboarding;
            }
        }
    }

    /// Restore a plaintext session from disk (legacy / `--no-encrypt` path).
    fn start_auth_restore_from_disk(&mut self) {
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            match crate::auth::try_restore_session(&grpc).await {
                Ok(Some(result)) => {
                    let full = result
                        .session
                        .clone()
                        .expect("try_restore_session always returns session");
                    let msg = AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: None, // already saved inside try_restore_session
                    }));
                    let _ = tx.send(InternalEvent::Auth(msg));
                }
                Ok(None) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure("no_session".into())));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure(format!("{e:#}"))));
                }
            }
        });
        self.screen = Screen::Connecting("Restoring session…".into());
    }

    /// Authenticate using a session already decrypted in memory (after Unlock screen).
    fn start_auth_restore_preloaded(&mut self, session: Session) {
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();

        tokio::spawn(async move {
            match crate::auth::authenticate_saved_session(session.clone(), &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    let msg = AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }));
                    let _ = tx.send(InternalEvent::Auth(msg));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure(format!("{e:#}"))));
                }
            }
        });
        self.screen = Screen::Connecting("Authenticating…".into());
    }

    fn start_auth_register(&mut self, username: String) {
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        let name = if username.is_empty() {
            None
        } else {
            Some(username)
        };

        // Channel for step-progress events from register_new_device.
        let (step_tx, mut step_rx) = mpsc::unbounded_channel::<RegistrationStep>();

        // Forward RegistrationStep events to the main internal_tx so handle_internal sees them.
        let step_fwd_tx = tx.clone();
        tokio::spawn(async move {
            while let Some(s) = step_rx.recv().await {
                let _ = step_fwd_tx.send(InternalEvent::RegistrationStep(s));
            }
        });

        tokio::spawn(async move {
            match crate::auth::register_new_device(&grpc, name.as_deref(), &step_tx).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("register_new_device always returns session");
                    let msg = AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }));
                    let _ = tx.send(InternalEvent::Auth(msg));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure(format!("{e:#}"))));
                }
            }
        });

        // Reset the registration checklist and start the spinner ticker.
        self.registration = RegistrationScreen::new();
        self.start_ticker();
        self.screen = Screen::Registering;
    }

    /// Spawn a background task that sends `InternalEvent::Tick` every 80ms.
    /// Stores an AbortHandle so it can be cancelled when leaving Screen::Registering.
    fn start_ticker(&mut self) {
        self.stop_ticker();
        let tx = self.internal_tx.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
                if tx.send(InternalEvent::Tick).is_err() {
                    break;
                }
            }
        });
        self.ticker_handle = Some(handle.abort_handle());
    }

    fn stop_ticker(&mut self) {
        if let Some(h) = self.ticker_handle.take() {
            h.abort();
        }
    }

    fn start_auth_link(&mut self, token: String) {
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            match crate::auth::link_existing_device(&grpc, &token).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("link_existing_device always returns session");
                    let msg = AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }));
                    let _ = tx.send(InternalEvent::Auth(msg));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure(format!("{e:#}"))));
                }
            }
        });
        self.screen = Screen::Connecting("Confirming device link…".into());
    }

    /// Handle a message arriving from a background task via the unified internal channel.
    fn handle_internal(&mut self, event: InternalEvent) {
        match event {
            InternalEvent::Auth(msg) => {
                // Registration complete — stop spinner before transitioning.
                if matches!(self.screen, Screen::Registering) {
                    self.stop_ticker();
                    // Show all steps as done briefly before AuthMsg is processed.
                    self.registration.active_step = crate::screens::registration::STEPS.len();
                }
                self.handle_auth_msg(msg);
            }
            InternalEvent::TokenRefresh(msg) => self.handle_token_refresh_msg(msg),
            InternalEvent::Bridge(evt) => self.handle_bridge_event(evt),
            InternalEvent::ContactSearchResult(results) => {
                self.contact_search.set_results(results);
            }
            InternalEvent::ContactSearchError(msg) => {
                let shown = if msg.contains("rate limit") || msg.contains("8:") {
                    "Search limit (5/hour). Wait, then Enter once.".to_string()
                } else {
                    msg
                };
                self.contact_search.set_error(shown);
            }
            InternalEvent::InviteAccepted { user_id, username } => {
                self.finish_add_contact(user_id, username);
            }
            InternalEvent::RegistrationStep(step) => {
                self.registration.advance(step.index());
            }
            InternalEvent::Tick => {
                if matches!(self.screen, Screen::Registering) {
                    self.registration.tick();
                }
            }
            InternalEvent::StreamAuthRequired => self.refresh_token_now(),
            InternalEvent::P2PStatus {
                peer_id,
                connected,
                latency_ms,
                is_relay,
            } => {
                self.handle_p2p_status(peer_id, connected, latency_ms, is_relay);
            }
        }
    }

    /// Update message status UI (sent/delivered/read).
    #[allow(dead_code)]
    fn callback_on_message_status(&mut self, _local_id: &str, _status: u8) {
        // TODO: Implement message status UI updates
    }

    /// Handle a decrypted message (legacy UI path; orchestrator also stores).
    #[allow(dead_code)]
    fn handle_decrypted_message(
        &mut self,
        message_id: String,
        plaintext: Vec<u8>,
        sender_id: String,
        conversation_id: String,
    ) {
        use crate::screens::chat_view::{ChatMessage, MessageKind};

        let text = String::from_utf8_lossy(&plaintext).into_owned();
        let time = current_time_hhmm();

        // Add to chat view if it's the current conversation
        if self.chat_view.contact_name == conversation_id
            || self.chat_view.contact_name == sender_id
        {
            self.chat_view.messages.push(ChatMessage {
                id: message_id,
                kind: MessageKind::Received,
                text,
                time,
            });
            self.chat_view.on_new_message();
        }

        // Persistence is handled by orchestrator_task on MessageDecrypted.
    }

    fn handle_auth_msg(&mut self, msg: AuthMsg) {
        match msg {
            AuthMsg::Success(s) => {
                let AuthSuccess {
                    user_id,
                    device_id,
                    access_token,
                    full_session,
                    pending_save,
                } = *s;
                self.status = format!("Connected as {}", user_id);
                self.user_id = user_id.clone();
                self.device_id = device_id.clone();
                self.access_token = access_token.clone();
                self.grpc.set_token(Some(access_token.clone()));
                self.grpc.set_device_id(Some(device_id.clone()));
                self.connection = ConnectionState::Connected {
                    transport: transport_label(&self.transport).into(),
                    latency_ms: None,
                };
                self.settings_screen.update(
                    &self.server_url,
                    transport_label(&self.transport),
                    &device_id,
                    &user_id,
                    self.pq_active,
                    &full_session.signing_key_hex,
                );
                // Keep the decrypted session in memory for token-refresh re-saves.
                self.current_session = Some(full_session.clone());

                if let Some(session) = pending_save {
                    self.start_token_refresh(&session);

                    if let Some(ref sk) = self.session_key {
                        // Keys are already derived (unlock path or link/register with existing keys).
                        match config::save_session_encrypted(&session, sk) {
                            Ok(()) => {
                                self.start_orchestrator(
                                    full_session,
                                    user_id,
                                    device_id,
                                    access_token,
                                );
                                self.screen = Screen::Main;
                            }
                            Err(e) => self.screen = Screen::AuthError(format!("Save failed: {e}")),
                        }
                    } else if self.no_encrypt {
                        match config::save_session(&session) {
                            Ok(()) => {
                                self.start_orchestrator(
                                    full_session,
                                    user_id,
                                    device_id,
                                    access_token,
                                );
                                self.screen = Screen::Main;
                            }
                            Err(e) => self.screen = Screen::AuthError(format!("Save failed: {e}")),
                        }
                    } else {
                        // New registration — no passphrase yet.
                        // Wait for SetPassphrase before opening the encrypted database.
                        self.pending_session = Some(session);
                        self.unlock_screen.reset_for_mode(UnlockMode::SetNew);
                        self.screen = Screen::SetPassphrase;
                    }
                } else {
                    // Session was already saved (restore-from-disk path) — start right away.
                    self.start_orchestrator(full_session, user_id, device_id, access_token);
                    self.screen = Screen::Main;
                }
            }
            AuthMsg::Failure(msg) if msg == "no_session" => {
                self.stop_ticker();
                self.screen = Screen::Onboarding;
            }
            AuthMsg::Failure(msg) => {
                self.stop_ticker();
                // Auto-restore on startup (plaintext path): session_key is None because
                // no passphrase has been entered yet.  Show Onboarding so the user can
                // re-register — they likely just logged out or the session file is stale.
                //
                // Unlock path (user entered passphrase): session_key is Some because we
                // already decrypted the session.  The failure is a server/network error,
                // NOT a "no session" case.  Show AuthError so the user sees what went wrong
                // instead of silently landing on the onboarding screen.
                let is_auto_restore = matches!(self.screen, Screen::Connecting(_))
                    && self.session_key.is_none()
                    && self.onboarding.username.is_empty();
                if is_auto_restore {
                    self.screen = Screen::Onboarding;
                } else {
                    tracing::error!(error = %msg, "Authentication failed");
                    self.screen = Screen::AuthError(msg);
                }
            }
        }
    }

    /// Construct the Orchestrator, spawn the gRPC stream worker, and wire everything together.
    fn start_orchestrator(
        &mut self,
        session: config::Session,
        user_id: String,
        device_id: String,
        _access_token: String,
    ) {
        use crate::orchestrator_task::{StreamMessageContext, spawn_orchestrator_task};
        use crate::storage::Storage;
        use crate::streaming::{CursorTracker, StreamEvent, spawn_stream_worker};
        use construct_core::{
            crypto::{client_api::ClassicClient, suites::classic::ClassicSuiteProvider},
            orchestration::orchestrator::Orchestrator,
        };

        // Decode private keys from hex.
        let identity_secret = match hex::decode(&session.identity_key_hex) {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Orchestrator key decode error: {e}");
                return;
            }
        };
        let signing_secret = match hex::decode(&session.signing_key_hex) {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Orchestrator key decode error: {e}");
                return;
            }
        };
        let spk_secret = match hex::decode(&session.spk_key_hex) {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Orchestrator key decode error: {e}");
                return;
            }
        };
        let spk_sig = match hex::decode(&session.spk_sig_hex) {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Orchestrator key decode error: {e}");
                return;
            }
        };

        // The stream receive task must unseal SealedInner.sender_cert_ciphertext
        // before it can recover sender_user_id. Keep a private-key copy at that
        // boundary; Double Ratchet decryption still happens inside the orchestrator.
        let identity_secret_for_sealed = identity_secret.clone();

        // Construct the ClassicClient.
        let client = match ClassicClient::<ClassicSuiteProvider>::from_keys(
            identity_secret,
            signing_secret,
            spk_secret,
            spk_sig,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.status = format!("Orchestrator init error: {e}");
                return;
            }
        };

        let mut orchestrator = Orchestrator::new(client, user_id.clone());

        // ── Open storage (two connections: orchestrator writes, UI reads) ─────
        let (storage, read_storage) = if let Some(ref sk) = self.session_key {
            let db_key = sk.keys.database.as_ref();
            match (Storage::open(db_key), Storage::open(db_key)) {
                (Ok(s1), Ok(s2)) => (s1, s2),
                (Err(e), _) | (_, Err(e)) => {
                    self.status = format!("Storage open error: {e}");
                    return;
                }
            }
        } else {
            match (Storage::open_unencrypted(), Storage::open_unencrypted()) {
                (Ok(s1), Ok(s2)) => (s1, s2),
                (Err(e), _) | (_, Err(e)) => {
                    self.status = format!("Storage open error: {e}");
                    return;
                }
            }
        };

        // ── Load contacts from DB, populate chat list, collect IDs for stream ─
        let contact_ids: Vec<String> = match read_storage.get_contacts() {
            Ok(stored) => {
                let contacts: Vec<_> = stored
                    .iter()
                    .map(|c| crate::screens::chat_list::Contact {
                        id: c.user_id.clone(),
                        display_name: c.display_name.clone(),
                        unread: 0,
                        last_message: None,
                    })
                    .collect();
                let ids: Vec<String> = stored.into_iter().map(|c| c.user_id).collect();
                self.chat_list.set_contacts(contacts);
                ids
            }
            Err(e) => {
                tracing::warn!("Failed to load contacts: {e}");
                Vec::new()
            }
        };

        // Restore core coordination state and per-contact DR material before
        // the stream worker can redeliver old envelopes. Without this, the TUI
        // starts the core with an empty session map while secure_store still
        // contains `session_<uuid>` / `archive_<uuid>` bytes.
        match read_storage.secure_load("construct.orchestrator_state") {
            Ok(Some(state)) if !state.is_empty() => {
                if let Err(e) = orchestrator.import_orchestrator_state_cfe(&state) {
                    tracing::warn!(
                        error = %e,
                        "failed to restore orchestrator coordination state"
                    );
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = %e,
                "failed to load orchestrator coordination state"
            ),
        }
        for contact_id in &contact_ids {
            let key = format!("session_{contact_id}");
            match read_storage.secure_load(&key) {
                Ok(Some(data)) => {
                    if let Err(error) = orchestrator.import_session_cfe(contact_id, &data) {
                        tracing::warn!(%contact_id, %error, "failed to restore session");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%contact_id, %error, "failed to load session"),
            }
        }

        self.read_storage = Some(read_storage);

        // ── Generate OTPKs before moving orchestrator into task ───────────────
        let otpks = orchestrator.generate_otpks(100).unwrap_or_default();

        // Capture our identity public key before the orchestrator is moved into the task.
        self.our_identity_key = orchestrator.identity_public_key_bytes().ok();

        // ── Spawn gRPC stream worker subscribed to known contacts ─────────────
        let cursor = self
            .read_storage
            .as_ref()
            .map(CursorTracker::load)
            .unwrap_or_default();
        let actor_known_contacts = contact_ids.clone();
        let (stream_tx, mut stream_rx) =
            spawn_stream_worker(self.grpc.clone(), contact_ids, cursor.clone());
        self.stream_tx = Some(stream_tx.clone());

        // Spawn the Orchestrator actor task.
        let orch_handle = spawn_orchestrator_task(
            orchestrator,
            storage,
            stream_tx,
            self.internal_tx.clone(),
            self.grpc.clone(),
            cursor.clone(),
            actor_known_contacts,
            user_id.clone(),
            device_id.clone(),
        );

        // Fire AppLaunched to trigger session GC / prewarm sweep.
        orch_handle.send(construct_core::orchestration::actions::IncomingEvent::AppLaunched);
        self.orch_handle = Some(orch_handle.clone());

        // ── Upload OTPKs in background ────────────────────────────────────────
        if !otpks.is_empty() {
            tracing::info!("OTPKs generated: {} keys", otpks.len());
            let did = device_id.clone();
            let keys = otpks.clone();
            let grpc = self.grpc.clone();
            tokio::spawn(async move {
                grpc.set_device_id(Some(did.clone()));
                if let Err(e) = crate::grpc::upload_pre_keys(&grpc, &did, keys, false).await {
                    tracing::warn!("OTPK upload failed: {e}");
                }
            });
        }

        // Relay stream events to the Orchestrator.
        let orch_tx = orch_handle.tx.clone();
        let orch_stream = orch_handle.clone();
        let internal_tx = self.internal_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = stream_rx.recv().await {
                match event {
                    StreamEvent::Message {
                        envelope,
                        stream_cursor,
                    } => {
                        let inbound = match resolve_inbound_envelope(
                            &envelope,
                            &identity_secret_for_sealed,
                        ) {
                            Ok(inbound) => inbound,
                            Err(e) => {
                                tracing::warn!(
                                    message_id = %direct_envelope_message_id(&envelope),
                                    has_sealed_sender = envelope.sealed_sender.is_some(),
                                    payload_len = envelope.encrypted_payload.len(),
                                    stream_cursor = ?stream_cursor,
                                    "incoming envelope dropped: {e}"
                                );
                                continue;
                            }
                        };
                        if inbound.is_sealed {
                            tracing::info!(
                                message_id = %inbound.message_id,
                                sender = %inbound.from,
                                content_type = inbound.content_type,
                                payload_len = inbound.wire_payload.len(),
                                "incoming sealed sender envelope resolved"
                            );
                        }

                        let message_id = inbound.message_id;
                        let from = inbound.from;
                        let sender_user_id = inbound
                            .sender_certificate
                            .as_ref()
                            .map(|cert| cert.user_id.clone())
                            .unwrap_or_else(|| from.clone());
                        let content_type = inbound.content_type;
                        let wire_payload = inbound.wire_payload;
                        let is_sealed = inbound.is_sealed;

                        match construct_core::wire_payload::unpack(&wire_payload) {
                            Ok(decoded) => {
                                let msg_num = decoded.message_number;
                                orch_stream.stream_message(
                                    construct_core::orchestration::actions::IncomingEvent::MessageReceived {
                                        message_id: message_id.clone(),
                                        from: from.clone(),
                                        data: wire_payload,
                                        sender_certificate: inbound.sender_certificate.clone(),
                                        content_type,
                                        // This client does not open session envelopes yet.
                                        envelope_session: None,
                                    },
                                    StreamMessageContext {
                                        contact_id: sender_user_id.clone(),
                                        message_id,
                                        stream_cursor,
                                        content_type,
                                        msg_num,
                                    },
                                );
                            }
                            Err(e) => {
                                let is_reset_control = is_session_reset_control_type(content_type);
                                if is_reset_control {
                                    tracing::warn!(
                                        message_id = %message_id,
                                        sender = %from,
                                        content_type,
                                        payload_len = wire_payload.len(),
                                        has_sealed_sender = is_sealed,
                                        stream_cursor = ?stream_cursor,
                                        "incoming reset control routed without wire payload decode: {e}"
                                    );
                                    orch_stream.stream_message(
                                        construct_core::orchestration::actions::IncomingEvent::MessageReceived {
                                            message_id: message_id.clone(),
                                            from: from.clone(),
                                            data: wire_payload,
                                            sender_certificate: inbound.sender_certificate.clone(),
                                            content_type,
                                            envelope_session: None,
                                        },
                                        StreamMessageContext {
                                            contact_id: sender_user_id,
                                            message_id,
                                            stream_cursor,
                                            content_type,
                                            msg_num: 0,
                                        },
                                    );
                                } else {
                                    tracing::warn!(
                                        message_id = %message_id,
                                        sender = %from,
                                        content_type,
                                        payload_len = wire_payload.len(),
                                        has_sealed_sender = is_sealed,
                                        stream_cursor = ?stream_cursor,
                                        "incoming envelope dropped: wire payload unpack failed: {e}"
                                    );
                                }
                            }
                        }
                    }
                    StreamEvent::Ack {
                        message_id,
                        stream_cursor,
                    } => {
                        cursor.note(&message_id, stream_cursor);
                        let _ = orch_tx.send(
                            construct_core::orchestration::actions::IncomingEvent::AckReceived {
                                message_id,
                            },
                        );
                    }
                    StreamEvent::Heartbeat {
                        timestamp,
                        server_timestamp,
                        stream_cursor,
                    } => {
                        tracing::debug!(
                            timestamp,
                            server_timestamp,
                            stream_cursor = ?stream_cursor,
                            "stream heartbeat observed"
                        );
                    }
                    StreamEvent::StreamError {
                        message_id,
                        error_code,
                        error_message,
                        retryable,
                        retry_after_ms,
                        stream_cursor,
                    } => {
                        tracing::warn!(
                            message_id = %message_id,
                            error_code,
                            retryable,
                            retry_after_ms = ?retry_after_ms,
                            stream_cursor = ?stream_cursor,
                            "stream server error routed to UI: {}",
                            error_message
                        );
                        let label = if message_id.is_empty() {
                            format!("Stream error {error_code}: {error_message}")
                        } else {
                            format!("Stream error for {message_id}: {error_message}")
                        };
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::Error(label),
                        ));
                    }
                    StreamEvent::Connected => {
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::StreamStatus { connected: true },
                        ));
                        let _ = orch_tx.send(
                            construct_core::orchestration::actions::IncomingEvent::NetworkReconnected,
                        );
                    }
                    StreamEvent::Disconnected => {
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::StreamStatus { connected: false },
                        ));
                    }
                    StreamEvent::Reconnecting { attempt, delay } => {
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::StreamReconnecting {
                                attempt,
                                delay_ms: delay.as_millis() as u64,
                            },
                        ));
                    }
                    StreamEvent::AuthRequired => {
                        let _ = internal_tx.send(InternalEvent::StreamAuthRequired);
                    }
                }
            }
        });
    }

    fn refresh_token_now(&mut self) {
        let Some(session) = self.current_session.clone() else {
            return;
        };
        let tx = self.internal_tx.clone();
        let mut rx = crate::bridge::spawn_token_refresh_now(
            self.grpc.clone(),
            session.device_id,
            session.refresh_token,
        );
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = tx.send(InternalEvent::TokenRefresh(msg));
            }
        });
    }

    fn start_token_refresh(&mut self, session: &Session) {
        let tx = self.internal_tx.clone();
        let mut rx = crate::bridge::spawn_token_refresh(
            self.grpc.clone(),
            session.device_id.clone(),
            session.refresh_token.clone(),
            session.expires_at,
        );
        // Forward the single result from the token refresh task into the unified channel.
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = tx.send(InternalEvent::TokenRefresh(msg));
            }
        });
    }

    fn handle_token_refresh_msg(&mut self, msg: TokenRefreshMsg) {
        match msg {
            TokenRefreshMsg::Refreshed {
                access_token,
                refresh_token,
                expires_at,
            } => {
                self.access_token = access_token.clone();
                self.grpc.set_token(Some(access_token.clone()));
                let updated = self.build_updated_session(access_token, refresh_token, expires_at);
                if let Some(session) = updated {
                    self.persist_session_background(session);
                }
            }
            TokenRefreshMsg::FailedTransport(e) => {
                tracing::warn!("Token refresh transport failure ({e}) — keeping tokens");
            }
            TokenRefreshMsg::FailedAuth(e) => {
                tracing::warn!("Token refresh rejected ({e}) — attempting device re-auth");
                self.start_device_reauth();
            }
        }
    }

    /// Fall back to device signing-key authentication when the refresh token is expired
    /// or server-rejected (e.g. JWT secret rotation on redeploy).
    /// On success, routes through the normal `AuthMsg::Success` path which updates tokens,
    /// persists the session, and restarts the orchestrator with a fresh access token.
    fn start_device_reauth(&mut self) {
        let Some(session) = self.current_session.clone() else {
            self.status = "Device re-auth failed: no session in memory".into();
            return;
        };
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            match crate::auth::authenticate_saved_session(session, &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    let msg = AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full.clone(),
                        pending_save: Some(full),
                    }));
                    let _ = tx.send(InternalEvent::Auth(msg));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::Auth(AuthMsg::Failure(format!(
                        "Device re-auth failed: {e}"
                    ))));
                }
            }
        });
    }

    /// Handle P2P connection status updates.
    fn handle_p2p_status(
        &mut self,
        peer_id: String,
        connected: bool,
        latency_ms: Option<u32>,
        is_relay: bool,
    ) {
        if connected {
            let latency_str = latency_ms
                .map(|l| format!("{}ms", l))
                .unwrap_or_else(|| "unknown".to_string());
            self.status = format!("P2P connected to {} ({} latency)", peer_id, latency_str);

            // Update connection state to show P2P
            self.connection = ConnectionState::Connected {
                transport: "P2P".into(),
                latency_ms,
            };
        } else if is_relay {
            self.status = format!("P2P failed for {}, using relay", peer_id);
            self.connection = ConnectionState::Connected {
                transport: "Relay".into(),
                latency_ms: None,
            };
        } else {
            self.status = format!("P2P disconnected from {}", peer_id);
        }

        tracing::info!(
            "P2P status: peer={} connected={} latency={:?} relay={}",
            peer_id,
            connected,
            latency_ms,
            is_relay
        );
    }

    fn handle_bridge_event(&mut self, evt: BridgeEvent) {
        match evt {
            BridgeEvent::NewMessage {
                peer_id: _,
                message_id: _,
                text,
                timestamp_ms: _,
            } => {
                use crate::screens::chat_view::{ChatMessage, MessageKind};
                self.chat_view.messages.push(ChatMessage {
                    id: generate_message_id(),
                    kind: MessageKind::Received,
                    text,
                    time: current_time_hhmm(),
                });
                self.chat_view.on_new_message();
            }
            BridgeEvent::MessageDelivered { message_id: _ } => {
                // TODO: update delivery indicator
            }
            BridgeEvent::StreamStatus { connected } => {
                if connected {
                    self.connection = ConnectionState::Connected {
                        transport: transport_label(&self.transport).into(),
                        latency_ms: None,
                    };
                    self.status = "● connected".into();
                } else {
                    self.connection = ConnectionState::Disconnected;
                    self.status = "○ disconnected".into();
                }
            }
            BridgeEvent::StreamReconnecting { attempt, delay_ms } => {
                let interval = std::time::Duration::from_millis(delay_ms);
                self.connection = ConnectionState::Reconnecting {
                    attempt,
                    next_retry: std::time::Instant::now() + interval,
                    interval,
                };
                self.status = format!("↺ reconnecting (attempt {attempt})");
            }
            BridgeEvent::Error(e) => {
                self.status = format!("Bridge error: {e}");
            }
            BridgeEvent::SessionReady { contact_id } => {
                let name = self
                    .chat_list
                    .contacts
                    .iter()
                    .find(|c| c.id == contact_id)
                    .map(|c| c.display_name.as_str())
                    .unwrap_or("contact");
                self.status = format!("Session ready with @{name}");
            }
        }
    }

    /// Build an updated Session with refreshed tokens, using the in-memory session copy.
    fn build_updated_session(
        &self,
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    ) -> Option<Session> {
        let mut session = self.current_session.clone()?;
        session.access_token = access_token;
        session.refresh_token = refresh_token;
        session.expires_at = expires_at;
        Some(session)
    }

    fn persist_session_background(&mut self, session: Session) {
        // Keep in-memory copy fresh so token refreshes don't need disk reads.
        self.current_session = Some(session.clone());

        // Restart token refresh with new expiry.
        self.start_token_refresh(&session);

        if let Some(ref sk) = self.session_key {
            let _ = config::save_session_encrypted(&session, sk);
        } else if self.no_encrypt {
            let _ = config::save_session(&session);
        }
    }

    // ── Event handling ──────────────────────────────────────────────────────────

    fn handle_event(&mut self, event: Event) {
        let Event::Key(key) = event;
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always exits regardless of screen.
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.running = false;
            return;
        }

        // Use discriminant checks to avoid cloning Screen variants that hold String data.
        if matches!(self.screen, Screen::Startup | Screen::Connecting(_)) {
            return;
        }
        if matches!(self.screen, Screen::AuthError(_)) {
            // If a session key is present the user came from the Unlock screen —
            // go back there so they can retry (or choose to start fresh via Esc).
            // Otherwise it was a startup-auto-restore or registration error: Onboarding.
            if self.session_key.is_some() {
                self.unlock_screen.reset_for_mode(UnlockMode::Unlock);
                self.screen = Screen::Unlock;
            } else {
                self.screen = Screen::Onboarding;
            }
            return;
        }
        if matches!(self.screen, Screen::Unlock) {
            return self.handle_unlock(key);
        }
        if matches!(self.screen, Screen::SetPassphrase) {
            return self.handle_set_passphrase(key);
        }
        if matches!(self.screen, Screen::Onboarding) {
            return self.handle_onboarding(key);
        }
        if matches!(self.screen, Screen::DeviceLink) {
            return self.handle_device_link(key);
        }
        if matches!(self.screen, Screen::Main) {
            return self.handle_main(key);
        }
        if matches!(self.screen, Screen::Settings) {
            return self.handle_settings(key);
        }
        if matches!(self.screen, Screen::ContactSearch) {
            return self.handle_contact_search(key);
        }
        if matches!(self.screen, Screen::SafetyNumber) {
            // Any key exits safety number back to settings.
            self.screen = Screen::Settings;
        }
        if matches!(self.screen, Screen::IdentityQr) {
            // Any key exits full-screen QR back to settings.
            self.screen = Screen::Settings;
        }
    }

    fn handle_onboarding(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Char('q')
                if key.modifiers == KeyModifiers::NONE
                    && self.onboarding.focused_field == OnboardingField::Username
                    && self.onboarding.username.is_empty() =>
            {
                self.running = false;
            }
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                self.running = false;
            }
            // Tab switches to device-link flow
            KeyCode::Tab | KeyCode::BackTab => {
                self.device_link = DeviceLinkScreen::new();
                self.screen = Screen::DeviceLink;
            }
            KeyCode::Enter => {
                let username = self.onboarding.username.trim().to_string();
                self.onboarding.status = None;
                self.start_auth_register(username);
            }
            KeyCode::Backspace => {
                self.onboarding.pop_char();
                self.onboarding.status = None;
            }
            KeyCode::Char(c) => {
                self.onboarding.push_char(c);
                self.onboarding.status = None;
            }
            _ => {}
        }
    }

    fn handle_unlock(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Backspace => {
                self.unlock_screen.pop_char();
                self.unlock_screen.clear_error();
            }
            KeyCode::Char(c) => {
                self.unlock_screen.push_char(c);
                self.unlock_screen.clear_error();
            }
            KeyCode::Enter => {
                let passphrase = self.unlock_screen.take_passphrase();
                if passphrase.is_empty() {
                    self.unlock_screen.set_error("Enter your passphrase");
                    return;
                }
                match config::open_session_key(&passphrase) {
                    Ok(Some(sk)) => match config::load_session_encrypted(&sk) {
                        Ok(Some(session)) => {
                            self.session_key = Some(sk);
                            self.start_auth_restore_preloaded(session);
                        }
                        Ok(None) => self.unlock_screen.set_error("No session found"),
                        Err(e) => self
                            .unlock_screen
                            .set_error(format!("Session corrupted: {e}")),
                    },
                    Ok(None) => self.unlock_screen.set_error("No session found"),
                    Err(_) => self
                        .unlock_screen
                        .set_error("Wrong passphrase or corrupted session"),
                }
            }
            _ => {}
        }
    }

    fn handle_set_passphrase(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Backspace => self.unlock_screen.pop_char(),
            KeyCode::Char(c) => self.unlock_screen.push_char(c),
            KeyCode::Enter => {
                let passphrase = self.unlock_screen.take_passphrase();
                if passphrase.is_empty() {
                    self.unlock_screen
                        .set_error("Choose a passphrase to protect your session");
                    return;
                }
                if let Some(session) = self.pending_session.take() {
                    match config::create_session_key(&passphrase) {
                        Ok(sk) => match config::save_session_encrypted(&session, &sk) {
                            Ok(()) => {
                                self.session_key = Some(sk);
                                // Orchestrator was deferred until now — we finally have the DB key.
                                if let Some(full) = self.current_session.clone() {
                                    self.start_orchestrator(
                                        full,
                                        self.user_id.clone(),
                                        self.device_id.clone(),
                                        self.access_token.clone(),
                                    );
                                }
                                self.screen = Screen::Main;
                            }
                            Err(e) => {
                                self.pending_session = Some(session);
                                self.unlock_screen.set_error(format!("Save failed: {e}"));
                            }
                        },
                        Err(e) => {
                            self.pending_session = Some(session);
                            self.unlock_screen
                                .set_error(format!("Key derivation failed: {e}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_device_link(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') if key.modifiers == KeyModifiers::NONE => {
                self.screen = Screen::Onboarding;
            }
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                self.running = false;
            }
            KeyCode::Enter => {
                let token = self.device_link.token.trim().to_string();
                if token.is_empty() {
                    self.device_link
                        .set_status("Paste the link token first", true);
                } else {
                    self.device_link.clear_status();
                    self.start_auth_link(token);
                }
            }
            KeyCode::Backspace => {
                self.device_link.pop_char();
            }
            KeyCode::Char(c) => {
                self.device_link.push_char(c);
            }
            _ => {}
        }
    }

    fn handle_main(&mut self, key: crossterm::event::KeyEvent) {
        // If a delete-confirm dialog is active, intercept all keys.
        if self.delete_confirm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_delete(),
                _ => {
                    self.delete_confirm = None;
                }
            }
            return;
        }
        if is_quit(&key) && self.focus != Focus::Compose {
            self.running = false;
            return;
        }
        match self.focus {
            Focus::ContactList => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.chat_list.next(),
                KeyCode::Up | KeyCode::Char('k') => self.chat_list.prev(),
                // Delete selected contact (x key)
                KeyCode::Char('x') if key.modifiers == crossterm::event::KeyModifiers::NONE => {
                    if let Some(c) = self.chat_list.selected_contact() {
                        self.delete_confirm = Some(c.id.clone());
                    }
                }
                KeyCode::Enter | KeyCode::Tab => {
                    if let Some(c) = self.chat_list.selected_contact() {
                        self.chat_view.contact_name = c.display_name.clone();
                        self.chat_view.messages.clear();
                        // Load history from DB (last 50 messages).
                        if let Some(ref storage) = self.read_storage {
                            let peer_id = c.id.clone();
                            if let Ok(history) = storage.get_messages(&peer_id, 50) {
                                use crate::screens::chat_view::{ChatMessage, MessageKind};
                                for msg in history {
                                    let kind = if msg.direction == "sent" {
                                        MessageKind::Sent
                                    } else {
                                        MessageKind::Received
                                    };
                                    // Format stored ms timestamp as HH:MM.
                                    let time = {
                                        let secs = msg.timestamp_ms / 1000;
                                        let h = (secs / 3600) % 24;
                                        let m = (secs / 60) % 60;
                                        format!("{:02}:{:02}", h, m)
                                    };
                                    self.chat_view.messages.push(ChatMessage {
                                        id: msg.id,
                                        kind,
                                        text: msg.text,
                                        time,
                                    });
                                }
                            }
                        }
                    }
                    self.set_focus(Focus::ChatView);
                }
                // Open settings
                KeyCode::Char('s') if key.modifiers == crossterm::event::KeyModifiers::NONE => {
                    self.screen = Screen::Settings;
                }
                // Add contact / search (`a` as documented, `n` as the old binding)
                KeyCode::Char('a' | 'n')
                    if key.modifiers == crossterm::event::KeyModifiers::NONE =>
                {
                    self.contact_search.reset();
                    self.screen = Screen::ContactSearch;
                }
                _ => {}
            },
            Focus::ChatView => match key.code {
                KeyCode::Tab | KeyCode::Char('i') => self.set_focus(Focus::Compose),
                KeyCode::BackTab => self.set_focus(Focus::ContactList),
                KeyCode::Esc => self.set_focus(Focus::ContactList),
                KeyCode::PageUp | KeyCode::Char('u') => self.chat_view.scroll_up(10),
                KeyCode::PageDown | KeyCode::Char('d') => self.chat_view.scroll_down(10),
                KeyCode::Up | KeyCode::Char('k') => self.chat_view.scroll_up(1),
                KeyCode::Down | KeyCode::Char('j') => self.chat_view.scroll_down(1),
                KeyCode::Home => self.chat_view.scroll_to_top(),
                KeyCode::End => self.chat_view.scroll_to_bottom(),
                _ => {}
            },
            Focus::Compose => match key.code {
                KeyCode::Esc => self.set_focus(Focus::ChatView),
                KeyCode::Enter => {
                    let text = self.chat_view.take_compose();
                    if !text.trim().is_empty() {
                        use crate::screens::chat_view::{ChatMessage, MessageKind};
                        let message_id = generate_message_id();

                        // Send via E2EE Orchestrator if wired up.
                        #[allow(clippy::collapsible_if)]
                        if let Some(ref orch) = self.orch_handle {
                            if let Some(contact) = self.chat_list.selected_contact() {
                                orch.send(construct_core::orchestration::actions::IncomingEvent::OutgoingMessage {
                                    contact_id: contact.id.clone(),
                                    message_id: message_id.clone(),
                                    plaintext: text.as_bytes().to_vec(),
                                    content_type: 0,
                                });
                            }
                        }

                        self.chat_view.messages.push(ChatMessage {
                            id: message_id,
                            kind: MessageKind::Sent,
                            text,
                            time: current_time_hhmm(),
                        });
                        self.status = "Message sent".into();
                    }
                }
                KeyCode::Backspace => self.chat_view.pop_char(),
                KeyCode::Char(c) => self.chat_view.push_char(c),
                _ => {}
            },
        }
    }

    fn set_focus(&mut self, f: Focus) {
        self.chat_list.focused = f == Focus::ContactList;
        self.chat_view.focused = f == Focus::ChatView;
        self.chat_view.compose_focused = f == Focus::Compose;
        self.focus = f;
    }

    fn handle_settings(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Main,
            KeyCode::Up | KeyCode::Char('k') => self.settings_screen.prev(),
            KeyCode::Down | KeyCode::Char('j') => self.settings_screen.next(),
            KeyCode::Enter => {
                if let Some(action) = self.settings_screen.confirm() {
                    match action {
                        SettingsAction::CycleTheme => self.cycle_theme(),
                        SettingsAction::Back => self.screen = Screen::Main,
                        SettingsAction::Logout => self.do_logout(),
                        SettingsAction::ShowSafetyNumber => {
                            self.open_safety_number_screen();
                        }
                        SettingsAction::ExportKeys => {
                            self.export_identity_key();
                        }
                        SettingsAction::ShowMyQr => {
                            self.screen = Screen::IdentityQr;
                        }
                    }
                }
            }
            // Shortcut keys
            KeyCode::Char('l') | KeyCode::Char('L') => self.do_logout(),
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.screen = Screen::IdentityQr;
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.open_safety_number_screen();
            }
            KeyCode::Char('t') | KeyCode::Char('T') => self.cycle_theme(),
            _ => {}
        }
    }

    fn cycle_theme(&mut self) {
        let mut cfg = match config::load_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                self.status = format!("Could not load settings: {e}");
                return;
            }
        };
        cfg.theme = self.theme.next();
        match config::save_config(&cfg) {
            Ok(()) => {
                self.theme = cfg.theme;
                self.settings_screen.theme = cfg.theme;
                self.status = format!("Theme: {}", cfg.theme.label());
            }
            Err(e) => self.status = format!("Could not save theme: {e}"),
        }
    }

    fn open_safety_number_screen(&mut self) {
        let Some(contact) = self.chat_list.selected_contact() else {
            self.status = "Select a contact first".into();
            return;
        };
        let contact_name = contact.display_name.clone();
        let contact_id = contact.id.clone();

        let our_key = match &self.our_identity_key {
            Some(k) => vec_to_key32(k),
            None => {
                self.status = "Identity key not available".into();
                return;
            }
        };

        // Look up peer's identity key from DB (empty string → key not yet fetched).
        let their_key: [u8; 32] = self
            .read_storage
            .as_ref()
            .and_then(|s| s.get_contact_by_id(&contact_id).ok().flatten())
            .and_then(|c| {
                if c.identity_key_b64.is_empty() {
                    None
                } else {
                    base64::engine::general_purpose::STANDARD
                        .decode(&c.identity_key_b64)
                        .ok()
                        .map(|v| vec_to_key32(&v))
                }
            })
            .unwrap_or([0u8; 32]);

        self.safety_number = Some(SafetyNumberScreen::new(contact_name, &our_key, &their_key));
        self.screen = Screen::SafetyNumber;
    }

    fn export_identity_key(&mut self) {
        let key = match &self.our_identity_key {
            Some(k) => k.clone(),
            None => {
                self.status = "Identity key not available".into();
                return;
            }
        };
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let path = format!(
            "{}/construct_identity_{}.txt",
            std::env::var("HOME").unwrap_or_else(|_| ".".into()),
            &self.user_id,
        );
        match std::fs::write(
            &path,
            format!("identity_public_key_hex={hex}\nuser_id={}\n", self.user_id),
        ) {
            Ok(()) => self.status = format!("Key exported → {path}"),
            Err(e) => self.status = format!("Export failed: {e}"),
        }
    }

    fn handle_contact_search(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.contact_search.reset();
                self.screen = Screen::Main;
            }
            KeyCode::Down => self.contact_search.next(),
            KeyCode::Up => self.contact_search.prev(),
            KeyCode::Enter => {
                if self.contact_search.selected().is_some() {
                    self.add_selected_search_result();
                } else {
                    self.submit_contact_search();
                }
            }
            KeyCode::Tab => self.contact_search.next(),
            KeyCode::BackTab => self.contact_search.prev(),
            KeyCode::Char('a') if key.modifiers == crossterm::event::KeyModifiers::CONTROL => {
                self.add_selected_search_result();
            }
            KeyCode::Backspace => self.contact_search.pop_char(),
            KeyCode::Char(c) => self.contact_search.push_char(c),
            _ => {}
        }
    }

    fn submit_contact_search(&mut self) {
        let raw = self.contact_search.query.trim().to_string();
        if crate::invite::looks_like_invite(&raw) {
            self.redeem_pasted_invite(&raw);
            return;
        }
        let query = crate::grpc::users::normalize_username(&self.contact_search.query);
        if !crate::grpc::users::username_is_searchable(&query) {
            self.contact_search
                .set_error("Username: 3–30 chars, letters/digits/_  (no @)");
            return;
        }
        self.contact_search.searching = true;
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let result = crate::grpc::find_user(&grpc, &query).await;
            match result {
                Ok(Some(user_id)) => {
                    let _ = tx.send(InternalEvent::ContactSearchResult(vec![SearchResult {
                        user_id,
                        username: query.clone(),
                        display_name: query,
                    }]));
                }
                Ok(None) => {
                    let _ = tx.send(InternalEvent::ContactSearchResult(vec![]));
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::ContactSearchError(e.to_string()));
                }
            }
        });
    }

    fn add_selected_search_result(&mut self) {
        let Some(result) = self.contact_search.selected().cloned() else {
            return;
        };
        self.finish_add_contact(result.user_id, result.username);
    }

    fn finish_add_contact(&mut self, user_id: String, username: String) {
        let new_contact = Contact {
            id: user_id.clone(),
            display_name: username.clone(),
            unread: 0,
            last_message: None,
        };
        if let Some(ref storage) = self.read_storage {
            let _ = storage.upsert_contact(&crate::storage::StoredContact {
                user_id: user_id.clone(),
                display_name: username.clone(),
                identity_key_b64: String::new(),
            });
        }
        self.chat_list.add_contact(new_contact);
        self.resubscribe_stream_to_contacts();
        if let Some(ref orch) = self.orch_handle {
            orch.remember_contact(user_id.clone());
        }
        self.status = format!("Added @{username}");
        self.contact_search.reset();
        self.screen = Screen::Main;
    }

    fn resubscribe_stream_to_contacts(&self) {
        let Some(ref stream_tx) = self.stream_tx else {
            return;
        };
        let contact_ids = contact_ids_for_stream(&self.chat_list.contacts);
        let stream_cursor = self
            .read_storage
            .as_ref()
            .and_then(|storage| storage.load_stream_cursor().ok().flatten());
        let _ = stream_tx.try_send(crate::streaming::StreamCmd::Subscribe(
            contact_ids,
            stream_cursor,
        ));
    }

    fn redeem_pasted_invite(&mut self, raw: &str) {
        let invite = match crate::invite::parse_invite(raw) {
            Ok(inv) => inv,
            Err(e) => {
                self.contact_search.set_error(format!("Bad invite: {e:#}"));
                return;
            }
        };
        if invite.is_expired(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        ) {
            self.contact_search.set_error("Invite expired");
            return;
        }
        self.contact_search.searching = true;
        self.contact_search.status = Some("Redeeming invite…".into());
        let tx = self.internal_tx.clone();
        let grpc = self.grpc.clone();
        let username = invite
            .un
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| invite.uuid[..8.min(invite.uuid.len())].to_string());
        tokio::spawn(async move {
            match crate::grpc::accept_invite(&grpc, &invite).await {
                Ok(accepted) => {
                    let _ = tx.send(InternalEvent::InviteAccepted {
                        user_id: accepted.user_id,
                        username,
                    });
                }
                Err(e) => {
                    let _ = tx.send(InternalEvent::ContactSearchError(format!("Invite: {e}")));
                }
            }
        });
    }

    /// Execute a confirmed contact deletion: remove from storage, chat list, and active view.
    fn confirm_delete(&mut self) {
        let Some(peer_id) = self.delete_confirm.take() else {
            return;
        };
        // Find the index before deleting from storage so we can remove from the list.
        let idx = self.chat_list.contacts.iter().position(|c| c.id == peer_id);
        let delete_result = self
            .read_storage
            .as_ref()
            .map(|s| s.delete_contact(&peer_id));
        if let Some(Err(e)) = delete_result {
            self.status = format!("Delete failed: {e}");
            return;
        }
        if let Some(ref orch) = self.orch_handle {
            orch.forget_contact(peer_id.clone());
        }
        if let Some(i) = idx {
            self.chat_list.remove_at(i);
        }
        self.resubscribe_stream_to_contacts();
        // Clear chat view if it was showing the deleted contact.
        if self.chat_view.contact_name == peer_id
            || self.chat_list.contacts.iter().all(|c| c.id != peer_id)
        {
            self.chat_view.messages.clear();
            self.chat_view.contact_name = self
                .chat_list
                .selected_contact()
                .map(|c| c.display_name.clone())
                .unwrap_or_default();
        }
        self.status = "Person removed.".into();
    }

    /// Clear session from disk and reset to onboarding state.
    fn do_logout(&mut self) {
        if let Err(e) = config::clear_session() {
            self.status = format!("Logout error: {e}");
            return;
        }
        // Drop the orchestrator and stream worker (stops background tasks).
        self.orch_handle = None;
        if let Some(ref tx) = self.stream_tx.take() {
            let _ = tx.try_send(crate::streaming::StreamCmd::Shutdown);
        }
        if let Some(ref storage) = self.read_storage {
            let _ = storage.clear_stream_cursor();
        }
        self.grpc.set_token(None);
        self.grpc.set_device_id(None);
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            grpc.invalidate_h3().await;
        });
        self.read_storage = None;
        self.session_key = None;
        self.current_session = None;
        self.pending_session = None;
        self.our_identity_key = None;
        self.user_id = String::new();
        self.device_id = String::new();
        self.access_token = String::new();
        self.connection = ConnectionState::Disconnected;
        self.contact_search.reset();
        self.chat_list = ChatListPane::new();
        self.chat_view = ChatViewPane::new(String::new());
        self.settings_screen = SettingsScreen::new(
            &self.server_url,
            transport_label(&self.transport),
            "—",
            "—",
            self.pq_active,
            "",
        );
        self.onboarding = OnboardingScreen::new();
        self.screen = Screen::Onboarding;
    }

    // ── Rendering ───────────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let palette = self.theme.palette();
        frame.render_widget(Block::default().style(palette.canvas()), area);

        self.onboarding.theme = self.theme;
        self.device_link.theme = self.theme;
        self.unlock_screen.theme = self.theme;
        self.registration.theme = self.theme;
        self.settings_screen.theme = self.theme;
        self.contact_search.theme = self.theme;
        if let Some(ref mut safety_number) = self.safety_number {
            safety_number.theme = self.theme;
        }

        if matches!(self.screen, Screen::Main) {
            self.render_main(frame);
            // Overlay delete confirmation dialog on top of the main view.
            if let Some(ref peer_id) = self.delete_confirm.clone() {
                self.render_delete_confirm(frame, peer_id);
            }
            return;
        }
        if matches!(self.screen, Screen::Settings) {
            return frame.render_widget(&mut self.settings_screen, area);
        }
        if matches!(self.screen, Screen::ContactSearch) {
            return frame.render_widget(&mut self.contact_search, area);
        }
        if matches!(self.screen, Screen::SafetyNumber) {
            if let Some(ref sn) = self.safety_number {
                return frame.render_widget(sn, area);
            }
            self.screen = Screen::Settings;
            return frame.render_widget(&mut self.settings_screen, area);
        }
        if matches!(self.screen, Screen::IdentityQr) {
            let payload = self.settings_screen.invite_payload().map(|s| s.to_owned());
            let user_id = self.user_id.clone();
            return self.render_identity_qr_fullscreen(frame, area, payload.as_deref(), &user_id);
        }
        if matches!(self.screen, Screen::DeviceLink) {
            return frame.render_widget(&self.device_link, area);
        }
        if matches!(self.screen, Screen::Registering) {
            return frame.render_widget(&self.registration, area);
        }
        if matches!(self.screen, Screen::Unlock | Screen::SetPassphrase) {
            return frame.render_widget(&self.unlock_screen, area);
        }
        if matches!(self.screen, Screen::Startup) {
            frame.render_widget(&self.onboarding, area);
            return self.render_spinner(frame, "Restoring session…");
        }
        if let Screen::Connecting(ref msg) = self.screen {
            let msg = msg.clone();
            frame.render_widget(&self.onboarding, area);
            return self.render_spinner(frame, &msg);
        }
        if let Screen::AuthError(ref msg) = self.screen {
            let msg = msg.clone();
            frame.render_widget(&self.onboarding, area);
            return self.render_error_overlay(frame, &msg);
        }
        // Screen::Onboarding (and any future unauthenticated screens)
        frame.render_widget(&self.onboarding, area);
    }

    fn render_identity_qr_fullscreen(
        &self,
        frame: &mut Frame,
        area: Rect,
        payload: Option<&str>,
        user_id: &str,
    ) {
        let palette = self.theme.palette();
        frame.render_widget(Clear, area);
        frame.render_widget(Block::default().style(palette.canvas()), area);

        let Some(payload) = payload else {
            let msg = Paragraph::new("Generating invite…")
                .style(palette.muted())
                .alignment(Alignment::Center);
            frame.render_widget(msg, area);
            return;
        };

        // Hint at bottom
        let hint = Paragraph::new(Line::from(vec![
            Span::styled("  Scan with Konstruct iOS  (v5, 5 min)  ", palette.muted()),
            Span::styled(
                "[ any key to return ]",
                palette.muted().add_modifier(Modifier::DIM),
            ),
        ]))
        .alignment(Alignment::Center);

        let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
        frame.render_widget(hint, chunks[1]);

        // Centre the QR within the available area
        let qr_area = chunks[0];
        let Some((qr_w, qr_h)) = QrWidget::size_hint(payload) else {
            let msg = Paragraph::new("[ QR unavailable — payload too large ]")
                .style(palette.muted())
                .alignment(Alignment::Center);
            frame.render_widget(msg, qr_area);
            return;
        };

        let x = qr_area.x + qr_area.width.saturating_sub(qr_w) / 2;
        let y = qr_area.y + qr_area.height.saturating_sub(qr_h) / 2;
        let render_area = Rect {
            x,
            y,
            width: qr_w.min(qr_area.width),
            height: qr_h.min(qr_area.height),
        };

        let widget = QrWidget {
            theme: self.theme,
            data: payload,
            caption: Some(user_id),
            fg: Color::Black,
            bg: Color::White,
        };
        frame.render_widget(&widget, render_area);
    }

    fn render_spinner(&self, frame: &mut Frame, msg: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let y = area.height.saturating_sub(2);
        let line = Line::from(vec![
            Span::styled("  ⠋ ", palette.emphasis()),
            Span::styled(msg, palette.text()),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            ratatui::layout::Rect {
                x: 0,
                y,
                width: area.width,
                height: 1,
            },
        );
    }

    fn render_error_overlay(&self, frame: &mut Frame, msg: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let y = area.height.saturating_sub(2);
        let display = format!("  ✗ {}  (any key to retry)", msg);
        let line = Line::from(Span::styled(display, palette.state(true)));
        frame.render_widget(
            Paragraph::new(line),
            ratatui::layout::Rect {
                x: 0,
                y,
                width: area.width,
                height: 1,
            },
        );
    }

    /// Render the delete confirmation over the active screen.
    fn render_delete_confirm(&self, frame: &mut Frame, peer_id: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let name = self
            .chat_list
            .contacts
            .iter()
            .find(|c| c.id == peer_id)
            .map(|c| c.display_name.as_str())
            .unwrap_or(peer_id);
        let width = area.width.min(54);
        let height = area.height.min(5);
        let dialog = Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, dialog);
        let block = palette
            .panel(" Remove person ", false)
            .border_style(Style::default().fg(palette.warning).bg(palette.panel))
            .style(palette.surface());
        let inner = block.inner(dialog);
        frame.render_widget(block, dialog);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(name),
                Line::from("Remove this person and all messages?"),
                Line::from(vec![
                    Span::styled("Y", Style::default().fg(palette.warning)),
                    Span::raw(" remove    Any other key cancel"),
                ]),
            ])
            .style(palette.surface()),
            inner,
        );
    }

    fn render_main(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let palette = self.theme.palette();
        let root = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                " KONSTRUCT ",
                palette.selected().add_modifier(Modifier::BOLD),
            ),
            Span::styled("  CHATS", Style::default().fg(palette.foreground)),
            Span::styled(
                format!("  ·  {}", self.theme.label()),
                Style::default().fg(palette.muted),
            ),
        ]))
        .style(Style::default().bg(palette.background));
        frame.render_widget(title, root[0]);

        self.chat_list.theme = self.theme;
        self.chat_view.theme = self.theme;
        if area.width >= 96 {
            let body = Layout::horizontal([Constraint::Percentage(34), Constraint::Percentage(66)])
                .split(root[1]);
            frame.render_widget(&mut self.chat_list, body[0]);
            frame.render_widget(&mut self.chat_view, body[1]);
        } else if self.focus == Focus::ContactList {
            frame.render_widget(&mut self.chat_list, root[1]);
        } else {
            frame.render_widget(&mut self.chat_view, root[1]);
        }

        let hints = match self.focus {
            Focus::ContactList => "↑↓ choose  Enter open  a add  x remove  s settings  q quit",
            Focus::ChatView => "Tab write  Esc chats  ↑↓ scroll  s settings",
            Focus::Compose => "Enter send  Esc back",
        };
        let footer_text = format!("{}  │  {}", self.status, hints);
        let status_bar = StatusBar {
            connection: &self.connection,
            status_text: &footer_text,
            unread_count: self.chat_list.contacts.iter().map(|c| c.unread).sum(),
            pq_active: self.pq_active,
            theme: self.theme,
        };
        frame.render_widget(status_bar, root[2]);
    }
}

fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
}

struct InboundEnvelope {
    message_id: String,
    from: String,
    wire_payload: Vec<u8>,
    content_type: u8,
    is_sealed: bool,
    sender_certificate: Option<construct_core::crypto::sealed_sender::SenderCertificate>,
}

fn resolve_inbound_envelope(
    envelope: &crate::proto::core::v1::Envelope,
    identity_secret: &[u8],
) -> std::result::Result<InboundEnvelope, String> {
    let message_id = direct_envelope_message_id(envelope).to_owned();
    let Some(sealed) = envelope.sealed_sender.as_ref() else {
        return Ok(InboundEnvelope {
            message_id,
            from: envelope
                .sender
                .as_ref()
                .map(|sender| sender.user_id.clone())
                .unwrap_or_default(),
            wire_payload: envelope.encrypted_payload.to_vec(),
            content_type: content_type_to_u8(envelope.content_type),
            is_sealed: false,
            sender_certificate: None,
        });
    };

    let inner = crate::proto::core::v1::SealedInner::decode(sealed.sealed_inner.as_ref())
        .map_err(|e| format!("sealed inner decode failed: {e}"))?;
    let cert_bytes = construct_core::crypto::sealed_sender::open_with_x25519_secret(
        &inner.sender_cert_ciphertext,
        identity_secret,
    )
    .map_err(|e| format!("sealed sender cert unseal failed: {e}"))?;
    let cert = crate::proto::core::v1::SenderCertificate::decode(cert_bytes.as_slice())
        .map_err(|e| format!("sender certificate decode failed: {e}"))?;
    if cert.sender_user_id.is_empty() {
        return Err("sender certificate has empty sender_user_id".to_string());
    }

    // Sealed delivery deliberately masks the outer sender and content type.
    // Everything authoritative after this boundary comes from SealedInner /
    // SenderCertificate; the inner bytes are then handed to the normal ratchet
    // path, which remains the message authentication root.
    let wire_payload = if envelope.encrypted_payload.is_empty() {
        inner.encrypted_payload.to_vec()
    } else {
        envelope.encrypted_payload.to_vec()
    };
    if wire_payload.is_empty() {
        return Err("sealed inner encrypted_payload is empty".to_string());
    }

    Ok(InboundEnvelope {
        message_id,
        from: cert.sender_device_id.clone(),
        wire_payload,
        content_type: content_type_to_u8(inner.content_type),
        is_sealed: true,
        sender_certificate: Some(construct_core::crypto::sealed_sender::SenderCertificate {
            user_id: cert.sender_user_id,
            domain: cert.sender_domain,
            identity_key: cert.sender_identity_key.to_vec(),
            device_id: cert.sender_device_id,
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            signature: cert.server_signature.to_vec(),
        }),
    })
}

fn content_type_to_u8(content_type: i32) -> u8 {
    u8::try_from(content_type).unwrap_or_default()
}

fn is_session_reset_control_type(content_type: u8) -> bool {
    content_type == crate::proto::core::v1::ContentType::SessionReset as u8
        || content_type == crate::proto::core::v1::ContentType::SessionResetInit as u8
}

fn direct_envelope_message_id(envelope: &crate::proto::core::v1::Envelope) -> &str {
    match &envelope.message_id_type {
        Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(id)) => id,
        Some(crate::proto::core::v1::envelope::MessageIdType::GroupMessageId(_)) | None => "",
    }
}

fn contact_ids_for_stream(contacts: &[Contact]) -> Vec<String> {
    contacts.iter().map(|contact| contact.id.clone()).collect()
}

fn current_time_hhmm() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}", (secs % 86400) / 3600, (secs % 3600) / 60)
}

fn transport_label(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Direct => "direct",
        TransportConfig::Obfs4 { .. } => "obfs4",
        TransportConfig::Obfs4Tls { .. } => "obfs4+tls",
        TransportConfig::CdnFront { .. } => "cdn-front",
    }
}

/// Truncate or zero-pad a key slice to exactly 32 bytes.
fn vec_to_key32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = v.len().min(32);
    out[..len].copy_from_slice(&v[..len]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_core::crypto::provider::CryptoProvider;
    use construct_core::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn stream_resubscribe_uses_the_full_contact_set() {
        let contacts = vec![
            Contact {
                id: "alice".to_string(),
                display_name: "Alice".to_string(),
                unread: 0,
                last_message: None,
            },
            Contact {
                id: "bob".to_string(),
                display_name: "Bob".to_string(),
                unread: 0,
                last_message: None,
            },
        ];

        assert_eq!(
            contact_ids_for_stream(&contacts),
            vec!["alice".to_string(), "bob".to_string()]
        );
    }

    #[test]
    fn invalid_wire_payload_with_reset_type_is_routed_as_control() {
        let invalid_wire_payload = b"not-a-wire-payload";

        assert!(construct_core::wire_payload::unpack(invalid_wire_payload).is_err());
        assert!(is_session_reset_control_type(
            crate::proto::core::v1::ContentType::SessionReset as u8
        ));
        assert!(is_session_reset_control_type(
            crate::proto::core::v1::ContentType::SessionResetInit as u8
        ));
        assert!(!is_session_reset_control_type(
            crate::proto::core::v1::ContentType::E2eeSignal as u8
        ));
    }

    #[test]
    fn resolves_sealed_envelope_from_inner_payload_and_sender_cert() {
        let identity_secret = vec![7u8; 32];
        let identity_private =
            ClassicSuiteProvider::kem_private_key_from_bytes(identity_secret.clone());
        let identity_public =
            ClassicSuiteProvider::from_private_key_to_public_key(&identity_private)
                .expect("test identity public key should derive");

        let cert = crate::proto::core::v1::SenderCertificate {
            sender_user_id: "sender-user".to_string(),
            sender_domain: "konstruct.cc".to_string(),
            sender_identity_key: vec![9u8; 32].into(),
            sender_device_id: "sender-device".to_string(),
            issued_at: 1,
            expires_at: 2,
            server_signature: vec![3u8; 64].into(),
        };
        let sealed_cert = construct_core::crypto::sealed_sender::seal_to_x25519_public(
            &cert.encode_to_vec(),
            identity_public.as_ref(),
        )
        .expect("test sender cert should seal");
        let wire_payload = vec![1, 2, 3, 4];
        let inner = crate::proto::core::v1::SealedInner {
            recipient_user_id: "recipient-user".to_string(),
            delivery_tag: vec![4u8; 32].into(),
            sender_cert_ciphertext: sealed_cert.into(),
            encrypted_payload: wire_payload.clone().into(),
            content_type: 13,
            ..Default::default()
        };
        let envelope = crate::proto::core::v1::Envelope {
            recipient: Some(crate::proto::core::v1::UserId {
                user_id: "recipient-user".to_string(),
                domain: None,
                display_name: None,
            }),
            encrypted_payload: Vec::new().into(),
            sealed_sender: Some(crate::proto::core::v1::SealedSenderEnvelope {
                sealed_inner: inner.encode_to_vec().into(),
                ..Default::default()
            }),
            message_id_type: Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(
                "msg-1".to_string(),
            )),
            content_type: 1,
            ..Default::default()
        };

        let resolved = resolve_inbound_envelope(&envelope, &identity_secret)
            .expect("sealed envelope should resolve");

        assert_eq!(resolved.message_id, "msg-1");
        // The core keys sessions by device since bfe444a, so `from` is the certificate's device.
        assert_eq!(resolved.from, "sender-device");
        assert_eq!(resolved.wire_payload, wire_payload);
        assert_eq!(resolved.content_type, 13);
        assert!(resolved.is_sealed);
    }
}
