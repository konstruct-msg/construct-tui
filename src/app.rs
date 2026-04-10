use anyhow::Result;
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::mpsc;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    bridge::{BridgeEvent, TokenRefreshMsg},
    config::{self, Session, SessionState, TransportConfig},
    event::{Event, EventHandler, is_quit},
    screens::onboarding::OnboardingField,
    screens::{
        ChatListPane, ChatViewPane, ConnectionState, ContactSearchScreen, DeviceLinkScreen,
        OnboardingScreen, SafetyNumberScreen, SettingsAction, SettingsScreen, StatusBar,
        UnlockMode, UnlockScreen,
    },
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
    /// Auth request in flight — show spinner message.
    Connecting(String),
    /// Auth failed — show error, return to onboarding.
    AuthError(String),
    /// Authenticated — show main chat UI.
    Main,
    /// Settings (server, transport, device ID, logout, safety number…).
    Settings,
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
enum AuthMsg {
    /// Authentication succeeded.
    Success {
        user_id: String,
        device_id: String,
        access_token: String,
        /// Full session including private keys — used to construct the Orchestrator.
        full_session: config::Session,
        /// When `Some`, this session must be persisted to disk (new/updated).
        pending_save: Option<config::Session>,
    },
    Failure(String),
}

/// Unified internal event type — all background tasks funnel through this.
pub(crate) enum InternalEvent {
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    Bridge(BridgeEvent),
}

/// Type alias referenced by `orchestrator_task` to send bridge events back to the UI.
pub(crate) type InternalEventProxy = InternalEvent;

/// Configuration derived from config file + CLI overrides.
/// Passed to `App::new()` at startup.
pub struct AppConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub headless: bool,
    pub pq_active: bool,
}

pub struct App {
    screen: Screen,
    onboarding: OnboardingScreen,
    device_link: DeviceLinkScreen,
    unlock_screen: UnlockScreen,
    /// Passphrase kept in memory (zeroized on drop) for re-encrypting on token refresh.
    session_passphrase: Option<Zeroizing<Vec<u8>>>,
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
    transport: TransportConfig,
    /// Authenticated user ID (set after successful auth).
    user_id: String,
    /// Whether Kyber-768 PQXDH is active for this session.
    pq_active: bool,
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
    /// Device ID of the authenticated device (set after successful auth).
    device_id: String,
    /// Bearer token for gRPC calls (set after successful auth, refreshed on token refresh).
    access_token: String,
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
        );

        Self {
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
            unlock_screen: UnlockScreen::new(UnlockMode::Unlock),
            session_passphrase: None,
            pending_session: None,
            no_encrypt: cfg.no_encrypt,
            focus: Focus::ContactList,
            chat_list,
            chat_view: ChatViewPane::new(initial_name),
            status: "Ready".into(),
            running: true,
            internal_tx,
            internal_rx,
            server_url: cfg.server_url,
            transport: cfg.transport,
            user_id: String::new(),
            pq_active: cfg.pq_active,
            connection: ConnectionState::default(),
            settings_screen,
            contact_search: ContactSearchScreen::new(),
            safety_number: None,
            orch_handle: None,
            stream_tx: None,
            device_id: String::new(),
            access_token: String::new(),
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
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::try_restore_session(&url).await {
                Ok(Some(r)) => {
                    let full = r.session.expect("try_restore_session always returns session");
                    AuthMsg::Success {
                        user_id: r.user_id,
                        device_id: r.device_id,
                        access_token: r.access_token,
                        full_session: full.clone(),
                        pending_save: None, // already saved inside try_restore_session
                    }
                }
                Ok(None) => AuthMsg::Failure("no_session".into()),
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(InternalEvent::Auth(msg));
        });
        self.screen = Screen::Connecting("Restoring session…".into());
    }

    /// Authenticate using a session already decrypted in memory (after Unlock screen).
    fn start_auth_restore_preloaded(&mut self, session: Session) {
        let tx = self.internal_tx.clone();
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &url).await {
                Ok(r) => {
                    let full = r.session.clone().expect("authenticate_saved_session always returns session");
                    AuthMsg::Success {
                        user_id: r.user_id,
                        device_id: r.device_id,
                        access_token: r.access_token,
                        full_session: full.clone(),
                        pending_save: r.session,
                    }
                }
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(InternalEvent::Auth(msg));
        });
        self.screen = Screen::Connecting("Authenticating…".into());
    }

    fn start_auth_register(&mut self, username: String) {
        let tx = self.internal_tx.clone();
        let url = self.server_url.clone();
        let name = if username.is_empty() {
            None
        } else {
            Some(username)
        };
        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&url, name.as_deref()).await {
                Ok(r) => {
                    let full = r.session.clone().expect("register_new_device always returns session");
                    AuthMsg::Success {
                        user_id: r.user_id,
                        device_id: r.device_id,
                        access_token: r.access_token,
                        full_session: full.clone(),
                        pending_save: r.session,
                    }
                }
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(InternalEvent::Auth(msg));
        });
        self.screen = Screen::Connecting("Solving proof-of-work, registering device…".into());
    }

    fn start_auth_link(&mut self, token: String) {
        let tx = self.internal_tx.clone();
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::link_existing_device(&url, &token).await {
                Ok(r) => {
                    let full = r.session.clone().expect("link_existing_device always returns session");
                    AuthMsg::Success {
                        user_id: r.user_id,
                        device_id: r.device_id,
                        access_token: r.access_token,
                        full_session: full.clone(),
                        pending_save: r.session,
                    }
                }
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(InternalEvent::Auth(msg));
        });
        self.screen = Screen::Connecting("Confirming device link…".into());
    }

    /// Handle a message arriving from a background task via the unified internal channel.
    fn handle_internal(&mut self, event: InternalEvent) {
        match event {
            InternalEvent::Auth(msg) => self.handle_auth_msg(msg),
            InternalEvent::TokenRefresh(msg) => self.handle_token_refresh_msg(msg),
            InternalEvent::Bridge(evt) => self.handle_bridge_event(evt),
        }
    }

    fn handle_auth_msg(&mut self, msg: AuthMsg) {
        match msg {
            AuthMsg::Success {
                user_id,
                device_id,
                access_token,
                full_session,
                pending_save,
            } => {
                self.status = format!("Connected as {}", user_id);
                self.user_id = user_id.clone();
                self.device_id = device_id.clone();
                self.access_token = access_token.clone();
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
                );

                // Start the E2EE Orchestrator in the background.
                self.start_orchestrator(full_session.clone(), user_id.clone(), device_id.clone(), access_token.clone());

                if let Some(session) = pending_save {
                    self.start_token_refresh(&session);

                    if let Some(ref passphrase) = self.session_passphrase {
                        match config::save_session_encrypted(&session, passphrase) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => self.screen = Screen::AuthError(format!("Save failed: {e}")),
                        }
                    } else if self.no_encrypt {
                        match config::save_session(&session) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => self.screen = Screen::AuthError(format!("Save failed: {e}")),
                        }
                    } else {
                        self.pending_session = Some(session);
                        self.unlock_screen.reset_for_mode(UnlockMode::SetNew);
                        self.screen = Screen::SetPassphrase;
                    }
                } else {
                    self.screen = Screen::Main;
                }
            }
            AuthMsg::Failure(msg) if msg == "no_session" => {
                self.screen = Screen::Onboarding;
            }
            AuthMsg::Failure(msg) => {
                let is_startup_restore = matches!(self.screen, Screen::Connecting(_))
                    && self.onboarding.username.is_empty();
                if is_startup_restore {
                    self.screen = Screen::Onboarding;
                } else {
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
        access_token: String,
    ) {
        use construct_core::{
            crypto::{client_api::ClassicClient, suites::classic::ClassicSuiteProvider},
            orchestration::orchestrator::Orchestrator,
        };
        use crate::orchestrator_task::spawn_orchestrator_task;
        use crate::streaming::{spawn_stream_worker, StreamCmd, StreamEvent};
        use crate::storage::Storage;

        // Decode private keys from hex.
        let identity_secret = match hex::decode(&session.identity_key_hex) {
            Ok(v) => v,
            Err(e) => { self.status = format!("Orchestrator key decode error: {e}"); return; }
        };
        let signing_secret = match hex::decode(&session.signing_key_hex) {
            Ok(v) => v,
            Err(e) => { self.status = format!("Orchestrator key decode error: {e}"); return; }
        };
        let spk_secret = match hex::decode(&session.spk_key_hex) {
            Ok(v) => v,
            Err(e) => { self.status = format!("Orchestrator key decode error: {e}"); return; }
        };
        let spk_sig = match hex::decode(&session.spk_sig_hex) {
            Ok(v) => v,
            Err(e) => { self.status = format!("Orchestrator key decode error: {e}"); return; }
        };

        // Construct the ClassicClient.
        let client = match ClassicClient::<ClassicSuiteProvider>::from_keys(
            identity_secret,
            signing_secret,
            spk_secret,
            spk_sig,
        ) {
            Ok(c) => c,
            Err(e) => { self.status = format!("Orchestrator init error: {e}"); return; }
        };

        let orchestrator = Orchestrator::new(client, user_id.clone());

        let storage = match Storage::open() {
            Ok(s) => s,
            Err(e) => { self.status = format!("Storage open error: {e}"); return; }
        };

        // Spawn the gRPC stream worker.
        let (stream_tx, mut stream_rx) = spawn_stream_worker(
            self.server_url.clone(),
            access_token.clone(),
            vec![],
        );
        self.stream_tx = Some(stream_tx.clone());

        // Spawn the Orchestrator actor task.
        let orch_handle = spawn_orchestrator_task(
            orchestrator,
            storage,
            stream_tx,
            self.internal_tx.clone(),
            self.server_url.clone(),
            access_token,
            user_id,
            device_id,
        );

        // Fire AppLaunched to trigger session GC / prewarm sweep.
        orch_handle.send(construct_core::orchestration::actions::IncomingEvent::AppLaunched);
        self.orch_handle = Some(orch_handle.clone());

        // Relay stream events to the Orchestrator.
        let orch_tx = orch_handle.tx.clone();
        let internal_tx = self.internal_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = stream_rx.recv().await {
                match event {
                    StreamEvent::Message(envelope) => {
                        // Unpack the wire payload to extract header fields.
                        if let Ok(decoded) = construct_core::wire_payload::unpack(&envelope.encrypted_payload) {
                            let from = envelope.sender
                                .as_ref()
                                .map(|s| s.user_id.clone())
                                .unwrap_or_default();
                            let message_id = match &envelope.message_id_type {
                                Some(crate::grpc::core_types::envelope::MessageIdType::MessageId(id)) => id.clone(),
                                _ => String::new(),
                            };
                            let content_type = envelope.content_type as u8;
                            let is_control = matches!(
                                content_type,
                                21 | 24 // SESSION_RESET | SESSION_RESET_INIT
                            );
                            let _ = orch_tx.send(
                                construct_core::orchestration::actions::IncomingEvent::MessageReceived {
                                    message_id,
                                    from,
                                    data: envelope.encrypted_payload.clone(),
                                    msg_num: decoded.message_number,
                                    kem_ct: decoded.kem_ciphertext.unwrap_or_default(),
                                    otpk_id: decoded.one_time_prekey_id,
                                    is_control,
                                    content_type,
                                },
                            );
                        }
                    }
                    StreamEvent::Ack(id) => {
                        let _ = orch_tx.send(
                            construct_core::orchestration::actions::IncomingEvent::AckReceived {
                                message_id: id,
                            },
                        );
                    }
                    StreamEvent::Connected => {
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::Error("Stream connected".into()),
                        ));
                        let _ = orch_tx.send(
                            construct_core::orchestration::actions::IncomingEvent::NetworkReconnected,
                        );
                    }
                    StreamEvent::Disconnected => {
                        let _ = internal_tx.send(InternalEvent::Bridge(
                            crate::bridge::BridgeEvent::Error("Stream disconnected".into()),
                        ));
                    }
                }
            }
        });
    }

    fn start_token_refresh(&mut self, session: &Session) {
        let tx = self.internal_tx.clone();
        let mut rx = crate::bridge::spawn_token_refresh(
            self.server_url.clone(),
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
                let updated = self.build_updated_session(access_token, refresh_token, expires_at);
                if let Some(session) = updated {
                    self.persist_session_background(session);
                }
            }
            TokenRefreshMsg::Failed(e) => {
                self.status = format!("Token refresh failed: {e}");
            }
        }
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
            BridgeEvent::Error(e) => {
                self.status = format!("Bridge error: {e}");
            }
        }
    }

    /// Build an updated Session from refreshed tokens (if we have a current session in memory).
    /// Returns None if we cannot reconstruct the session (e.g. no saved passphrase to re-load).
    fn build_updated_session(
        &self,
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    ) -> Option<Session> {
        // Try to load the current session from disk and patch the tokens.
        if let Some(ref passphrase) = self.session_passphrase
            && let Ok(Some(mut session)) = config::load_session_encrypted(passphrase)
        {
            session.access_token = access_token;
            session.refresh_token = refresh_token;
            session.expires_at = expires_at;
            return Some(session);
        }
        if self.no_encrypt
            && let Ok(Some(mut session)) = config::load_session()
        {
            session.access_token = access_token;
            session.refresh_token = refresh_token;
            session.expires_at = expires_at;
            return Some(session);
        }
        None
    }

    fn persist_session_background(&mut self, session: Session) {
        // Restart token refresh with new expiry.
        self.start_token_refresh(&session);

        if let Some(ref passphrase) = self.session_passphrase {
            let _ = config::save_session_encrypted(&session, passphrase);
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
            self.screen = Screen::Onboarding;
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
                if username.is_empty() {
                    self.onboarding.status = Some("Enter a username to continue".into());
                    self.onboarding.is_error = true;
                } else {
                    self.onboarding.status = None;
                    self.start_auth_register(username);
                }
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
                match config::load_session_encrypted(&passphrase) {
                    Ok(Some(session)) => {
                        self.session_passphrase = Some(passphrase);
                        self.start_auth_restore_preloaded(session);
                    }
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
                    match config::save_session_encrypted(&session, &passphrase) {
                        Ok(()) => {
                            self.session_passphrase = Some(passphrase);
                            self.screen = Screen::Main;
                        }
                        Err(e) => {
                            self.pending_session = Some(session);
                            self.unlock_screen.set_error(format!("Save failed: {e}"));
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
        if is_quit(&key) && self.focus != Focus::Compose {
            self.running = false;
            return;
        }
        match self.focus {
            Focus::ContactList => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.chat_list.next(),
                KeyCode::Up | KeyCode::Char('k') => self.chat_list.prev(),
                KeyCode::Enter | KeyCode::Tab => {
                    if let Some(c) = self.chat_list.selected_contact() {
                        self.chat_view.contact_name = c.display_name.clone();
                        self.chat_view.messages.clear();
                    }
                    self.set_focus(Focus::ChatView);
                }
                // Open settings
                KeyCode::Char('s') if key.modifiers == crossterm::event::KeyModifiers::NONE => {
                    self.screen = Screen::Settings;
                }
                // Add contact / search
                KeyCode::Char('n') if key.modifiers == crossterm::event::KeyModifiers::NONE => {
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
                        if let Some(ref orch) = self.orch_handle {
                            if let Some(contact) = self.chat_list.selected_contact() {
                                orch.send(construct_core::orchestration::actions::IncomingEvent::OutgoingMessage {
                                    contact_id: contact.id.clone(),
                                    message_id: message_id.clone(),
                                    plaintext_utf8: text.clone(),
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
                        SettingsAction::Back => self.screen = Screen::Main,
                        SettingsAction::Logout => self.do_logout(),
                        SettingsAction::ShowSafetyNumber => {
                            let contact_name = self
                                .chat_list
                                .selected_contact()
                                .map(|c| c.display_name.clone())
                                .unwrap_or_else(|| "Unknown".into());
                            // TODO: replace with real identity keys from Orchestrator
                            let our_key = [0u8; 32];
                            let their_key = [1u8; 32];
                            self.safety_number =
                                Some(SafetyNumberScreen::new(contact_name, &our_key, &their_key));
                            self.screen = Screen::SafetyNumber;
                        }
                        SettingsAction::ExportKeys => {
                            // TODO: export identity keys to file
                            self.status = "Key export not yet implemented".into();
                        }
                    }
                }
            }
            // Shortcut keys
            KeyCode::Char('l') | KeyCode::Char('L') => self.do_logout(),
            KeyCode::Char('s') | KeyCode::Char('S') => {
                // Trigger ShowSafetyNumber directly
                let contact_name = self
                    .chat_list
                    .selected_contact()
                    .map(|c| c.display_name.clone())
                    .unwrap_or_else(|| "Unknown".into());
                let our_key = [0u8; 32];
                let their_key = [1u8; 32];
                self.safety_number =
                    Some(SafetyNumberScreen::new(contact_name, &our_key, &their_key));
                self.screen = Screen::SafetyNumber;
            }
            _ => {}
        }
    }

    fn handle_contact_search(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.contact_search.reset();
                self.screen = Screen::Main;
            }
            KeyCode::Up | KeyCode::Char('k') => self.contact_search.prev(),
            KeyCode::Down | KeyCode::Char('j') => self.contact_search.next(),
            KeyCode::Enter => {
                if self.contact_search.results.is_empty() {
                    // No results yet — trigger search
                    let query = self.contact_search.query.trim().to_string();
                    if !query.is_empty() {
                        self.contact_search.searching = true;
                        // TODO: dispatch gRPC SearchUsers(query) → call set_results / set_error
                        self.contact_search
                            .set_error("Search not yet connected to gRPC");
                    }
                } else {
                    // Results visible — Enter = search again
                    let query = self.contact_search.query.trim().to_string();
                    if !query.is_empty() {
                        self.contact_search.searching = true;
                        self.contact_search
                            .set_error("Search not yet connected to gRPC");
                    }
                }
            }
            KeyCode::Tab => self.contact_search.next(),
            KeyCode::BackTab => self.contact_search.prev(),
            // Ctrl+A — add selected contact
            KeyCode::Char('a') if key.modifiers == crossterm::event::KeyModifiers::CONTROL => {
                if let Some(result) = self.contact_search.selected().cloned() {
                    // TODO: dispatch gRPC AddContact(result.user_id)
                    self.status =
                        format!("Add contact '{}' — not yet implemented", result.username);
                    self.contact_search.reset();
                    self.screen = Screen::Main;
                }
            }
            KeyCode::Backspace => self.contact_search.pop_char(),
            KeyCode::Char(c) => self.contact_search.push_char(c),
            _ => {}
        }
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
        self.session_passphrase = None;
        self.pending_session = None;
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
        );
        self.onboarding = OnboardingScreen::new();
        self.screen = Screen::Onboarding;
    }

    // ── Rendering ───────────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        if matches!(self.screen, Screen::Main) {
            return self.render_main(frame);
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
        if matches!(self.screen, Screen::DeviceLink) {
            return frame.render_widget(&self.device_link, area);
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

    fn render_spinner(&self, frame: &mut Frame, msg: &str) {
        let area = frame.area();
        let y = area.height.saturating_sub(2);
        let line = Line::from(vec![
            Span::styled("  ⠋ ", Style::default().fg(Color::Cyan)),
            Span::styled(msg, Style::default().fg(Color::White)),
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
        let y = area.height.saturating_sub(2);
        let display = format!("  ✗ {}  (any key to retry)", msg);
        let line = Line::from(Span::styled(display, Style::default().fg(Color::Red)));
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

    fn render_main(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let root = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

        let title = Paragraph::new(Line::from(vec![
            Span::styled(" ◆ Construct ", Style::default().fg(Color::Cyan)),
            Span::styled("TUI", Style::default().fg(Color::White)),
            Span::raw("  "),
            Span::styled(
                "Tab=switch  ↑↓/jk=nav  i=compose  s=settings  n=add node  q=quit",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        frame.render_widget(title, root[0]);

        let body = Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(root[1]);
        frame.render_widget(&mut self.chat_list, body[0]);
        frame.render_widget(&mut self.chat_view, body[1]);

        let status_bar = StatusBar {
            connection: &self.connection,
            status_text: &self.status,
            unread_count: 0,
            pq_active: self.pq_active,
        };
        frame.render_widget(status_bar, root[2]);
    }
}

fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
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
