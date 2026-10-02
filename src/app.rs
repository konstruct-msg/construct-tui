//! The terminal front end: screens, focus, keys and drawing. What the program *does* is the
//! client layer (`crate::client`); this file turns keys into calls on it and its events into
//! what is on screen.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use tokio::sync::mpsc;

use crate::{
    bridge::BridgeEvent,
    client::{AuthMsg, AuthOutcome, Client, ClientConfig, ClientEvent, FindStarted},
    config::{self, SessionState, TransportConfig},
    event::{Event, EventHandler, is_quit},
    screens::onboarding::OnboardingField,
    screens::{
        ChatListPane, ChatViewPane, ConnectionState, ContactSearchScreen, DeviceLinkScreen,
        OnboardingScreen, RegistrationScreen, SafetyNumberScreen, SettingsAction, SettingsScreen,
        StatusBar, UnlockMode, UnlockScreen,
        chat_list::Contact,
        chat_view::{ChatMessage, MessageKind},
        qr_widget::QrWidget,
    },
    storage::StoredContact,
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
    client: Client,
    /// Everything the client reports back.
    client_rx: mpsc::UnboundedReceiver<ClientEvent>,
    /// Spinner ticks for the registration screen — a front-end concern, not the client's.
    tick_tx: mpsc::UnboundedSender<()>,
    tick_rx: mpsc::UnboundedReceiver<()>,
    screen: Screen,
    onboarding: OnboardingScreen,
    device_link: DeviceLinkScreen,
    unlock_screen: UnlockScreen,
    registration: RegistrationScreen,
    /// Handle to the spinner ticker task — present only while Screen::Registering is active.
    ticker_handle: Option<tokio::task::AbortHandle>,
    focus: Focus,
    chat_list: ChatListPane,
    chat_view: ChatViewPane,
    status: String,
    running: bool,
    theme: ThemeMode,
    /// Live connection state shown in the status bar.
    connection: ConnectionState,
    settings_screen: SettingsScreen,
    contact_search: ContactSearchScreen,
    /// Safety number widget for the currently selected contact.
    safety_number: Option<SafetyNumberScreen>,
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

        let (client_tx, client_rx) = mpsc::unbounded_channel();
        let (tick_tx, tick_rx) = mpsc::unbounded_channel();
        let client = Client::new(
            ClientConfig {
                server_url: cfg.server_url,
                transport: cfg.transport,
                no_encrypt: cfg.no_encrypt,
                pq_active: cfg.pq_active,
            },
            client_tx,
        );
        let settings_screen = fresh_settings_screen(&client);

        Self {
            client,
            client_rx,
            tick_tx,
            tick_rx,
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
            unlock_screen: UnlockScreen::new(UnlockMode::Unlock),
            registration: RegistrationScreen::new(),
            ticker_handle: None,
            focus: Focus::ContactList,
            chat_list,
            chat_view: ChatViewPane::new(initial_name),
            status: "Ready".into(),
            running: true,
            theme: cfg.theme,
            connection: ConnectionState::default(),
            settings_screen,
            contact_search: ContactSearchScreen::new(),
            safety_number: None,
            delete_confirm: None,
        }
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        self.startup_check();

        let mut events = EventHandler::new();
        while self.running {
            terminal.draw(|frame| self.render(frame))?;

            // Block until a key, a client event or a tick arrives — zero CPU when idle.
            tokio::select! {
                Some(event) = events.next() => self.handle_event(event),
                Some(event) = self.client_rx.recv() => self.handle_client_event(event),
                Some(()) = self.tick_rx.recv() => {
                    if matches!(self.screen, Screen::Registering) {
                        self.registration.tick();
                    }
                }
            }
        }
        Ok(())
    }

    // ── Startup and authentication ──────────────────────────────────────────────

    /// Detect session state on disk and set the initial screen accordingly.
    fn startup_check(&mut self) {
        match self.client.stored_session_state() {
            SessionState::Encrypted => self.screen = Screen::Unlock,
            SessionState::Plaintext => {
                self.client.restore_from_disk();
                self.screen = Screen::Connecting("Restoring session…".into());
            }
            SessionState::None => self.screen = Screen::Onboarding,
        }
    }

    fn start_registration(&mut self, username: String) {
        self.client.register(username);
        self.registration = RegistrationScreen::new();
        self.start_ticker();
        self.screen = Screen::Registering;
    }

    /// Spawn a background task that ticks every 80ms for the registration spinner.
    fn start_ticker(&mut self) {
        self.stop_ticker();
        let tx = self.tick_tx.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
                if tx.send(()).is_err() {
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

    fn handle_client_event(&mut self, event: ClientEvent) {
        match event {
            ClientEvent::Auth(msg) => {
                if matches!(self.screen, Screen::Registering) {
                    self.stop_ticker();
                    // Show all steps as done before the outcome replaces the screen.
                    self.registration.active_step = crate::screens::registration::STEPS.len();
                }
                self.handle_auth_msg(msg);
            }
            ClientEvent::TokenRefresh(msg) => {
                if let Err(status) = self.client.apply_token_refresh(msg) {
                    self.status = status;
                }
            }
            ClientEvent::Bridge(evt) => self.handle_bridge_event(evt),
            ClientEvent::ContactSearchResult(results) => self.contact_search.set_results(results),
            ClientEvent::ContactSearchError(msg) => {
                let shown = if msg.contains("rate limit") || msg.contains("8:") {
                    "Search limit (5/hour). Wait, then Enter once.".to_string()
                } else {
                    msg
                };
                self.contact_search.set_error(shown);
            }
            ClientEvent::InviteAccepted { user_id, username } => {
                self.finish_add_contact(user_id, username);
            }
            ClientEvent::RegistrationStep(step) => self.registration.advance(step.index()),
            ClientEvent::StreamAuthRequired => self.client.refresh_token_now(),
        }
    }

    fn handle_auth_msg(&mut self, msg: AuthMsg) {
        match msg {
            AuthMsg::Success(success) => {
                let outcome = self.client.apply_auth_success(*success);
                self.status = format!("Connected as {}", self.client.user_id());
                self.connection = ConnectionState::Connected {
                    transport: self.client.transport_label().into(),
                    latency_ms: None,
                };
                self.settings_screen.update(
                    self.client.server_url(),
                    self.client.transport_label(),
                    self.client.device_id(),
                    self.client.user_id(),
                    self.client.pq_active(),
                    self.client.signing_key_hex(),
                );
                match outcome {
                    AuthOutcome::Ready(contacts) => self.enter_main(contacts),
                    AuthOutcome::NeedsPassphrase => {
                        self.unlock_screen.reset_for_mode(UnlockMode::SetNew);
                        self.screen = Screen::SetPassphrase;
                    }
                    AuthOutcome::Failed(e) => self.screen = Screen::AuthError(e),
                }
            }
            AuthMsg::Failure(msg) if msg == "no_session" => {
                self.stop_ticker();
                self.screen = Screen::Onboarding;
            }
            AuthMsg::Failure(msg) => {
                self.stop_ticker();
                // Auto-restore on startup (plaintext path): no passphrase has been entered, so
                // show Onboarding — the user likely logged out or the session file is stale.
                // Unlock path: the passphrase opened the session, so this is a server/network
                // error; show it rather than silently landing on onboarding.
                let is_auto_restore = matches!(self.screen, Screen::Connecting(_))
                    && !self.client.has_session_key()
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

    /// The client is running: show its contacts and the chat screen.
    fn enter_main(&mut self, contacts: Vec<StoredContact>) {
        self.chat_list.set_contacts(
            contacts
                .into_iter()
                .map(|c| Contact {
                    id: c.user_id,
                    display_name: c.display_name,
                    unread: 0,
                    last_message: None,
                })
                .collect(),
        );
        self.screen = Screen::Main;
    }

    fn handle_bridge_event(&mut self, evt: BridgeEvent) {
        match evt {
            BridgeEvent::NewMessage { text, .. } => {
                self.chat_view.messages.push(ChatMessage {
                    id: uuid::Uuid::new_v4().to_string(),
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
                        transport: self.client.transport_label().into(),
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
            // A session key means the user came from Unlock — go back there to retry.
            // Otherwise it was an auto-restore or registration error: Onboarding.
            if self.client.has_session_key() {
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
        if matches!(self.screen, Screen::SafetyNumber | Screen::IdentityQr) {
            // Any key goes back to settings.
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
                self.start_registration(username);
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
                match self.client.unlock(&passphrase) {
                    Ok(()) => self.screen = Screen::Connecting("Authenticating…".into()),
                    Err(e) => self.unlock_screen.set_error(e),
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
                match self.client.set_passphrase(&passphrase) {
                    Ok(Some(contacts)) => self.enter_main(contacts),
                    Ok(None) => {}
                    Err(e) => self.unlock_screen.set_error(e),
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
                    self.client.link_device(token);
                    self.screen = Screen::Connecting("Confirming device link…".into());
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
                KeyCode::Char('x') if key.modifiers == KeyModifiers::NONE => {
                    if let Some(c) = self.chat_list.selected_contact() {
                        self.delete_confirm = Some(c.id.clone());
                    }
                }
                KeyCode::Enter | KeyCode::Tab => {
                    self.open_selected_chat();
                    self.set_focus(Focus::ChatView);
                }
                // Open settings
                KeyCode::Char('s') if key.modifiers == KeyModifiers::NONE => {
                    self.screen = Screen::Settings;
                }
                // Add contact / search (`a` as documented, `n` as the old binding)
                KeyCode::Char('a' | 'n') if key.modifiers == KeyModifiers::NONE => {
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
                        let message_id = match self.chat_list.selected_contact() {
                            Some(contact) => self.client.send_text(&contact.id, &text),
                            None => uuid::Uuid::new_v4().to_string(),
                        };
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

    /// Show the selected person's last 50 messages.
    fn open_selected_chat(&mut self) {
        let Some(c) = self.chat_list.selected_contact() else {
            return;
        };
        self.chat_view.contact_name = c.display_name.clone();
        self.chat_view.messages.clear();
        for msg in self.client.history(&c.id, 50) {
            let kind = if msg.direction == "sent" {
                MessageKind::Sent
            } else {
                MessageKind::Received
            };
            let secs = msg.timestamp_ms / 1000;
            self.chat_view.messages.push(ChatMessage {
                id: msg.id,
                kind,
                text: msg.text,
                time: format!("{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60),
            });
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
                        SettingsAction::ShowSafetyNumber => self.open_safety_number_screen(),
                        SettingsAction::ExportKeys => self.export_identity_key(),
                        SettingsAction::ShowMyQr => self.screen = Screen::IdentityQr,
                    }
                }
            }
            // Shortcut keys
            KeyCode::Char('l') | KeyCode::Char('L') => self.do_logout(),
            KeyCode::Char('q') | KeyCode::Char('Q') => self.screen = Screen::IdentityQr,
            KeyCode::Char('s') | KeyCode::Char('S') => self.open_safety_number_screen(),
            KeyCode::Char('t') | KeyCode::Char('T') => self.cycle_theme(),
            _ => {}
        }
    }

    /// The theme is a front-end preference, stored in the config file.
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
        match self.client.safety_number_keys(&contact.id) {
            Ok((ours, theirs)) => {
                self.safety_number = Some(SafetyNumberScreen::new(
                    contact.display_name.clone(),
                    &ours,
                    &theirs,
                ));
                self.screen = Screen::SafetyNumber;
            }
            Err(e) => self.status = e,
        }
    }

    fn export_identity_key(&mut self) {
        self.status = match self.client.export_identity_key() {
            Ok(path) => format!("Key exported → {path}"),
            Err(e) => e,
        };
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
            KeyCode::Char('a') if key.modifiers == KeyModifiers::CONTROL => {
                self.add_selected_search_result();
            }
            KeyCode::Backspace => self.contact_search.pop_char(),
            KeyCode::Char(c) => self.contact_search.push_char(c),
            _ => {}
        }
    }

    fn submit_contact_search(&mut self) {
        match self.client.find_contact(&self.contact_search.query) {
            Ok(FindStarted::UsernameSearch) => self.contact_search.searching = true,
            Ok(FindStarted::InviteRedemption) => {
                self.contact_search.searching = true;
                self.contact_search.status = Some("Redeeming invite…".into());
            }
            Err(e) => self.contact_search.set_error(e),
        }
    }

    fn add_selected_search_result(&mut self) {
        let Some(result) = self.contact_search.selected().cloned() else {
            return;
        };
        self.finish_add_contact(result.user_id, result.username);
    }

    fn finish_add_contact(&mut self, user_id: String, username: String) {
        self.client.add_contact(&user_id, &username);
        self.chat_list.add_contact(Contact {
            id: user_id,
            display_name: username.clone(),
            unread: 0,
            last_message: None,
        });
        self.status = format!("Added @{username}");
        self.contact_search.reset();
        self.screen = Screen::Main;
    }

    /// Execute a confirmed contact deletion: remove from storage, chat list, and active view.
    fn confirm_delete(&mut self) {
        let Some(peer_id) = self.delete_confirm.take() else {
            return;
        };
        if let Err(e) = self.client.delete_contact(&peer_id) {
            self.status = e;
            return;
        }
        if let Some(i) = self.chat_list.contacts.iter().position(|c| c.id == peer_id) {
            self.chat_list.remove_at(i);
        }
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
        if let Err(e) = self.client.logout() {
            self.status = e;
            return;
        }
        self.connection = ConnectionState::Disconnected;
        self.contact_search.reset();
        self.chat_list = ChatListPane::new();
        self.chat_view = ChatViewPane::new(String::new());
        self.settings_screen = fresh_settings_screen(&self.client);
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
            let user_id = self.client.user_id().to_string();
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
            pq_active: self.client.pq_active(),
            theme: self.theme,
        };
        frame.render_widget(status_bar, root[2]);
    }
}

fn fresh_settings_screen(client: &Client) -> SettingsScreen {
    SettingsScreen::new(
        client.server_url(),
        client.transport_label(),
        "—",
        "—",
        client.pq_active(),
        "",
    )
}

fn current_time_hhmm() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}", (secs % 86400) / 3600, (secs % 3600) / 60)
}
