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
    screens::{ChatListPane, ChatViewPane, DeviceLinkScreen, OnboardingScreen, UnlockMode, UnlockScreen},
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
    Success { user_id: String, pending_save: Option<Session> },
    Failure(String),
}

/// Unified internal event type — all background tasks funnel through this.
enum InternalEvent {
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    Bridge(BridgeEvent),
}

/// Configuration derived from config file + CLI overrides.
/// Passed to `App::new()` at startup.
pub struct AppConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub headless: bool,
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
}

impl App {
    pub fn new(cfg: AppConfig) -> Self {
        let chat_list = ChatListPane::new();
        let initial_name = chat_list
            .selected_contact()
            .map(|c| c.display_name.clone())
            .unwrap_or_default();

        let (internal_tx, internal_rx) = mpsc::unbounded_channel();

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
                Ok(Some(r)) => AuthMsg::Success { user_id: r.user_id, pending_save: None },
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
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(InternalEvent::Auth(msg));
        });
        self.screen = Screen::Connecting("Authenticating…".into());
    }

    fn start_auth_register(&mut self, username: String) {
        let tx = self.internal_tx.clone();
        let url = self.server_url.clone();
        let name = if username.is_empty() { None } else { Some(username) };
        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&url, name.as_deref()).await {
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
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
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
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
            AuthMsg::Success { user_id, pending_save } => {
                self.status = format!("Connected as {}", user_id);

                if let Some(session) = pending_save {
                    self.start_token_refresh(&session);

                    if let Some(ref passphrase) = self.session_passphrase {
                        match config::save_session_encrypted(&session, passphrase) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => {
                                self.screen = Screen::AuthError(format!("Save failed: {e}"))
                            }
                        }
                    } else if self.no_encrypt {
                        match config::save_session(&session) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => {
                                self.screen = Screen::AuthError(format!("Save failed: {e}"))
                            }
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
            TokenRefreshMsg::Refreshed { access_token, refresh_token, expires_at } => {
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
            BridgeEvent::NewMessage { peer_id: _, message_id: _, text, timestamp_ms: _ } => {
                use crate::screens::chat_view::{ChatMessage, MessageKind};
                self.chat_view.messages.push(ChatMessage {
                    id: generate_message_id(),
                    kind: MessageKind::Received,
                    text,
                    time: current_time_hhmm(),
                });
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
        if let Some(ref passphrase) = self.session_passphrase {
            if let Ok(Some(mut session)) = config::load_session_encrypted(passphrase) {
                session.access_token = access_token;
                session.refresh_token = refresh_token;
                session.expires_at = expires_at;
                return Some(session);
            }
        }
        if self.no_encrypt {
            if let Ok(Some(mut session)) = config::load_session() {
                session.access_token = access_token;
                session.refresh_token = refresh_token;
                session.expires_at = expires_at;
                return Some(session);
            }
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
                    Err(_) => self.unlock_screen.set_error("Wrong passphrase or corrupted session"),
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
                    self.device_link.set_status("Paste the link token first", true);
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
                _ => {}
            },
            Focus::ChatView => match key.code {
                KeyCode::Tab | KeyCode::Char('i') => self.set_focus(Focus::Compose),
                KeyCode::BackTab => self.set_focus(Focus::ContactList),
                KeyCode::Esc => self.set_focus(Focus::ContactList),
                _ => {}
            },
            Focus::Compose => match key.code {
                KeyCode::Esc => self.set_focus(Focus::ChatView),
                KeyCode::Enter => {
                    let text = self.chat_view.take_compose();
                    if !text.trim().is_empty() {
                        use crate::screens::chat_view::{ChatMessage, MessageKind};
                        self.chat_view.messages.push(ChatMessage {
                            id: generate_message_id(),
                            kind: MessageKind::Sent,
                            text,
                            time: current_time_hhmm(),
                        });
                        self.status = "Message queued".into();
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

    // ── Rendering ───────────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        if matches!(self.screen, Screen::Main) {
            return self.render_main(frame);
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
                "Tab=switch  ↑↓/jk=navigate  i=compose  Esc=back  q=quit",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        frame.render_widget(title, root[0]);

        let body = Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(root[1]);
        frame.render_widget(&mut self.chat_list, body[0]);
        frame.render_widget(&mut self.chat_view, body[1]);

        let status = Paragraph::new(Line::from(vec![
            Span::styled(" ● ", Style::default().fg(Color::Green)),
            Span::raw(&self.status),
        ]));
        frame.render_widget(status, root[2]);
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
