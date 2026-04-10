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
    config::{self, Session, SessionState},
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
    /// `pending_save` is Some when a new session was created (register/link) or when an
    /// encrypted session was restored (updated tokens) — the App handles persisting it.
    /// `None` for plaintext restores (handled inside `try_restore_session`).
    Success { user_id: String, pending_save: Option<Session> },
    Failure(String),
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
    auth_rx: Option<mpsc::Receiver<AuthMsg>>,
    server_url: String,
}

impl App {
    pub fn new() -> Self {
        let chat_list = ChatListPane::new();
        let initial_name = chat_list
            .selected_contact()
            .map(|c| c.display_name.clone())
            .unwrap_or_default();

        let server_url = config::load_config()
            .map(|c| c.server)
            .unwrap_or_else(|_| "https://ams.konstruct.cc:443".into());

        // Respect CONSTRUCT_NO_ENCRYPT env var for headless/systemd deployments.
        let no_encrypt = std::env::var("CONSTRUCT_NO_ENCRYPT").is_ok();

        Self {
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
            unlock_screen: UnlockScreen::new(UnlockMode::Unlock),
            session_passphrase: None,
            pending_session: None,
            no_encrypt,
            focus: Focus::ContactList,
            chat_list,
            chat_view: ChatViewPane::new(initial_name),
            status: "Ready".into(),
            running: true,
            auth_rx: None,
            server_url,
        }
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Detect session state and set initial screen / kick off auth.
        self.startup_check();

        let mut events = EventHandler::new();
        while self.running {
            // Poll for auth task completion
            self.poll_auth();

            terminal.draw(|frame| self.render(frame))?;

            // Short timeout so we can repaint while auth is running
            tokio::select! {
                Some(event) = events.next() => self.handle_event(event),
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
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
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::try_restore_session(&url).await {
                Ok(Some(r)) => AuthMsg::Success { user_id: r.user_id, pending_save: None },
                Ok(None) => AuthMsg::Failure("no_session".into()),
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Restoring session…".into());
    }

    /// Authenticate using a session already decrypted in memory (after Unlock screen).
    fn start_auth_restore_preloaded(&mut self, session: Session) {
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &url).await {
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Authenticating…".into());
    }

    fn start_auth_register(&mut self, username: String) {
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        let name = if username.is_empty() { None } else { Some(username) };
        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&url, name.as_deref()).await {
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Solving proof-of-work, registering device…".into());
    }

    fn start_auth_link(&mut self, token: String) {
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::link_existing_device(&url, &token).await {
                Ok(r) => AuthMsg::Success { user_id: r.user_id, pending_save: r.session },
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Confirming device link…".into());
    }

    fn poll_auth(&mut self) {
        let Some(rx) = self.auth_rx.as_mut() else { return };
        match rx.try_recv() {
            Ok(AuthMsg::Success { user_id, pending_save }) => {
                self.auth_rx = None;
                self.status = format!("Connected as {}", user_id);

                if let Some(session) = pending_save {
                    if let Some(ref passphrase) = self.session_passphrase {
                        // Encrypted session restore — re-save with updated tokens.
                        match config::save_session_encrypted(&session, passphrase) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => {
                                self.screen = Screen::AuthError(format!("Save failed: {e}"))
                            }
                        }
                    } else if self.no_encrypt {
                        // Headless / --no-encrypt: save plaintext.
                        match config::save_session(&session) {
                            Ok(()) => self.screen = Screen::Main,
                            Err(e) => {
                                self.screen = Screen::AuthError(format!("Save failed: {e}"))
                            }
                        }
                    } else {
                        // New session — ask the user to set a passphrase.
                        self.pending_session = Some(session);
                        self.unlock_screen.reset_for_mode(UnlockMode::SetNew);
                        self.screen = Screen::SetPassphrase;
                    }
                } else {
                    // Plaintext restore — session already persisted by try_restore_session.
                    self.screen = Screen::Main;
                }
            }
            Ok(AuthMsg::Failure(msg)) if msg == "no_session" => {
                self.auth_rx = None;
                self.screen = Screen::Onboarding;
            }
            Ok(AuthMsg::Failure(msg)) => {
                self.auth_rx = None;
                let is_startup_restore = matches!(self.screen, Screen::Connecting(_))
                    && self.onboarding.username.is_empty();
                if is_startup_restore {
                    self.screen = Screen::Onboarding;
                } else {
                    self.screen = Screen::AuthError(msg);
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.auth_rx = None;
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
