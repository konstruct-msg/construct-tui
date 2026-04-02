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

use crate::{
    config::load_config,
    event::{Event, EventHandler, is_quit},
    screens::onboarding::OnboardingField,
    screens::{ChatListPane, ChatViewPane, DeviceLinkScreen, OnboardingScreen},
    tui::Tui,
};

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    /// Checking for saved session on startup.
    Startup,
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

/// Messages sent from the background auth task back to the UI event loop.
#[derive(Debug)]
enum AuthMsg {
    Success { user_id: String },
    Failure(String),
}

pub struct App {
    screen: Screen,
    onboarding: OnboardingScreen,
    device_link: DeviceLinkScreen,
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

        let server_url = load_config()
            .map(|c| c.server)
            .unwrap_or_else(|_| "https://ams.konstruct.cc:443".into());

        Self {
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
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
        // On startup: try to restore saved session
        self.start_auth_restore();

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

    fn start_auth_restore(&mut self) {
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::try_restore_session(&url).await {
                Ok(Some(r)) => AuthMsg::Success { user_id: r.user_id },
                Ok(None) => AuthMsg::Failure("no_session".into()),
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Restoring session…".into());
    }

    fn start_auth_register(&mut self, username: String) {
        let (tx, rx) = mpsc::channel(1);
        self.auth_rx = Some(rx);
        let url = self.server_url.clone();
        let name = if username.is_empty() {
            None
        } else {
            Some(username)
        };
        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&url, name.as_deref()).await {
                Ok(r) => AuthMsg::Success { user_id: r.user_id },
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
                Ok(r) => AuthMsg::Success { user_id: r.user_id },
                Err(e) => AuthMsg::Failure(e.to_string()),
            };
            let _ = tx.send(msg).await;
        });
        self.screen = Screen::Connecting("Confirming device link…".into());
    }

    fn poll_auth(&mut self) {
        let Some(rx) = self.auth_rx.as_mut() else {
            return;
        };
        match rx.try_recv() {
            Ok(AuthMsg::Success { user_id }) => {
                self.auth_rx = None;
                self.status = format!("Connected as {}", user_id);
                self.screen = Screen::Main;
            }
            Ok(AuthMsg::Failure(msg)) if msg == "no_session" => {
                // No saved session → show onboarding
                self.auth_rx = None;
                self.screen = Screen::Onboarding;
            }
            Ok(AuthMsg::Failure(msg)) => {
                self.auth_rx = None;
                match self.screen {
                    Screen::Connecting(_) if self.onboarding.username.is_empty() => {
                        // Startup restore failed → show onboarding (not an error to display)
                        self.screen = Screen::Onboarding;
                    }
                    _ => {
                        self.screen = Screen::AuthError(msg);
                    }
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => {} // still running
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
        match &self.screen.clone() {
            Screen::Startup | Screen::Connecting(_) => {
                // Ctrl+C always exits
                if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
                    self.running = false;
                }
            }
            Screen::AuthError(_) => {
                // Any key dismisses the error and returns to onboarding
                self.screen = Screen::Onboarding;
            }
            Screen::Onboarding => self.handle_onboarding(key),
            Screen::DeviceLink => self.handle_device_link(key),
            Screen::Main => self.handle_main(key),
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
                            id: uuid_placeholder(),
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
        match &self.screen.clone() {
            Screen::Onboarding | Screen::AuthError(_) => {
                frame.render_widget(&self.onboarding, frame.area());
                if let Screen::AuthError(msg) = &self.screen {
                    self.render_error_overlay(frame, msg.clone());
                }
            }
            Screen::DeviceLink => {
                frame.render_widget(&self.device_link, frame.area());
            }
            Screen::Startup => {
                frame.render_widget(&self.onboarding, frame.area());
                self.render_spinner(frame, "Restoring session…".into());
            }
            Screen::Connecting(msg) => {
                let msg = msg.clone();
                frame.render_widget(&self.onboarding, frame.area());
                self.render_spinner(frame, msg);
            }
            Screen::Main => self.render_main(frame),
        }
    }

    fn render_spinner(&self, frame: &mut Frame, msg: String) {
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

    fn render_error_overlay(&self, frame: &mut Frame, msg: String) {
        let area = frame.area();
        let y = area.height.saturating_sub(2);
        let display = format!("  ✗ {}  (any key to retry)", msg);
        let line = Line::from(Span::styled(
            display.clone(),
            Style::default().fg(Color::Red),
        ));
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

fn uuid_placeholder() -> String {
    format!(
        "msg-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}

fn current_time_hhmm() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}", (secs % 86400) / 3600, (secs % 3600) / 60)
}
