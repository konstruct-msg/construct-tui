//! Settings screen — server/transport info, device identity, logout, safety number.

use std::time::{Duration, Instant};

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget},
};

use super::qr_widget::QrWidget;
use crate::invite::generate_invite_qr;

/// An action the user triggered from the settings screen.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsAction {
    /// User pressed [L] — log out, clear session.
    Logout,
    /// User pressed [S] — open safety number view.
    ShowSafetyNumber,
    /// User pressed [E] — export identity keys.
    ExportKeys,
    /// User pressed [Q] — show own identity QR (narrow terminals only).
    ShowMyQr,
    /// User pressed Esc or [B] — go back.
    Back,
}

#[derive(Debug, Clone)]
pub struct SettingsItem {
    label: String,
    value: String,
    action: Option<SettingsAction>,
}

pub struct SettingsScreen {
    pub server: String,
    pub transport_label: String,
    pub device_id: String,
    pub user_id: String,
    pub pq_active: bool,
    state: ListState,
    items: Vec<SettingsItem>,
    /// Signing key for generating invite QR codes.
    signing_key_hex: String,
    /// Cached invite QR payload (Base64 JSON) and the time it was generated.
    /// Regenerated automatically after 4 minutes (server TTL is 5 min).
    invite_cache: Option<(String, Instant)>,
}

impl SettingsScreen {
    pub fn new(
        server: impl Into<String>,
        transport_label: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        pq_active: bool,
        signing_key_hex: impl Into<String>,
    ) -> Self {
        let server = server.into();
        let transport_label = transport_label.into();
        let device_id = device_id.into();
        let user_id = user_id.into();
        let signing_key_hex = signing_key_hex.into();

        let pq_str = if pq_active {
            "yes (Kyber-768)"
        } else {
            "no (classic)"
        };

        let items = vec![
            SettingsItem {
                label: "Server".into(),
                value: server.clone(),
                action: None,
            },
            SettingsItem {
                label: "Transport".into(),
                value: transport_label.clone(),
                action: None,
            },
            SettingsItem {
                label: "Device ID".into(),
                value: device_id.clone(),
                action: None,
            },
            SettingsItem {
                label: "User ID".into(),
                value: user_id.clone(),
                action: None,
            },
            SettingsItem {
                label: "Post-quantum".into(),
                value: pq_str.into(),
                action: None,
            },
            // Separator (empty value)
            SettingsItem {
                label: String::new(),
                value: String::new(),
                action: None,
            },
            // Actions
            SettingsItem {
                label: "[S] Safety number".into(),
                value: String::new(),
                action: Some(SettingsAction::ShowSafetyNumber),
            },
            SettingsItem {
                label: "[E] Export keys".into(),
                value: String::new(),
                action: Some(SettingsAction::ExportKeys),
            },
            SettingsItem {
                label: "[L] Logout".into(),
                value: String::new(),
                action: Some(SettingsAction::Logout),
            },
            SettingsItem {
                label: "[Esc] Back".into(),
                value: String::new(),
                action: Some(SettingsAction::Back),
            },
        ];

        let mut state = ListState::default();
        // Start selection on first action row.
        state.select(Some(6));

        Self {
            server,
            transport_label,
            device_id,
            user_id,
            pq_active,
            state,
            items,
            signing_key_hex,
            invite_cache: None,
        }
    }

    pub fn next(&mut self) {
        let max = self.items.len().saturating_sub(1);
        let i = self.state.selected().map(|i| (i + 1).min(max)).unwrap_or(0);
        self.state.select(Some(i));
    }

    pub fn prev(&mut self) {
        let i = self
            .state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.state.select(Some(i));
    }

    /// Returns the action for the currently selected item, if any.
    pub fn confirm(&self) -> Option<SettingsAction> {
        self.state
            .selected()
            .and_then(|i| self.items.get(i))
            .and_then(|item| item.action.clone())
    }

    /// Update dynamic values (called after auth or config changes).
    pub fn update(
        &mut self,
        server: impl Into<String>,
        transport_label: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        pq_active: bool,
        signing_key_hex: impl Into<String>,
    ) {
        *self = Self::new(
            server,
            transport_label,
            device_id,
            user_id,
            pq_active,
            signing_key_hex,
        );
    }

    /// Returns a valid invite QR payload, regenerating if the cached one is ≥4 min old.
    fn invite_payload(&mut self) -> Option<&str> {
        const REFRESH_SECS: u64 = 240; // regenerate after 4 min (TTL is 5 min)

        let needs_refresh = match &self.invite_cache {
            None => true,
            Some((_, ts)) => ts.elapsed() >= Duration::from_secs(REFRESH_SECS),
        };

        if needs_refresh && !self.signing_key_hex.is_empty() && !self.user_id.is_empty() {
            match generate_invite_qr(
                &self.user_id,
                &self.device_id,
                &self.server,
                &self.signing_key_hex,
            ) {
                Ok(payload) => self.invite_cache = Some((payload, Instant::now())),
                Err(e) => tracing::warn!("invite generation failed: {e}"),
            }
        }

        self.invite_cache.as_ref().map(|(p, _)| p.as_str())
    }
}

impl Widget for &mut SettingsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .title(" ◆ Settings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = outer.inner(area);
        outer.render(area, buf);

        // On wide terminals (≥ 100 cols) split: settings list | identity QR
        if area.width >= 100 {
            let cols =
                Layout::horizontal([Constraint::Min(50), Constraint::Length(36)]).split(inner);
            self.render_list(cols[0], buf);
            self.render_identity_qr(cols[1], buf);
        } else {
            self.render_list(inner, buf);
        }
    }
}

impl SettingsScreen {
    fn render_list(&mut self, area: Rect, buf: &mut Buffer) {
        // Header hint
        let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);
        let hint = Paragraph::new(Line::from(Span::styled(
            "  ↑↓ navigate  Enter=select  Esc=back",
            Style::default().fg(Color::DarkGray),
        )));
        hint.render(chunks[0], buf);

        let items: Vec<ListItem> = self
            .items
            .iter()
            .map(|item| {
                if item.label.is_empty() {
                    // Separator row
                    ListItem::new(Line::from(Span::styled(
                        "  ─────────────────────────────────────────",
                        Style::default().fg(Color::DarkGray),
                    )))
                } else if item.action.is_some() {
                    // Action row
                    let color = if item.label.contains("Logout") {
                        Color::Red
                    } else {
                        Color::Cyan
                    };
                    ListItem::new(Line::from(Span::styled(
                        format!("  {}", item.label),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )))
                } else {
                    // Info row: label  value
                    let label = Span::styled(
                        format!("  {:<16}", item.label),
                        Style::default().fg(Color::DarkGray),
                    );
                    let value = Span::styled(&item.value, Style::default().fg(Color::White));
                    ListItem::new(Line::from(vec![label, value]))
                }
            })
            .collect();

        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = self.state;
        StatefulWidget::render(list, chunks[1], buf, &mut state);
        self.state = state;
    }

    fn render_identity_qr(&mut self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(" My Identity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = block.inner(area);
        block.render(area, buf);

        match self.invite_payload() {
            Some(payload) => {
                // Clone to avoid borrow conflict (payload borrows self, QrWidget needs &str)
                let payload = payload.to_owned();
                QrWidget::new(&payload)
                    .caption(&self.user_id)
                    .render(inner, buf);
            }
            None => {
                Paragraph::new("Generating invite…")
                    .style(Style::default().fg(Color::DarkGray))
                    .render(inner, buf);
            }
        }
    }
}
