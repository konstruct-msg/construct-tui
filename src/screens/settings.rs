//! Settings screen — server/transport info, device identity, logout, safety number.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget,
    },
};

/// An action the user triggered from the settings screen.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsAction {
    /// User pressed [L] — log out, clear session.
    Logout,
    /// User pressed [S] — open safety number view.
    ShowSafetyNumber,
    /// User pressed [E] — export identity keys.
    ExportKeys,
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
}

impl SettingsScreen {
    pub fn new(
        server: impl Into<String>,
        transport_label: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        pq_active: bool,
    ) -> Self {
        let server = server.into();
        let transport_label = transport_label.into();
        let device_id = device_id.into();
        let user_id = user_id.into();

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
    ) {
        *self = Self::new(server, transport_label, device_id, user_id, pq_active);
    }
}

impl Widget for &mut SettingsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .title(" ◆ Settings ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = outer.inner(area);
        outer.render(area, buf);

        // Header hint
        let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(inner);
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
}
