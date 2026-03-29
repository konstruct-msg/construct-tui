use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,
    pub display_name: String,
    pub unread: usize,
    pub last_message: Option<String>,
}

pub struct ChatListPane {
    pub contacts: Vec<Contact>,
    pub state: ListState,
    pub focused: bool,
}

impl ChatListPane {
    pub fn new() -> Self {
        // Placeholder contacts for the skeleton UI
        let contacts = vec![
            Contact {
                id: "1".into(),
                display_name: "max".into(),
                unread: 2,
                last_message: Some("Привет!".into()),
            },
            Contact {
                id: "2".into(),
                display_name: "anna".into(),
                unread: 0,
                last_message: Some("Ок, договорились".into()),
            },
        ];
        let mut state = ListState::default();
        state.select(Some(0));
        Self { contacts, state, focused: true }
    }

    pub fn next(&mut self) {
        let i = self.state.selected().map(|i| (i + 1).min(self.contacts.len().saturating_sub(1)));
        self.state.select(i);
    }

    pub fn prev(&mut self) {
        let i = self.state.selected().map(|i| i.saturating_sub(1));
        self.state.select(i);
    }

    pub fn selected_contact(&self) -> Option<&Contact> {
        self.state.selected().and_then(|i| self.contacts.get(i))
    }
}

impl StatefulWidget for &mut ChatListPane {
    type State = ListState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut ListState) {
        let border_style = if self.focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let items: Vec<ListItem> = self
            .contacts
            .iter()
            .map(|c| {
                let badge = if c.unread > 0 {
                    Span::styled(
                        format!(" [{}]", c.unread),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw("")
                };
                let name = Span::styled(&c.display_name, Style::default().add_modifier(Modifier::BOLD));
                let preview = if let Some(last) = &c.last_message {
                    let truncated = if last.chars().count() > 18 {
                        format!("{}…", last.chars().take(18).collect::<String>())
                    } else {
                        last.clone()
                    };
                    Span::styled(
                        format!("\n  {}", truncated),
                        Style::default().fg(Color::DarkGray),
                    )
                } else {
                    Span::raw("")
                };
                ListItem::new(vec![
                    Line::from(vec![name, badge]),
                    Line::from(vec![preview]),
                ])
                .style(Style::default())
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(" Contacts ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        StatefulWidget::render(list, area, buf, state);
    }
}

impl Widget for &mut ChatListPane {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut state = self.state.clone();
        StatefulWidget::render(self, area, buf, &mut state);
    }
}
