use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Widget, Wrap},
};

#[derive(Debug, Clone, PartialEq)]
pub enum MessageKind {
    Sent,
    Received,
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub id: String,
    pub kind: MessageKind,
    pub text: String,
    pub time: String,
}

pub struct ChatViewPane {
    pub contact_name: String,
    pub messages: Vec<ChatMessage>,
    pub compose: String,
    pub focused: bool,
    pub compose_focused: bool,
}

impl ChatViewPane {
    pub fn new(contact_name: impl Into<String>) -> Self {
        // Placeholder messages for skeleton UI
        let messages = vec![
            ChatMessage {
                id: "1".into(),
                kind: MessageKind::Received,
                text: "Привет!".into(),
                time: "11:42".into(),
            },
            ChatMessage {
                id: "2".into(),
                kind: MessageKind::Received,
                text: "Как дела?".into(),
                time: "11:43".into(),
            },
            ChatMessage {
                id: "3".into(),
                kind: MessageKind::Sent,
                text: "Отлично!".into(),
                time: "11:44".into(),
            },
        ];
        Self {
            contact_name: contact_name.into(),
            messages,
            compose: String::new(),
            focused: false,
            compose_focused: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.compose.push(c);
    }

    pub fn pop_char(&mut self) {
        self.compose.pop();
    }

    pub fn take_compose(&mut self) -> String {
        std::mem::take(&mut self.compose)
    }
}

impl Widget for &mut ChatViewPane {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused || self.compose_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let outer = Block::default()
            .title(format!(" {} ", self.contact_name))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style);

        let inner = outer.inner(area);
        outer.render(area, buf);

        // Split inner: messages area + compose bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(inner);

        // Messages
        let msg_lines: Vec<Line> = self
            .messages
            .iter()
            .map(|m| {
                if m.kind == MessageKind::Sent {
                    let time = Span::styled(
                        format!("[{}] ", m.time),
                        Style::default().fg(Color::DarkGray),
                    );
                    let text = Span::styled(
                        &m.text,
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    );
                    // Right-aligned feel: pad with spaces before
                    Line::from(vec![
                        Span::raw("  "),
                        text,
                        Span::raw("  "),
                        time,
                    ])
                } else {
                    let time = Span::styled(
                        format!("[{}] ", m.time),
                        Style::default().fg(Color::DarkGray),
                    );
                    let text = Span::styled(&m.text, Style::default().fg(Color::Cyan));
                    Line::from(vec![time, text])
                }
            })
            .collect();

        Paragraph::new(msg_lines)
            .wrap(Wrap { trim: false })
            .render(chunks[0], buf);

        // Compose box
        let compose_border_style = if self.compose_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let compose_text = format!("{}_", self.compose);
        Paragraph::new(compose_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(compose_border_style)
                    .title(" Message "),
            )
            .style(Style::default().fg(Color::White))
            .render(chunks[1], buf);
    }
}
