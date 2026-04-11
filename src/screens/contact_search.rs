//! Contact search screen.
//!
//! Lets the user search for other nodes by username and send a contact request.
//! When connected, this triggers gRPC SearchUsers + AddContact RPCs.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget,
    },
};

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// State for the contact search / add screen.
pub struct ContactSearchScreen {
    /// Current text in the search box.
    pub query: String,
    /// Results from the last search RPC (empty until user searches).
    pub results: Vec<SearchResult>,
    /// Status / error message.
    pub status: Option<String>,
    pub is_error: bool,
    /// Whether a search RPC is in flight.
    pub searching: bool,
    state: ListState,
}

impl ContactSearchScreen {
    pub fn new() -> Self {
        Self {
            query: String::new(),
            results: Vec::new(),
            status: None,
            is_error: false,
            searching: false,
            state: ListState::default(),
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
        self.status = None;
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
        self.status = None;
    }

    pub fn next(&mut self) {
        if self.results.is_empty() {
            return;
        }
        let max = self.results.len() - 1;
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

    pub fn set_results(&mut self, results: Vec<SearchResult>) {
        self.results = results;
        if self.results.is_empty() {
            self.state.select(None);
            self.status = Some("No results".into());
            self.is_error = false;
        } else {
            self.state.select(Some(0));
            self.status = None;
        }
        self.searching = false;
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.status = Some(msg.into());
        self.is_error = true;
        self.searching = false;
    }

    pub fn selected(&self) -> Option<&SearchResult> {
        self.state.selected().and_then(|i| self.results.get(i))
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Widget for &mut ContactSearchScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .title(" ◆ Add Node ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = outer.inner(area);
        outer.render(area, buf);

        let chunks = Layout::vertical([
            Constraint::Length(1), // hint
            Constraint::Length(3), // search box
            Constraint::Length(1), // status
            Constraint::Min(1),    // results list
        ])
        .split(inner);

        // Hint
        Paragraph::new(Line::from(Span::styled(
            "  Enter username  Enter=search  Tab=select  Ctrl+A=add  Esc=back",
            Style::default().fg(Color::DarkGray),
        )))
        .render(chunks[0], buf);

        // Search input
        let input_style = Style::default().fg(Color::White);
        let input_text = if self.searching {
            format!("  {}  ⠋", self.query)
        } else {
            format!("  {}_", self.query)
        };
        Paragraph::new(input_text)
            .style(input_style)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Search "),
            )
            .render(chunks[1], buf);

        // Status
        if let Some(ref msg) = self.status {
            let color = if self.is_error {
                Color::Red
            } else {
                Color::Green
            };
            Paragraph::new(Line::from(Span::styled(
                format!("  {}", msg),
                Style::default().fg(color),
            )))
            .render(chunks[2], buf);
        }

        // Results
        let items: Vec<ListItem> = self
            .results
            .iter()
            .map(|r| {
                let name = Span::styled(
                    format!("  @{}", r.username),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                );
                let uid = Span::styled(
                    format!("  {}", &r.user_id[..8.min(r.user_id.len())]),
                    Style::default().fg(Color::DarkGray),
                );
                ListItem::new(vec![Line::from(vec![name, uid])])
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
        StatefulWidget::render(list, chunks[3], buf, &mut state);
        self.state = state;
    }
}
