//! Device linking screen — enter a link token from an existing Construct device.
//!
//! Flow:
//!   1. On another device: Settings → Add Device → generates a link token
//!   2. User enters the 32-char base64url token here
//!   3. Enter → ConfirmDeviceLink RPC → JWT saved → Main

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};

const TITLE: &str = " Link existing account ";
const HINT: &str = "Enter=confirm   Esc=back   q=quit";

pub struct DeviceLinkScreen {
    pub token: String,
    pub status: Option<String>,
    pub is_error: bool,
}

impl DeviceLinkScreen {
    pub fn new() -> Self {
        Self {
            token: String::new(),
            status: Some("Paste or type the link token shown on your other device".into()),
            is_error: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        if self.token.len() < 64 {
            self.token.push(c);
        }
    }

    pub fn pop_char(&mut self) {
        self.token.pop();
    }

    pub fn set_status(&mut self, msg: impl Into<String>, error: bool) {
        self.status = Some(msg.into());
        self.is_error = error;
    }

    pub fn clear_status(&mut self) {
        self.status = None;
        self.is_error = false;
    }
}

impl Widget for &DeviceLinkScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Layout: title + gap + token field + gap + status + gap + hint
        let total_h = 1u16 + 2 + 3 + 1 + 1 + 1 + 1;
        let v_offset = area.height.saturating_sub(total_h) / 2;
        let mut y = area.y + v_offset;

        // ── Title ─────────────────────────────────────────────────────────────
        let tw = TITLE.len() as u16;
        let tx = area.x + area.width.saturating_sub(tw) / 2;
        Paragraph::new(TITLE)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .render(
                Rect {
                    x: tx,
                    y,
                    width: tw.min(area.width),
                    height: 1,
                },
                buf,
            );
        y += 2;

        // ── Token input field ─────────────────────────────────────────────────
        let field_w = 50u16.min(area.width.saturating_sub(4));
        let field_x = area.x + area.width.saturating_sub(field_w) / 2;
        let display = format!("{}_", self.token);

        Paragraph::new(display)
            .block(
                Block::default()
                    .title(" Link Token ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .style(Style::default().fg(Color::White))
            .render(
                Rect {
                    x: field_x,
                    y,
                    width: field_w,
                    height: 3,
                },
                buf,
            );
        y += 4;

        // ── Status line ───────────────────────────────────────────────────────
        if let Some(ref msg) = self.status {
            let color = if self.is_error {
                Color::Red
            } else {
                Color::DarkGray
            };
            let sx = area.x + area.width.saturating_sub(msg.len() as u16) / 2;
            Paragraph::new(msg.as_str())
                .style(Style::default().fg(color))
                .render(
                    Rect {
                        x: sx,
                        y,
                        width: (msg.len() as u16).min(area.width),
                        height: 1,
                    },
                    buf,
                );
            y += 2;
        }

        // ── Hint ──────────────────────────────────────────────────────────────
        let hx = area.x + area.width.saturating_sub(HINT.len() as u16) / 2;
        Paragraph::new(HINT)
            .style(Style::default().fg(Color::DarkGray))
            .render(
                Rect {
                    x: hx,
                    y,
                    width: (HINT.len() as u16).min(area.width),
                    height: 1,
                },
                buf,
            );
    }
}
