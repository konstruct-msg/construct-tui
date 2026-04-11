use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Widget},
};

/// Full-width banner for terminals ≥ 82 columns. `.chars().count()` = 78.
const BANNER: &[&str] = &[
    r" ██████╗ ██████╗ ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗ ██████╗████████╗",
    r"██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝",
    r"██║     ██║   ██║██╔██╗ ██║███████╗   ██║   ██████╔╝██║   ██║██║        ██║   ",
    r"██║     ██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██╗██║   ██║██║        ██║   ",
    r"╚██████╗╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║╚██████╔╝╚██████╗   ██║   ",
    r" ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═╝  ",
];

/// Compact fallback for terminals < 80 columns.
const BANNER_NARROW: &[&str] = &[
    r" ___ ___  _  _ ___ _____ ___ _   _  ___ _____",
    r"/ __/ _ \| \| / __|_   _| _ \ | | |/ __|_   _|",
    r"| (_| (_) | .` \__ \ | | |   / |_| | (__  | |",
    r" \___\___/|_|\_|___/ |_| |_|_\\___/ \___| |_|",
];

const TAGLINE: &str = "end-to-end encrypted  \u{b7}  quantum-resistant  \u{b7}  open protocol";

/// Only one field for now — username (used as display name hint on registration).
/// Construct is passwordless/device-based; no password needed.
#[derive(Debug, Clone, PartialEq)]
pub enum OnboardingField {
    Username,
}

pub struct OnboardingScreen {
    pub username: String,
    pub focused_field: OnboardingField,
    pub status: Option<String>,
    pub is_error: bool,
}

impl OnboardingScreen {
    pub fn new() -> Self {
        Self {
            username: String::new(),
            focused_field: OnboardingField::Username,
            status: None,
            is_error: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        // Limit username to 32 chars
        if self.username.len() < 32 {
            self.username.push(c);
        }
    }

    pub fn pop_char(&mut self) {
        self.username.pop();
    }

    /// Cycle through fields (only one for now).
    pub fn next_field(&mut self) {
        // No-op — single field
    }
}

impl Widget for &OnboardingScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Pick banner based on terminal width. Use char count, not byte length.
        let use_full = area.width >= 80;
        let banner = if use_full { BANNER } else { BANNER_NARROW };
        let banner_w = banner[0].chars().count() as u16;
        let banner_h = banner.len() as u16;

        // banner + gap + tagline + gap + field + gap + hint
        let total_h = banner_h + 1 + 1 + 2 + 3 + 1 + 1;
        let v_offset = area.height.saturating_sub(total_h) / 2;
        let mut y = area.y + v_offset;

        // ── CONSTRUCT banner ──────────────────────────────────────────────────
        let banner_x = area.x + area.width.saturating_sub(banner_w) / 2;
        for (i, row) in banner.iter().enumerate() {
            let row_w = row.chars().count() as u16;
            Paragraph::new(*row)
                .style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )
                .render(
                    Rect {
                        x: banner_x,
                        y: y + i as u16,
                        width: row_w
                            .min(area.width.saturating_sub(banner_x.saturating_sub(area.x))),
                        height: 1,
                    },
                    buf,
                );
        }
        y += banner_h + 1;

        // ── Tagline ───────────────────────────────────────────────────────────
        let tag_w = TAGLINE.chars().count() as u16;
        let tag_x = area.x + area.width.saturating_sub(tag_w) / 2;
        Paragraph::new(TAGLINE)
            .style(Style::default().fg(Color::DarkGray))
            .render(
                Rect {
                    x: tag_x,
                    y,
                    width: tag_w.min(area.width),
                    height: 1,
                },
                buf,
            );
        y += 2;

        // ── Username field ────────────────────────────────────────────────────
        let field_w = 42u16.min(area.width.saturating_sub(4));
        let field_x = area.x + area.width.saturating_sub(field_w) / 2;

        let user_text = format!("{}_", self.username);
        Paragraph::new(user_text)
            .block(
                Block::default()
                    .title(" Username / Display name ")
                    .borders(Borders::ALL)
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
                Color::Green
            };
            let msg_w = msg.chars().count() as u16;
            let sx = area.x + area.width.saturating_sub(msg_w) / 2;
            Paragraph::new(msg.as_str())
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .render(
                    Rect {
                        x: sx,
                        y,
                        width: msg_w.min(area.width),
                        height: 1,
                    },
                    buf,
                );
            y += 1;
        }

        // ── Hint ──────────────────────────────────────────────────────────────
        let hint = "Enter=register (username optional)   Tab=link existing device   q=quit";
        let hint_w = hint.len() as u16; // all ASCII
        let hx = area.x + area.width.saturating_sub(hint_w) / 2;
        Paragraph::new(hint)
            .style(Style::default().fg(Color::DarkGray))
            .render(
                Rect {
                    x: hx,
                    y,
                    width: hint_w.min(area.width),
                    height: 1,
                },
                buf,
            );
    }
}
