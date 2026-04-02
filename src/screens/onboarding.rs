use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};

/// Construct logo — half-block art, 16 rows × 40 cols.
/// Generated from the brand asset using Unicode half-block compression (2 source rows → 1).
const LOGO: &[&str] = &[
    "████████████████████████████████████████",
    "████████████████████████████████████████",
    "████████████████████████████████████████",
    "████████████▀▀▀▀████████████████████████",
    "██████████▀      ▀██████████████████████",
    "█████████          ▀████▀    ▀██████████",
    "████████            ▀█▀        ▀████████",
    "████████                         ███████",
    "████████▄                         ██████",
    "█████████▄                        ██████",
    "███████████▄      ▄█▄           ▄███████",
    "█████████████▄▄▄▄█████▄        ▄████████",
    "████████████████████████▄    ▄██████████",
    "████████████████████████████████████████",
    "████████████████████████████████████████",
    "████████████████████████████████████████",
];

const BANNER: &[&str] = &[
    r" ██████╗ ██████╗ ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗ ██████╗████████╗",
    r"██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝",
    r"██║     ██║   ██║██╔██╗ ██║███████╗   ██║   ██████╔╝██║   ██║██║        ██║   ",
    r"██║     ██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██╗██║   ██║██║        ██║   ",
    r"╚██████╗╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║╚██████╔╝╚██████╗   ██║   ",
    r" ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═╝  ",
];

const TAGLINE: &str = "end-to-end encrypted  ·  quantum-resistant  ·  open protocol";

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
        let logo_h = LOGO.len() as u16;
        let banner_h = BANNER.len() as u16;
        // logo + gap + banner + gap + tagline + gap + field + gap + hint
        let total_h = logo_h + 1 + banner_h + 1 + 1 + 2 + 3 + 1 + 1;
        let v_offset = area.height.saturating_sub(total_h) / 2;
        let mut y = area.y + v_offset;

        // ── Logo ──────────────────────────────────────────────────────────────
        let logo_w = LOGO[0].chars().count() as u16;
        let logo_x = area.x + area.width.saturating_sub(logo_w) / 2;
        for (i, row) in LOGO.iter().enumerate() {
            Paragraph::new(*row)
                .style(Style::default().fg(Color::Cyan))
                .render(
                    Rect {
                        x: logo_x,
                        y: y + i as u16,
                        width: logo_w.min(area.width),
                        height: 1,
                    },
                    buf,
                );
        }
        y += logo_h + 1;

        // ── CONSTRUCT banner ──────────────────────────────────────────────────
        let banner_w = BANNER[0].len() as u16;
        let banner_x = area.x + area.width.saturating_sub(banner_w) / 2;
        for (i, row) in BANNER.iter().enumerate() {
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
                        width: banner_w.min(area.width),
                        height: 1,
                    },
                    buf,
                );
        }
        y += banner_h + 1;

        // ── Tagline ───────────────────────────────────────────────────────────
        let tag_x = area.x + area.width.saturating_sub(TAGLINE.len() as u16) / 2;
        Paragraph::new(TAGLINE)
            .style(Style::default().fg(Color::DarkGray))
            .render(
                Rect {
                    x: tag_x,
                    y,
                    width: TAGLINE.len() as u16,
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
                Color::Green
            };
            let sx = area.x + area.width.saturating_sub(msg.len() as u16) / 2;
            Paragraph::new(msg.as_str())
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .render(
                    Rect {
                        x: sx,
                        y,
                        width: (msg.len() as u16).min(area.width),
                        height: 1,
                    },
                    buf,
                );
            y += 1;
        }

        // ── Hint ──────────────────────────────────────────────────────────────
        let hint = "Enter=new account   Tab=link existing device   q=quit";
        let hx = area.x + area.width.saturating_sub(hint.len() as u16) / 2;
        Paragraph::new(hint)
            .style(Style::default().fg(Color::DarkGray))
            .render(
                Rect {
                    x: hx,
                    y,
                    width: hint.len() as u16,
                    height: 1,
                },
                buf,
            );
    }
}
