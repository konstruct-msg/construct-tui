use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};

/// "CONSTRUCT" in figlet block style (fits in 80-col terminal).
const BANNER: &[&str] = &[
    r" ██████╗ ██████╗ ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗ ██████╗████████╗",
    r"██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝",
    r"██║     ██║   ██║██╔██╗ ██║███████╗   ██║   ██████╔╝██║   ██║██║        ██║   ",
    r"██║     ██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██╗██║   ██║██║        ██║   ",
    r"╚██████╗╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║╚██████╔╝╚██████╗   ██║   ",
    r" ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═╝   ",
];

const TAGLINE: &str = "end-to-end encrypted  ·  quantum-resistant  ·  open protocol";

#[derive(Debug, Clone, PartialEq)]
pub enum OnboardingField {
    Username,
    Password,
}

pub struct OnboardingScreen {
    pub username: String,
    pub password: String,
    pub focused_field: OnboardingField,
    pub status: Option<String>,
    pub is_error: bool,
}

impl OnboardingScreen {
    pub fn new() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            focused_field: OnboardingField::Username,
            status: None,
            is_error: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        match self.focused_field {
            OnboardingField::Username => self.username.push(c),
            OnboardingField::Password => self.password.push(c),
        }
    }

    pub fn pop_char(&mut self) {
        match self.focused_field {
            OnboardingField::Username => {
                self.username.pop();
            }
            OnboardingField::Password => {
                self.password.pop();
            }
        }
    }

    pub fn next_field(&mut self) {
        self.focused_field = match self.focused_field {
            OnboardingField::Username => OnboardingField::Password,
            OnboardingField::Password => OnboardingField::Username,
        };
    }

    pub fn credentials(&self) -> (&str, &str) {
        (&self.username, &self.password)
    }
}

impl Widget for &OnboardingScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Heights of each section
        let banner_h = BANNER.len() as u16;
        // logo + gap + banner + gap + tagline + gap + username + password + gap + hint
        let total_h = banner_h + 1 + 1 + 2 + 3 + 3 + 1 + 1;
        let v_offset = area.height.saturating_sub(total_h) / 2;
        let mut y = area.y + v_offset;

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

        // ── Input fields ──────────────────────────────────────────────────────
        let field_w = 42u16.min(area.width.saturating_sub(4));
        let field_x = area.x + area.width.saturating_sub(field_w) / 2;

        let user_focused = self.focused_field == OnboardingField::Username;
        let user_style = field_border_style(user_focused);
        let user_text = format!("{}_", self.username);
        Paragraph::new(user_text)
            .block(
                Block::default()
                    .title(" Username ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(user_style),
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
        y += 3;

        let pass_focused = self.focused_field == OnboardingField::Password;
        let pass_style = field_border_style(pass_focused);
        let pass_text = format!("{}_", "●".repeat(self.password.len()));
        Paragraph::new(pass_text)
            .block(
                Block::default()
                    .title(" Password ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(pass_style),
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
        let hint = "Tab=next field   Enter=connect   q=quit";
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

fn field_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
