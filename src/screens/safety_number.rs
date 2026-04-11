//! Safety number verification screen.
//!
//! Computes a human-verifiable fingerprint from two X25519 identity keys
//! (ours and our peer's) — same approach as Signal's safety number.
//!
//! Format: 12 groups of 5 decimal digits, displayed in a 4×3 grid.
//! Example:
//!   12345 67890 11234  56789 01234 56789
//!   01234 56789 01234  56789 01234 56789

use sha2::{Digest, Sha512};

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

/// Compute the safety number for a pair of identity keys.
///
/// Canonical ordering: the lexicographically smaller key goes first.
/// This ensures both sides produce the same number regardless of who initiates.
pub fn compute_safety_number(our_identity: &[u8; 32], their_identity: &[u8; 32]) -> String {
    let (first, second) = if our_identity <= their_identity {
        (our_identity, their_identity)
    } else {
        (their_identity, our_identity)
    };

    let mut hasher = Sha512::new();
    hasher.update(b"construct-safety-number-v1\x00");
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();

    // Extract 12 groups of 5 decimal digits from the first 60 bytes.
    // Each group: take 5 bytes → interpret as big-endian u64 → mod 100000 → zero-pad to 5 digits.
    (0..12)
        .map(|i| {
            let offset = i * 5;
            let bytes = &digest[offset..offset + 5];
            let n = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Safety number verification overlay.
pub struct SafetyNumberScreen {
    pub contact_name: String,
    pub number: String,
}

impl SafetyNumberScreen {
    pub fn new(
        contact_name: impl Into<String>,
        our_identity: &[u8; 32],
        their_identity: &[u8; 32],
    ) -> Self {
        Self {
            contact_name: contact_name.into(),
            number: compute_safety_number(our_identity, their_identity),
        }
    }

    /// Format the safety number as a 4×3 grid of groups.
    fn formatted_grid(&self) -> Vec<String> {
        let groups: Vec<&str> = self.number.split_whitespace().collect();
        groups.chunks(3).map(|row| row.join("  ")).collect()
    }
}

impl Widget for &SafetyNumberScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let outer = Block::default()
            .title(format!(" ◆ Safety Number — {} ", self.contact_name))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let inner = outer.inner(area);
        outer.render(area, buf);

        let mut lines = vec![
            Line::from(Span::styled(
                "  Compare this number with your contact out-of-band.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::raw("")),
        ];

        for row in self.formatted_grid() {
            lines.push(Line::from(Span::styled(
                format!("    {}", row),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "  [Esc] Back",
            Style::default().fg(Color::DarkGray),
        )));

        Paragraph::new(lines).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_is_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        assert_eq!(
            compute_safety_number(&key_a, &key_b),
            compute_safety_number(&key_b, &key_a),
        );
    }

    #[test]
    fn safety_number_has_twelve_groups() {
        let key_a = [0xABu8; 32];
        let key_b = [0xCDu8; 32];
        let sn = compute_safety_number(&key_a, &key_b);
        assert_eq!(sn.split_whitespace().count(), 12);
    }

    #[test]
    fn safety_number_groups_are_5_digits() {
        let key_a = [42u8; 32];
        let key_b = [99u8; 32];
        let sn = compute_safety_number(&key_a, &key_b);
        for group in sn.split_whitespace() {
            assert_eq!(group.len(), 5);
            assert!(group.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
