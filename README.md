# construct-tui

Terminal UI client for [Konstruct](https://konstruct.cc) — Privacy-First Secure Messenger with Post-Quantum Encryption.

Built with Rust + [Ratatui](https://ratatui.rs). Target platforms: Linux, macOS. Binary name: `konstruct`.


```
 KONSTRUCT   CHATS · Phosphor
┌[ Chats ]────────────────────┐┌[ alice ]─────────────────────────────────────┐
│ ▸ alice                    ││ [15:42] hey, got the new build running        │
│   bob                      ││   works on the Pi Zero too now  [15:43]       │
│   carol                    ││                                               │
│                            │├[ Message ]───────────────────────────────────┤
│                            ││ Write a message…                              │
└────────────────────────────┘└───────────────────────────────────────────────┘
 ● connected │ Ready │ ↑↓ choose  Enter open  a add  s settings  q quit
```

License: [MPL-2.0](LICENSE). Trademark: [TRADEMARK.md](TRADEMARK.md).

Current status: this client is under active development and is not a production-usable
messenger yet. The next gate is a live 1:1 text exchange with iOS on `ams.konstruct.cc`.

---

## Terminal compatibility

| Terminal | Support |
|----------|---------|
| **[WezTerm](https://wezterm.org)** | Recommended — true color, Unicode, ligatures |
| **[Kitty](https://github.com/kovidgoyal/kitty)** | Excellent |
| **iTerm2** | Good |
| **Alacritty** | Good (no ligatures) |
| **tmux** | Works — set `TERM=xterm-256color` or `tmux-256color` |
| Apple Terminal | 256 colors only, no true color |

Minimum terminal size: **80×24**. At widths below 96 columns, the active pane fills the screen; use `Enter`, `Tab`, or `Esc` to move between chats and the conversation.

The interface has **Phosphor** (dark) and **Paper** (light) themes. Both use Konstruct blue `#008CFF` for focus and selection. Choose a theme with `T` in Settings; the choice is saved in `~/.config/construct-tui/config.json`.

Visual tokens and shared panel, text, selection, and state styles live in [`src/theme.rs`](src/theme.rs). Each screen receives the active theme from `App::render`; new screens should use those styles instead of terminal default colors. QR modules stay black on white in both themes so a camera can read them.

---

## Requirements

| Dependency | Version |
|------------|---------|
| Rust toolchain | stable ≥ 1.96 (matches `construct-core`) |
| Sibling checkouts | `../construct-core`, `../construct-protos` |
| `libsqlcipher` | bundled (no system install needed) |

```bash
# macOS
brew install rustup
rustup toolchain install 1.96.0

# Debian / Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install 1.96.0
```

Layout expected by `Cargo.toml`:

```
~/Code/
  construct-tui/       # this repo
  construct-core/      # crypto
  construct-protos/    # prost source of truth
```

---

## Build

```bash
cargo build --release
# binary: target/release/konstruct
```

Post-quantum (Kyber-768 PQXDH) is **on by default**. To build without it:

```bash
cargo build --release --no-default-features
```

> **Raspberry Pi Zero W:** Kyber-768 handshake can take ~60 s. Use `--no-default-features` on very small boards.

There is no `ice` feature and no `construct-ice` dependency. VEIL is planned later; the
CLI still accepts `--bridge` / `--bridge-tls-sni`, but those flags are parsed-only today.

Copy a built binary to another machine:

```bash
scp ./target/release/konstruct pi@raspberrypi.local:/usr/local/bin/konstruct
```

---

## Run

```bash
# Defaults — server from ~/.config/construct-tui/config.json,
# or https://ams.konstruct.cc:443 if the file is missing
konstruct

# Override server
konstruct --server https://ams.konstruct.cc:443

# Disable at-rest encryption (headless / systemd use)
konstruct --no-encrypt
# or:
CONSTRUCT_NO_ENCRYPT=1 konstruct

# Log level: error, warn, info, debug, trace (default: info).
# Logs: ~/.local/share/construct-tui/konstruct.log
# RUST_LOG overrides --log-level when set.
konstruct --log-level debug

# Print log path and exit
konstruct log-path

# Delete local session and all keys
konstruct logout
```

`--bridge` / `--bridge-tls-sni`, `--headless`, and `--config` are parsed by clap but
**not wired** — they do not change transport, skip the TUI, or load a custom config file.

---

## First run

1. **Register** — enter a username. The client generates Ed25519 + X25519 keys locally, solves a proof-of-work challenge, and registers the device with the server.
2. **Set passphrase** — protects the session file and message database with Argon2id + AES-256-GCM at rest. Leave empty to skip encryption (or pass `--no-encrypt`).
3. **Chat** — main screen.

On subsequent runs the session is loaded from disk and decrypted with the passphrase.

gRPC (register, authenticate, device link, token refresh, pre-key bundle, FindUser,
AcceptInvite, MessageStream) talks HTTP/2 over TCP/TLS to `ams.konstruct.cc` with the
system trust store. QUIC/H3 belongs to `construct-transport` on `quic.konstruct.cc`, not
this client. First real send/recv against iOS still needs a live session.

---

## Key bindings

### Main screen

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate contact list |
| `Enter` | Open conversation |
| `Tab` / `i` | Focus compose box |
| `Esc` | Back to contact list |
| `Shift+Tab` | Focus contact list from compose |
| `Enter` (in compose) | Send message |
| `s` | Open settings |
| `a` / `n` | Add contact (search) |
| `q` | Quit (when compose is not focused) |
| `Ctrl+C` | Force quit (any screen) |

### Settings screen

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Select / confirm |
| `Esc` / `q` | Back to chat |
| `t` | Switch between Phosphor and Paper themes |

### Add contact (search overlay)

| Key | Action |
|-----|--------|
| Type | Search by username, or paste `https://konstruct.cc/add?invite=…` |
| `Enter` | Search / redeem invite; if a result is selected, add it |
| `↑` / `↓` | Navigate results |
| `Esc` | Close |

---

## Data storage

| File | Contents |
|------|----------|
| `~/.config/construct-tui/session.enc` | Encrypted session (keys + tokens). Argon2id + AES-256-GCM. |
| `~/.config/construct-tui/config.json` | Server URL + transport config (plaintext). |
| `~/.local/share/construct-tui/messages.db` | SQLCipher-encrypted message database. |
| `~/.local/share/construct-tui/konstruct.log` | Application log. |

Argon2id parameters: 32 MiB memory, 3 iterations, 1 thread (tuned for Raspberry Pi 4). The DB key is derived from the same master key via HKDF.

**Deleting everything:**

```bash
rm -rf ~/.config/construct-tui ~/.local/share/construct-tui
# or:
konstruct logout
```

---

## Development

```bash
cargo run
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
bash scripts/install-hooks.sh    # pre-commit: fmt + clippy
```

There is no CI in this repo (removed 2026-06-19; the project was too early-stage to build in GitHub Actions).

---

## Security notes

- **Keys never leave the device** — the server only stores public keys.
- **Session file** is encrypted with Argon2id + AES-256-GCM. The Argon2id salt is stored alongside the ciphertext.
- **Messages** are stored in a SQLCipher AES-256 encrypted database.
- **Signal Protocol** (X3DH + Double Ratchet) + **PQXDH** (Kyber-768) when built with default features.

DPI-bypass (VEIL) is **not** integrated. Transport is in-tree gRPC-over-HTTP/2 in
`src/grpc/` and is kept extractable for a later non-Apple GUI.

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
