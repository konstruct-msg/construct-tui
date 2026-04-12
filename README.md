# construct-tui

Terminal UI client for [Construct Messenger](https://konstruct.cc) — E2EE messenger with a terminal/ASCII aesthetic.

Built with Rust + [Ratatui](https://ratatui.rs). Runs anywhere: Linux, macOS, Raspberry Pi.

```
┌─ CONSTRUCT ─────────────────────────────────────────────────────────────────┐
│ > CONTACTS                 │ [alice]  15:42                                  │
│   alice           15:42    │ hey, got the new build running                  │
│   bob             14:11    │                                                 │
│   carol           11:03    │ [you]  15:43                                    │
│                            │ works on the Pi Zero too now                    │
│                            │                                                 │
│                            │ ▌                                               │
└────────────────────────────┴────────────────────────────────────────────────┘
```

---

## Installation

### Pre-built binary (fastest)

```bash
curl -fsSL https://raw.githubusercontent.com/maximeliseyev/construct-tui/main/scripts/install.sh | sh
```

Downloads the latest release for your platform (macOS arm64/x86_64, Linux x86_64/aarch64)
and installs `konstrukt` to `/usr/local/bin`.

**Manual download** from [Releases](https://github.com/maximeliseyev/construct-tui/releases/latest):

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `konstrukt-macos-arm64.tar.gz` |
| macOS (Intel) | `konstrukt-macos-x86_64.tar.gz` |
| Linux x86_64 | `konstrukt-linux-x86_64.tar.gz` |
| Linux aarch64 (RPi 4+) | `konstrukt-linux-aarch64.tar.gz` |

```bash
# Example — macOS Apple Silicon
curl -LO https://github.com/maximeliseyev/construct-tui/releases/latest/download/konstrukt-macos-arm64.tar.gz
tar xzf konstrukt-macos-arm64.tar.gz
chmod +x konstrukt-macos-arm64
mv konstrukt-macos-arm64 /usr/local/bin/konstrukt
```

### Copy binary to another machine

```bash
# To a remote server or Raspberry Pi
scp ./target/release/konstrukt pi@raspberrypi.local:/usr/local/bin/konstrukt

# Or via rsync
rsync -avz ./target/release/konstrukt user@server:/usr/local/bin/konstrukt
```

### Build from source

See the [Build](#build) section below.

---

## Terminal compatibility

| Terminal | Support |
|----------|---------|
| **WezTerm** | ✅ Recommended — true color, Unicode, ligatures |
| **Kitty** | ✅ Excellent |
| **iTerm2** | ✅ Good |
| **Alacritty** | ✅ Good (no ligatures) |
| **tmux** | ✅ Works — set `TERM=xterm-256color` or `tmux-256color` |
| Apple Terminal | ⚠️ 256 colors only, no true color |

Minimum terminal size: **80×24**. The banner scales down automatically on narrower terminals.

---

## Requirements

| Dependency | Version |
|------------|---------|
| Rust toolchain | stable ≥ 1.85 |
| `libsqlcipher` | bundled (no system install needed) |
| `protoc` (Protocol Buffers compiler) | only if regenerating `.proto` |

```bash
# macOS
brew install rust

# Debian / Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Build

```bash
# Standard release build (direct TLS, no PQ)
cargo build --release

# With obfs4 DPI-bypass transport (construct-ice)
cargo build --release --features ice

# Post-quantum (Kyber-768 PQXDH) — for powerful devices (RPi 3B+ and up)
cargo build --profile release-pq --features post-quantum

# PQ + ICE (everything)
cargo build --profile release-pq --features post-quantum,ice
```

The binary is named `konstrukt` and is placed at `target/release/konstrukt`
(or `target/release-pq/konstrukt` for the PQ build).

> **Note for Raspberry Pi Zero W:** Kyber-768 handshake takes ~60 s. Use the standard build without `post-quantum`.

---

## Run

```bash
# Defaults — connects to https://construct.cc
konstrukt

# Override server
konstrukt --server https://ams.construct.cc:443

# Enable obfs4 DPI-bypass (requires --features ice build)
konstrukt --bridge "cert=BASE64... iat-mode=0"

# obfs4 + CDN SNI fronting
konstrukt --bridge "cert=BASE64... iat-mode=0" --bridge-tls-sni cdn.example.com

# Disable at-rest encryption (headless / systemd use)
konstrukt --no-encrypt
# or via env var:
CONSTRUCT_NO_ENCRYPT=1 konstrukt

# Post-quantum mode (binary must be built with --features post-quantum)
konstrukt --post-quantum

# Headless daemon (receive messages without a terminal UI)
konstrukt --headless

# Custom config file
konstrukt --config /etc/construct/config.json

# Delete local session and all keys
konstrukt logout
```

---

## First run

1. **Register** — enter a username. The client generates Ed25519 + X25519 keys locally, solves a proof-of-work challenge, and registers the device with the server.
2. **Set passphrase** — protects your session and message database with Argon2id + AES-256-GCM at rest. Leave empty to skip encryption (use `--no-encrypt` or `CONSTRUCT_NO_ENCRYPT`).
3. **Chat** — you're in.

On subsequent runs the session is loaded from disk and decrypted with your passphrase.

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
| `a` | Add contact (search) |
| `q` | Quit (when compose is not focused) |
| `Ctrl+C` | Force quit (any screen) |

### Settings screen

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Select / confirm |
| `Esc` / `q` | Back to chat |

### Add contact (search overlay)

| Key | Action |
|-----|--------|
| Type | Search by username |
| `↑` / `↓` | Navigate results |
| `Ctrl+A` | Add selected contact |
| `Esc` | Close |

---

## Config file

Stored at `~/.config/construct-tui/config.json`. Created automatically on first run.

```json
{
  "server": "https://ams.konstruct.cc",
  "transport": {
    "mode": "Direct"
  }
}
```

**Transport modes:**

```json
// Direct TLS (default)
{ "mode": "Direct" }

// obfs4 obfuscation
{ "mode": "Obfs4", "bridge_line": "cert=BASE64... iat-mode=0" }

// obfs4 + SNI fronting
{ "mode": "Obfs4Tls", "bridge_line": "cert=BASE64...", "tls_server_name": "cdn.example.com" }
```

---

## Data storage

| File | Contents |
|------|----------|
| `~/.config/construct-tui/session.enc` | Encrypted session (keys + tokens). Argon2id + AES-256-GCM. |
| `~/.config/construct-tui/config.json` | Server URL + transport config (plaintext). |
| `~/.local/share/construct-tui/messages.db` | SQLCipher-encrypted message database. |

**Deleting everything:**
```bash
rm -rf ~/.config/construct-tui ~/.local/share/construct-tui
# or use the built-in subcommand:
konstrukt logout
```

---

## Development

```bash
# Debug build + run
cargo run

# With ICE transport
cargo run --features ice

# Run tests
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt

# Install git pre-commit hooks (fmt + clippy)
bash scripts/install-hooks.sh
```

---

## Security notes

- **Keys never leave the device** — the server only stores public keys.
- **Session file** is encrypted with Argon2id (64 MiB memory, 3 iterations) + AES-256-GCM. The Argon2id salt is stored alongside the ciphertext.
- **Messages** are stored in a SQLCipher AES-256 encrypted database. The DB key is derived from the same Argon2id master key via HKDF.
- **Signal Protocol** (X3DH + Double Ratchet) + optional **PQXDH** (Kyber-768) for post-quantum forward secrecy.
- **construct-ice** (obfs4-based) transport hides traffic from DPI — useful on censored networks.


| Dependency | Version |
|------------|---------|
| Rust toolchain | stable ≥ 1.85 |
| `libsqlcipher` | bundled (no system install needed) |
| `protoc` (Protocol Buffers compiler) | only if regenerating `.proto` |

```bash
# macOS
brew install rust

# Debian / Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Build

```bash
# Standard release build (direct TLS, no PQ)
cargo build --release

# With obfs4 DPI-bypass transport (construct-ice)
cargo build --release --features ice

# Post-quantum (Kyber-768 PQXDH) — for powerful devices (RPi 3B+ and up)
cargo build --profile release-pq --features post-quantum

# PQ + ICE (everything)
cargo build --profile release-pq --features post-quantum,ice
```

The binary is at `target/release/construct-tui` (or `target/release-pq/construct-tui` for the PQ build).

> **Note for Raspberry Pi Zero W:** Kyber-768 handshake takes ~60 s. Use the standard build without `post-quantum`.

---

## Run

```bash
# Defaults — connects to https://construct.cc
./construct-tui

# Override server
./construct-tui --server https://ams.konstruct.cc:443

# Enable obfs4 DPI-bypass (requires --features ice build)
./construct-tui --bridge "cert=BASE64... iat-mode=0"

# obfs4 + CDN SNI fronting
./construct-tui --bridge "cert=BASE64... iat-mode=0" --bridge-tls-sni cdn.example.com

# Disable at-rest encryption (headless / systemd use)
./construct-tui --no-encrypt
# or via env var:
CONSTRUCT_NO_ENCRYPT=1 ./construct-tui

# Post-quantum mode (binary must be built with --features post-quantum)
./construct-tui --post-quantum

# Headless daemon (receive messages without a terminal UI)
./construct-tui --headless

# Custom config file
./construct-tui --config /etc/construct/config.json

# Delete local session and all keys
./construct-tui logout
```

---

## First run

1. **Register** — enter a username. The client generates Ed25519 + X25519 keys locally, solves a proof-of-work challenge, and registers the device with the server.
2. **Set passphrase** — protects your session and message database with Argon2id + AES-256-GCM at rest. Leave empty to skip encryption (use `--no-encrypt` or `CONSTRUCT_NO_ENCRYPT`).
3. **Chat** — you're in.

On subsequent runs the session is loaded from disk and decrypted with your passphrase.

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
| `a` | Add contact (search) |
| `q` | Quit (when compose is not focused) |
| `Ctrl+C` | Force quit (any screen) |

### Settings screen

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Select / confirm |
| `Esc` / `q` | Back to chat |

### Add contact (search overlay)

| Key | Action |
|-----|--------|
| Type | Search by username |
| `↑` / `↓` | Navigate results |
| `Ctrl+A` | Add selected contact |
| `Esc` | Close |

---

## Config file

Stored at `~/.config/construct-tui/config.json`. Created automatically on first run.

```json
{
  "server": "https://konstruct.cc",
  "transport": {
    "mode": "Direct"
  }
}
```

**Transport modes:**

```json
// Direct TLS (default)
{ "mode": "Direct" }

// obfs4 obfuscation
{ "mode": "Obfs4", "bridge_line": "cert=BASE64... iat-mode=0" }

// obfs4 + SNI fronting
{ "mode": "Obfs4Tls", "bridge_line": "cert=BASE64...", "tls_server_name": "cdn.example.com" }
```

---

## Data storage

| File | Contents |
|------|----------|
| `~/.config/construct-tui/session.enc` | Encrypted session (keys + tokens). Argon2id + AES-256-GCM. |
| `~/.config/construct-tui/config.json` | Server URL + transport config (plaintext). |
| `~/.local/share/construct-tui/messages.db` | SQLCipher-encrypted message database. |

**Deleting everything:**
```bash
rm -rf ~/.config/construct-tui ~/.local/share/construct-tui
# or use the built-in subcommand:
./construct-tui logout
```

---

## Development

```bash
# Debug build + run
cargo run

# With ICE transport
cargo run --features ice

# Run tests
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt

# Install git pre-commit hooks (fmt + clippy)
bash scripts/install-hooks.sh
```

---

## Security notes

- **Keys never leave the device** — the server only stores public keys.
- **Session file** is encrypted with Argon2id (64 MiB memory, 3 iterations) + AES-256-GCM. The Argon2id salt is stored alongside the ciphertext.
- **Messages** are stored in a SQLCipher AES-256 encrypted database. The DB key is derived from the same Argon2id master key via HKDF.
- **Signal Protocol** (X3DH + Double Ratchet) + optional **PQXDH** (Kyber-768) for post-quantum forward secrecy.
- **construct-ice** (obfs4-based) transport hides traffic from DPI — useful on censored networks.
