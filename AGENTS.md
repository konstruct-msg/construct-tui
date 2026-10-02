# AGENTS.md — construct-tui

Hard invariants for AI coding agents in this repository, and nothing else. Every rule here is
attached to the incident that produced it. Detail lives in the linked documents; read the one
covering your area **before** working in it.

| Area | Read first |
|---|---|
| Forward plan, current gaps | `~/Code/construct-docs/client/TUI_DEVELOPMENT_GUIDE.md` |
| Why gRPC is in-tree | `~/Code/construct-docs/decisions/tui-in-tree-grpc.md` |
| Protocol behaviour (source of truth) | `construct-messenger` + `~/Code/construct-docs/client/ios/ARCHITECTURE_NOTES.md` |
| Session / identity / AD | `~/Code/construct-docs/decisions/identity-spaces.md` |
| Handshake vs leftover | `~/Code/construct-docs/decisions/message-number-zero-is-not-a-handshake.md` |
| Stream cursor / reconnect | `~/Code/construct-docs/decisions/stream-cursor-stall-anatomy.md` |
| Binary data / CFE | `~/Code/construct-docs/client/shared/construct-ffi-binary-format.md` |
| Product wording | `~/Code/construct-docs/client/GLOSSARY_PRODUCT_LANGUAGE.md` |
| Protos | sibling `construct-protos`; `~/Code/construct-docs/decisions/protos-are-vendored-not-copied.md` |
| Engine is dead | `~/Code/construct-docs/decisions/macos-desktop-strategy.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) |

---

## Overview

Terminal UI client for Konstruct. Rust + Ratatui. Binary `konstruct`. Crate, git repo, and
config directory stay `construct-tui` — that split is deliberate (hygiene 2026-08-22: an
accidental binary rename fought the user-facing name; config was wrongly advertised as
`~/.config/konstruct/`).

This client is behind iOS and is **not** a production-usable messenger. Protocol behaviour
comes from `construct-messenger`, not from this tree or from the April 2026 TUI guide
(`construct-docs/_archive/TUI_DEVELOPMENT_GUIDE.md`).

Sibling checkouts under `~/Code/`: `construct-core` (path dep), `construct-protos` (prost
source of truth). GitHub org: [konstruct-msg](https://github.com/konstruct-msg).

---

## Build

Toolchain: stable **1.96** (`rust-toolchain.toml`). Core's `rust-version` is 1.96; a 1.92
host failed the first compile after the engine drop with an error that looked like a crate
problem.

```bash
cargo build --release              # binary at target/release/konstruct
cargo run
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

Default features include `post-quantum`. There is **no** `ice` feature. `construct-ice` is
gone; do not add a `[patch]` for it — a gitignored `.cargo/config.toml` pointing at
`../construct-ice` is what made `cargo check --offline` fail on a repo that no longer
exists.

Do not copy `.proto` files into this repo. `crates/construct-client/build.rs` reads
`CONSTRUCT_PROTOS_DIR`, default `../../../construct-protos` (a sibling of this checkout).

A workspace of two crates since 2026-10-02: the root package is the `konstruct` binary (the
terminal front end), `crates/construct-client` is everything else. Without `--workspace`, `cargo
test` and `cargo clippy` check only the binary.

---

## Architecture invariants

```
konstruct (src/)                     the terminal front end: screens, keys, drawing, theme
  app.rs  ── ClientCommand ──▶  construct-client (crates/construct-client)
          ◀── ClientEvent ───     client/            the client task: account, keys, contacts
                                  orchestrator_task  → construct-core Orchestrator
                                  grpc/              → gRPC-over-H2 (system-root TLS; ams.konstruct.cc)
```

- **`construct-client` knows no front end, and the compiler holds that line.** It has no
  Ratatui, crossterm or windowing dependency (`tests::the_client_crate_depends_on_no_front_end`
  reads its manifest), and it cannot name the binary's modules. The client runs as its own
  task: `app.rs` sends `ClientCommand`s through a `ClientHandle` and turns `ClientEvent`s into
  what is on screen — it never calls into the client or waits on it.
- **Nothing that two clients must compute identically lives in the front end.** Key material
  stays in the client (the invite is minted there; the settings screen held the signing key
  until 2026-10-02), and the safety number is the core's (`compute_safety_number` over device
  ids, the one iOS shows) — the front end computed its own until 2026-10-02 and could never
  have matched a phone. A decision made in `app.rs` is one the desktop shell would have to make
  again. Since 2026-10-02 (`decisions/desktop-is-the-tui-client-with-a-second-shell.md`): Linux
  and Windows get a second front end on `construct-client`, not a second client.
- **Front-end preferences are the front end's.** The theme is in `ui.json` beside the client's
  `config.json`, written by `src/theme.rs`; the client's config has no theme.

- **This client does not decide what a content type means.** It is the second implementation of
  the protocol, and the first comparison against iOS found the two already diverged: iOS held
  `{12,14,21,23,24,25,26}` as control, `knst::is_silent_type` held `{12,13,14,25,26}`. Both were
  defensible — they answered different questions nobody had written down — and nothing failed,
  because a divergence here is a payload that is a bubble on one client and nothing on the other.
  - Values come from the generated enum: `ContentType::SessionPing as u8`, never `= 25`.
  - What to do with a value is `construct-protos/conformance/knst_content_types.json`, read by
    `knst::tests::content_type_vectors_match_this_table`. `build.rs` exports
    `CONSTRUCT_PROTOS_DIR` so the test can `include_str!` it.
  - **Adding a content type means adding its row there in the same change.** A type this client
    has not learned then reddens that test on the next build.
  - `decisions/wire-format-one-authority.md` before touching `disposition()` or the constants.
- **`construct-engine` does not come back.** Retired from messenger 2026-07-28, dropped from
  this crate 2026-08-22. No `EngineAdapter`, no `UiEvent`/`PlatformAction` façade. See
  `decisions/macos-desktop-strategy.md` — the 2026-06-16 trigger "engine returns if a TUI
  push starts" is retired; the TUI push started and still does not use the engine.
- **Do not depend on `construct-transport`.** That crate is the iOS UniFFI QUIC pipe and
  `QuicClient::connect` wants a **pinned gateway cert** on `quic.konstruct.cc`. The TUI
  talks to `ams.konstruct.cc` over **HTTP/2** with the platform trust store (same as iOS
  TCP). QUIC handshake to `ams.konstruct.cc` times out — Traefik H3 was removed; that
  hostname is Caddy H2. Decision: `decisions/tui-in-tree-grpc.md`.
- **Screens and `app.rs` do not import `h3` / `quinn` / `construct-core`.** The binary does not
  depend on the core at all; crypto goes through the client's `orchestrator_task`, network I/O
  through its `grpc/`.
- **INITIATOR and RESPONDER init paths are distinct** (`init_session` vs
  `init_receiving_session`); tie-break: higher deviceId wins as INITIATOR. Copying the iOS
  "one init path" shortcut produces a permanent AEAD failure against a phone.
- **Session addressing uses `ServerUserId` (36-char UUID), never `CryptoDeviceId` (32-char
  hex).** Mixing the spaces breaks Double Ratchet AD.
- **`messageNumber == 0` is not a handshake.** A sending-chain restart looks the same as
  X3DH. Treating zero as "new session" is how leftovers loop on every reconnect.
- **Device keys are deleted only on gRPC UNAUTHENTICATED (16) / PERMISSION_DENIED (7)** —
  never on a transport error.
- **Advance `since_cursor` only after durable persist.** The server trims to that value.
  Optimistic advance deletes mail. The server also currently rewinds on the initial poll
  (`backend/MESSAGING_INITIAL_POLL_IGNORES_SINCE_CURSOR.md`); reconnect must tolerate
  redelivery.
- **A producer with no consumer is a defect.** If you add a send, a signal, or an action,
  the reader lands in the same change — or the sender is removed. An unconsumed control
  message still costs a ratchet advance (`__session_reset_notify__`, April 2026, four months
  of visible bubbles on multi-device accounts).
- **VEIL is not ICE and is not wired.** `--bridge` / `--headless` / `--config` are clap
  flags, not behaviour. Do not resume obfs4 / `construct-ice`. VEIL is phase D of the TUI
  plan, after 1:1 text works.

---

## Binary data

Same pipeline as iOS. Keys, ciphertexts, and wire payloads are bytes end to end — protobuf
`bytes` or CFE. No base64 in message processing, session management, or storage. Base64 only
at true text-transport boundaries (QR, invite links). Session state that the Orchestrator
asks to persist comes from `export_session_bytes_for`, not JSON.

---

## Code conventions

- TUI screens are Ratatui `Widget` impls in `screens/`. State lives in `App`; screens borrow
  it.
- User-facing copy is plain language ("people / chats / device", never "node / stream /
  replica"). Product name **Konstruct** in Latin. Code identifiers keep domain names.
- Config: `~/.config/construct-tui/` (`session.enc`, `config.json`). Data:
  `~/.local/share/construct-tui/` (`messages.db`, `konstruct.log`). Argon2id is 32 MiB.
- Comment only non-obvious logic. A field left out on purpose at a boundary must say so in
  a comment — an uncommented omission is indistinguishable from a forgotten one.
- [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope): …`,
  `fix(scope): …`, `refactor(scope): …`, `chore(scope): …`.

---

## Testing

**The target is not a coverage number.** A test that cannot fail is worse than no test —
it occupies the place where someone would otherwise have looked. Extract the decision
(identity space, handshake-vs-leftover, cursor prefix) and mutate it; do not assert that a
procedure returned. Method: `~/Code/construct-docs/decisions/testing-by-pure-decision.md`.

This crate currently tests storage and safety-number helpers only. Live 1:1 against iOS is
the gate for phase B, not a green `cargo test`.

There is no CI. Do not add a workflow that cannot compile this crate (sibling path deps).
CI was removed 2026-06-19 for that reason.

---

## Documentation & session notes

Docs live in `~/Code/construct-docs`. **The vault's `AGENTS.md` is authoritative** for
structure and writing rules. If a path is missing, search the domain folder rather than
trusting an old link.

After any session with architectural changes, design decisions, root-cause analysis or
non-obvious choices:

1. Write `sessions/YYYY-MM-DD-<topic>.md` (Context / What Changed / **Why** / Decisions /
   Open Questions) — `## Why` with rejected alternatives is mandatory.
2. If it constrains future work, add or update `decisions/<slug>.md`.
3. Patch the affected spec in its domain folder in the **same** session.
4. Append one line to `~/Code/construct-docs/log.md`.

## Git workflow (branch + PR only)

**Never commit on `main`.** Every change goes on a topic branch cut from an up-to-date `main`
(`feat|fix|docs|chore|test/<topic>`) and lands through a GitHub pull request. Agents push and
open the PR only when asked.

`main` is what a release is built from, so it moves only by a reviewed merge. From 2026-09-11 to
2026-10-01 changes went straight to `main` across the construct-* repos — two people on the
project made a branch per change look like ceremony. That was reversed on purpose: the habit has
to be in place before there is a release for it to break.

A commit that landed on `main` by mistake and is not pushed moves off it with
`git branch <topic> && git reset --keep origin/main && git switch <topic>`. Pushed history is
never rewritten.
