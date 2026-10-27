# AGENTS.md — construct-tui

Terminal shell of the Konstruct client: Rust + Ratatui, binary `konstruct`. Crate, git repo and
config directory stay `construct-tui` on purpose. Since 2026-10-23 the repo holds only the
terminal (`src/main.rs`, `src/tui.rs`, `src/event.rs`); the client layer and the screens live in
[`construct-client`](https://github.com/konstruct-msg/construct-client), checked out next to it.
Behind iOS; **not** a production-usable messenger. Protocol behaviour comes from
`construct-messenger`, not from this tree or the archived April 2026 TUI guide.

If a rule here and your plan disagree, the rule wins until a `decisions/` note says otherwise.

## Read first

| Area | Read |
|---|---|
| Why these rules exist; checklist before any protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Forward plan, current gaps | `~/Code/construct-docs/client/TUI_DEVELOPMENT_GUIDE.md` |
| Why gRPC is in-tree | `~/Code/construct-docs/decisions/tui-in-tree-grpc.md` |
| Protocol behaviour (source of truth) | `construct-messenger` + `~/Code/construct-docs/client/ios/ARCHITECTURE_NOTES.md` |
| Session / identity / AD | `~/Code/construct-docs/decisions/identity-spaces.md` |
| Handshake vs leftover | `~/Code/construct-docs/decisions/message-number-zero-is-not-a-handshake.md` |
| Stream cursor / reconnect | `~/Code/construct-docs/decisions/stream-cursor-stall-anatomy.md` |
| Content-type mappings | `~/Code/construct-docs/decisions/wire-format-one-authority.md` |
| Binary data / CFE | `~/Code/construct-docs/client/shared/construct-ffi-binary-format.md` |
| Product wording | `~/Code/construct-docs/client/GLOSSARY_PRODUCT_LANGUAGE.md` |
| Protos | sibling `construct-protos`; `~/Code/construct-docs/decisions/protos-are-vendored-not-copied.md` |
| Engine is dead | `~/Code/construct-docs/decisions/macos-desktop-strategy.md` |
| Testing | `~/Code/construct-docs/decisions/testing-by-pure-decision.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md` — change it there first.

## Rules

1. **Prior art first.** Before any protocol mechanism, write down how Signal / MLS / Matrix solve it and why we deviate. The reference client is iOS.
2. **The core decides, this client executes.** If two clients must compute it identically, or it touches ratchet/session state or a session's lifecycle, it is a `construct-core` call. A decision reimplemented here does not fail loudly — the message just never appears. Look in `construct-core/src/construct_core.udl` first.
3. **A control message names the state it refers to.** A timer, cooldown, window, tie-break or retry budget in a fix means the message has no address.
4. **Reproduce before fixing.** Live 1:1 against iOS is the gate; a fix counts when the case that was red turns green.
5. **One meaning, one carrier.** Device id and account id are different types; content-type meaning is the conformance file, not this crate. Read `decisions/one-meaning-two-carriers.md` before adding a field, counter or timeout.
6. **Binary stays binary**, source to destination (see Binary data).
7. **Measure, then build** (network, transport, battery): a measurement on the real path before a mechanism.
8. **Verify the effect, not the exit code.**
9. **A test must be able to fail.** Put the decision in a pure function and mutation-check the test.
10. **Depth before breadth.** 1:1 text against iOS before VEIL, groups or polish.
11. **A temporary exception has an end date and a check.**
12. **Branch and PR, always** (see Git).

A change on the delivery or crypto path answers three questions in its commit message: what does the server or any relay learn that it did not before; what can a party (server, sender, sibling device) withhold or substitute that it could not before; which trust boundary moves, and which way.

## Invariants of this repo

- **`construct-client` knows no front end; the compiler holds the line** (`the_client_crate_depends_on_no_front_end`). `app.rs` sends `ClientCommand`s and renders `ClientEvent`s; it never calls into the client or waits on it.
- **Nothing two clients must compute identically lives in the front end.** Key material stays in the client; the safety number is the core's `compute_safety_number` over device ids. A decision in `app.rs` is one the desktop shell must make again.
- **Front-end preferences are the front end's**: the theme is `ui.json` (`src/theme.rs`), not the client's `config.json`.
- **Content types:** values come from the generated enum (`ContentType::SessionPing as u8`), never `= 25`. What to do with one is `construct-protos/conformance/knst_content_types.json`, read by `knst::tests::content_type_vectors_match_this_table` (`build.rs` exports `CONSTRUCT_PROTOS_DIR`). A new type adds its row there in the same change.
- **`construct-engine` does not come back** — no `EngineAdapter`, no `UiEvent`/`PlatformAction` façade.
- **Do not depend on `construct-transport`.** It is the iOS QUIC pipe wanting a pinned gateway cert; the TUI speaks HTTP/2 with the platform trust store (QUIC to the H2 host times out). `decisions/tui-in-tree-grpc.md`.
- **Screens and `app.rs` do not import `h3` / `quinn` / `construct-core`**; crypto goes through the client's `orchestrator_task`, network through its `grpc/`.
- **INITIATOR and RESPONDER init paths are distinct** (`init_session` vs `init_receiving_session`); higher deviceId wins as INITIATOR. The iOS "one init path" shortcut gives a permanent AEAD failure against a phone.
- **Everything handed to the core is a `CryptoDeviceId` (32-char hex), including the core's own local id; `ServerUserId` (36-char UUID) is for the server and screens.** Mixing breaks the Double Ratchet AD (see `peers.rs` in construct-client).
- **`messageNumber == 0` is not a handshake**; treating it as one loops leftovers on every reconnect.
- **Device keys are deleted only on gRPC UNAUTHENTICATED (16) / PERMISSION_DENIED (7)**, never on a transport error.
- **Advance `since_cursor` only after durable persist** — the server trims to it. The initial poll currently rewinds (`backend/MESSAGING_INITIAL_POLL_IGNORES_SINCE_CURSOR.md`); reconnect must tolerate redelivery.
- **A producer with no consumer is a defect**: a send, signal or action lands with its reader, or is removed. An unconsumed control message still costs a ratchet advance.
- **VEIL is not ICE and is not wired.** `--bridge` / `--headless` / `--config` are clap flags, not behaviour. Do not resume obfs4 / `construct-ice`; VEIL is phase D, after 1:1 text works.
- **No `construct-ice` `[patch]`**; a gitignored `.cargo/config.toml` pointing at it breaks `cargo check --offline`.

### Binary data

Keys, ciphertexts and wire payloads are bytes end to end (protobuf `bytes` or CFE). Base64 only at true text boundaries (QR, invite links). Session state the Orchestrator persists comes from `export_session_bytes_for`, not JSON.

### Build and test

Toolchain stable **1.96** (`rust-toolchain.toml`; core's `rust-version` is 1.96, an older host fails with an error that looks like a crate problem). Default features include `post-quantum`; there is no `ice` feature. Do not copy `.proto` files (the client's `build.rs` reads `CONSTRUCT_PROTOS_DIR`). Siblings under `~/Code/`: `construct-client`, `construct-core`, `construct-protos`.

```bash
cargo build --release   # target/release/konstruct
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

Tests cover storage and safety-number helpers only; extract the decision and mutate it. There is no CI and none may be added that cannot compile sibling path deps.

### Conventions

- Screens are Ratatui `Widget`s in construct-screens; state lives in `App`.
- Plain-language copy ("people / chats / device"); product name **Konstruct** in Latin; code keeps domain names.
- Config `~/.config/construct-tui/` (`session.enc`, `config.json`); data `~/.local/share/construct-tui/` (`messages.db`, `konstruct.log`); Argon2id 32 MiB.
- Comment only non-obvious logic; a field left out on purpose at a boundary says so in a comment.

## Git and process

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from an up-to-date `main`, PR into `main`. Conventional Commits. Agents push and open the PR only when asked.
- Check branch and `git status` before every commit; never `checkout -- .`, `reset --hard` or `stash` in a shared tree; never rewrite pushed history. A commit made on `main` by mistake and not pushed: `git branch <topic> && git reset --keep origin/main && git switch <topic>`.
- Docs live in `~/Code/construct-docs` (its `AGENTS.md` is authoritative). After work: progress to the task note; a root cause or rejected alternatives to `sessions/` (with `## Why`); a constraint to `decisions/`; one line to `log.md`.
