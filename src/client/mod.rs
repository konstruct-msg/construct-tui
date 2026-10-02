//! The client layer: account, session keys, the orchestrator, the message stream, storage and
//! contacts — everything this program is, apart from how it is shown.
//!
//! Nothing here knows the terminal, the drawing library, the screens or `App`;
//! `boundary_tests` fails if it starts to. A front end calls the methods below and reads [`ClientEvent`]s from the channel it
//! handed over; the terminal UI is the first such front end, a desktop window the second
//! (`decisions/desktop-is-the-tui-client-with-a-second-shell.md`).

mod inbound;

use base64::Engine as _;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{
    auth::RegistrationStep,
    bridge::{BridgeEvent, TokenRefreshMsg},
    config::{self, Session, SessionKey, SessionState, TransportConfig},
    grpc::GrpcClient,
    storage::{StoredContact, StoredMessage},
};

/// Results of background work, delivered to the front end over one channel.
pub(crate) enum ClientEvent {
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    Bridge(BridgeEvent),
    /// Result of a FindUser search.
    ContactSearchResult(Vec<SearchResult>),
    /// A search or an invite redemption failed.
    ContactSearchError(String),
    /// An invite was redeemed — the front end confirms with [`Client::add_contact`].
    InviteAccepted {
        user_id: String,
        username: String,
    },
    /// A registration step completed.
    RegistrationStep(RegistrationStep),
    /// MessageStream got gRPC 16 — refresh the bearer, do not wipe keys.
    StreamAuthRequired,
}

/// The outcome of an authentication attempt, sent from the task that ran it.
#[derive(Debug)]
pub(crate) enum AuthMsg {
    Success(Box<AuthSuccess>),
    Failure(String),
}

#[derive(Debug)]
pub(crate) struct AuthSuccess {
    user_id: String,
    device_id: String,
    access_token: String,
    /// Full session including private keys — used to construct the Orchestrator.
    full_session: Session,
    /// When `Some`, this session must be persisted to disk (new/updated).
    pending_save: Option<Session>,
}

/// One FindUser hit.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// What became of a successful authentication.
pub(crate) enum AuthOutcome {
    /// Saved, the orchestrator and stream are running; these are the stored contacts.
    Ready(Vec<StoredContact>),
    /// A new account with no passphrase yet: [`Client::set_passphrase`] finishes it.
    NeedsPassphrase,
    /// Saving the session failed.
    Failed(String),
}

/// What [`Client::find_contact`] started.
pub(crate) enum FindStarted {
    UsernameSearch,
    InviteRedemption,
}

/// Configuration derived from the config file and CLI overrides.
pub struct ClientConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub pq_active: bool,
}

pub(crate) struct Client {
    server_url: String,
    transport: TransportConfig,
    /// Skip at-rest encryption (headless / `--no-encrypt`).
    no_encrypt: bool,
    pq_active: bool,
    grpc: GrpcClient,
    events: mpsc::UnboundedSender<ClientEvent>,
    /// Derived key material for the active session (zeroized on drop / logout). `None` in
    /// `--no-encrypt` mode or before a passphrase is entered.
    session_key: Option<SessionKey>,
    /// The decrypted session in memory — re-saved on token refresh without a disk read.
    current_session: Option<Session>,
    /// A new session waiting for its passphrase before it is saved.
    pending_session: Option<Session>,
    user_id: String,
    device_id: String,
    access_token: String,
    /// Our identity public key, captured at orchestrator start; for safety numbers and export.
    our_identity_key: Option<Vec<u8>>,
    orch_handle: Option<crate::orchestrator_task::OrchestratorHandle>,
    stream_tx: Option<mpsc::Sender<crate::streaming::StreamCmd>>,
    /// Read connection for queries (messages, contacts); the orchestrator holds the writer.
    read_storage: Option<crate::storage::Storage>,
    /// The people the stream is subscribed for, in the order they were added.
    contact_ids: Vec<String>,
}

impl Client {
    pub(crate) fn new(cfg: ClientConfig, events: mpsc::UnboundedSender<ClientEvent>) -> Self {
        Self {
            grpc: GrpcClient::new(&cfg.server_url),
            server_url: cfg.server_url,
            transport: cfg.transport,
            no_encrypt: cfg.no_encrypt,
            pq_active: cfg.pq_active,
            events,
            session_key: None,
            current_session: None,
            pending_session: None,
            user_id: String::new(),
            device_id: String::new(),
            access_token: String::new(),
            our_identity_key: None,
            orch_handle: None,
            stream_tx: None,
            read_storage: None,
            contact_ids: Vec::new(),
        }
    }

    // ── Read-only state ─────────────────────────────────────────────────────────

    pub(crate) fn server_url(&self) -> &str {
        &self.server_url
    }
    pub(crate) fn transport_label(&self) -> &'static str {
        transport_label(&self.transport)
    }
    pub(crate) fn pq_active(&self) -> bool {
        self.pq_active
    }
    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }
    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }
    /// A passphrase has unlocked or created the session key.
    pub(crate) fn has_session_key(&self) -> bool {
        self.session_key.is_some()
    }
    pub(crate) fn signing_key_hex(&self) -> &str {
        self.current_session
            .as_ref()
            .map(|s| s.signing_key_hex.as_str())
            .unwrap_or("")
    }

    // ── Authentication ──────────────────────────────────────────────────────────

    /// What is on disk: an encrypted session, a plaintext one, or none.
    pub(crate) fn stored_session_state(&self) -> SessionState {
        config::detect_session()
    }

    /// Restore a plaintext session from disk (legacy / `--no-encrypt` path).
    pub(crate) fn restore_from_disk(&self) {
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::try_restore_session(&grpc).await {
                Ok(Some(result)) => {
                    let full = result
                        .session
                        .clone()
                        .expect("try_restore_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: None, // already saved inside try_restore_session
                    }))
                }
                Ok(None) => AuthMsg::Failure("no_session".into()),
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = tx.send(ClientEvent::Auth(msg));
        });
    }

    /// Open the encrypted session with a passphrase and authenticate it.
    pub(crate) fn unlock(&mut self, passphrase: &[u8]) -> Result<(), String> {
        match config::open_session_key(passphrase) {
            Ok(Some(sk)) => match config::load_session_encrypted(&sk) {
                Ok(Some(session)) => {
                    self.session_key = Some(sk);
                    self.authenticate_saved(session);
                    Ok(())
                }
                Ok(None) => Err("No session found".into()),
                Err(e) => Err(format!("Session corrupted: {e}")),
            },
            Ok(None) => Err("No session found".into()),
            Err(_) => Err("Wrong passphrase or corrupted session".into()),
        }
    }

    /// Authenticate a session already decrypted in memory.
    fn authenticate_saved(&self, session: Session) {
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = tx.send(ClientEvent::Auth(msg));
        });
    }

    /// Register a new account and device; steps arrive as [`ClientEvent::RegistrationStep`].
    pub(crate) fn register(&self, username: String) {
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        let name = (!username.is_empty()).then_some(username);

        let (step_tx, mut step_rx) = mpsc::unbounded_channel::<RegistrationStep>();
        let step_fwd_tx = tx.clone();
        tokio::spawn(async move {
            while let Some(s) = step_rx.recv().await {
                let _ = step_fwd_tx.send(ClientEvent::RegistrationStep(s));
            }
        });

        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&grpc, name.as_deref(), &step_tx).await
            {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("register_new_device always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = tx.send(ClientEvent::Auth(msg));
        });
    }

    /// Link this device to an existing account with a token from another device.
    pub(crate) fn link_device(&self, token: String) {
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::link_existing_device(&grpc, &token).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("link_existing_device always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = tx.send(ClientEvent::Auth(msg));
        });
    }

    /// Take in a successful authentication: tokens, persistence, and — once the session can be
    /// saved — the orchestrator and the stream.
    pub(crate) fn apply_auth_success(&mut self, success: AuthSuccess) -> AuthOutcome {
        let AuthSuccess {
            user_id,
            device_id,
            access_token,
            full_session,
            pending_save,
        } = success;
        self.user_id = user_id;
        self.device_id = device_id.clone();
        self.access_token = access_token.clone();
        self.grpc.set_token(Some(access_token));
        self.grpc.set_device_id(Some(device_id));
        self.current_session = Some(full_session.clone());

        let Some(session) = pending_save else {
            // Already saved (restore-from-disk path) — start right away.
            return self.start_or_fail(full_session);
        };
        self.start_token_refresh(&session);

        if let Some(ref sk) = self.session_key {
            // Keys already derived (unlock path, or link/register with existing keys).
            match config::save_session_encrypted(&session, sk) {
                Ok(()) => self.start_or_fail(full_session),
                Err(e) => AuthOutcome::Failed(format!("Save failed: {e}")),
            }
        } else if self.no_encrypt {
            match config::save_session(&session) {
                Ok(()) => self.start_or_fail(full_session),
                Err(e) => AuthOutcome::Failed(format!("Save failed: {e}")),
            }
        } else {
            // New registration — wait for a passphrase before opening the encrypted database.
            self.pending_session = Some(session);
            AuthOutcome::NeedsPassphrase
        }
    }

    fn start_or_fail(&mut self, session: Session) -> AuthOutcome {
        match self.start_orchestrator(session) {
            Ok(contacts) => AuthOutcome::Ready(contacts),
            Err(e) => {
                // The account is in; only the local engine failed. Report it and stay in.
                let _ = self
                    .events
                    .send(ClientEvent::Bridge(BridgeEvent::Error(e.clone())));
                AuthOutcome::Ready(Vec::new())
            }
        }
    }

    /// Protect a newly created session with a passphrase, save it, and start. `Ok(None)`:
    /// there was no new session waiting for one.
    pub(crate) fn set_passphrase(
        &mut self,
        passphrase: &[u8],
    ) -> Result<Option<Vec<StoredContact>>, String> {
        let Some(session) = self.pending_session.take() else {
            return Ok(None);
        };
        let sk = match config::create_session_key(passphrase) {
            Ok(sk) => sk,
            Err(e) => {
                self.pending_session = Some(session);
                return Err(format!("Key derivation failed: {e}"));
            }
        };
        if let Err(e) = config::save_session_encrypted(&session, &sk) {
            self.pending_session = Some(session);
            return Err(format!("Save failed: {e}"));
        }
        self.session_key = Some(sk);
        // The orchestrator waited for this: the database key comes from the passphrase.
        let contacts = match self.current_session.clone() {
            Some(full) => self.start_orchestrator(full).unwrap_or_else(|e| {
                let _ = self.events.send(ClientEvent::Bridge(BridgeEvent::Error(e)));
                Vec::new()
            }),
            None => Vec::new(),
        };
        Ok(Some(contacts))
    }

    // ── Orchestrator and stream ─────────────────────────────────────────────────

    /// Construct the Orchestrator, open storage, spawn the stream worker and the orchestrator
    /// task, and wire them together. Returns the stored contacts.
    fn start_orchestrator(&mut self, session: Session) -> Result<Vec<StoredContact>, String> {
        use crate::orchestrator_task::spawn_orchestrator_task;
        use crate::storage::Storage;
        use crate::streaming::{CursorTracker, spawn_stream_worker};
        use construct_core::{
            crypto::{client_api::ClassicClient, suites::classic::ClassicSuiteProvider},
            orchestration::orchestrator::Orchestrator,
        };

        let decode = |hex_str: &str| {
            hex::decode(hex_str).map_err(|e| format!("Orchestrator key decode error: {e}"))
        };
        let identity_secret = decode(&session.identity_key_hex)?;
        let signing_secret = decode(&session.signing_key_hex)?;
        let spk_secret = decode(&session.spk_key_hex)?;
        let spk_sig = decode(&session.spk_sig_hex)?;

        // The stream relay must unseal SealedInner.sender_cert_ciphertext before it can recover
        // the sender. Keep a private-key copy at that boundary; Double Ratchet decryption still
        // happens inside the orchestrator.
        let identity_secret_for_sealed = identity_secret.clone();

        let core_client = ClassicClient::<ClassicSuiteProvider>::from_keys(
            identity_secret,
            signing_secret,
            spk_secret,
            spk_sig,
        )
        .map_err(|e| format!("Orchestrator init error: {e}"))?;
        let mut orchestrator = Orchestrator::new(core_client, self.user_id.clone());

        // Two connections: the orchestrator writes, queries read.
        let (storage, read_storage) = if let Some(ref sk) = self.session_key {
            let db_key = sk.keys.database.as_ref();
            (Storage::open(db_key), Storage::open(db_key))
        } else {
            (Storage::open_unencrypted(), Storage::open_unencrypted())
        };
        let (storage, read_storage) = match (storage, read_storage) {
            (Ok(s1), Ok(s2)) => (s1, s2),
            (Err(e), _) | (_, Err(e)) => return Err(format!("Storage open error: {e}")),
        };

        let contacts = read_storage.get_contacts().unwrap_or_else(|e| {
            tracing::warn!("Failed to load contacts: {e}");
            Vec::new()
        });
        let contact_ids: Vec<String> = contacts.iter().map(|c| c.user_id.clone()).collect();

        // Restore core coordination state and per-contact DR material before the stream worker
        // can redeliver old envelopes. Without this the core starts with an empty session map
        // while secure_store still holds `session_<id>` / `archive_<id>` bytes.
        match read_storage.secure_load("construct.orchestrator_state") {
            Ok(Some(state)) if !state.is_empty() => {
                if let Err(e) = orchestrator.import_orchestrator_state_cfe(&state) {
                    tracing::warn!(error = %e, "failed to restore orchestrator coordination state");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "failed to load orchestrator coordination state"),
        }
        for contact_id in &contact_ids {
            match read_storage.secure_load(&format!("session_{contact_id}")) {
                Ok(Some(data)) => {
                    if let Err(error) = orchestrator.import_session_cfe(contact_id, &data) {
                        tracing::warn!(%contact_id, %error, "failed to restore session");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%contact_id, %error, "failed to load session"),
            }
        }

        // OTPKs and our identity key before the orchestrator moves into its task.
        let otpks = orchestrator.generate_otpks(100).unwrap_or_default();
        self.our_identity_key = orchestrator.identity_public_key_bytes().ok();

        let cursor = CursorTracker::load(&read_storage);
        self.read_storage = Some(read_storage);
        self.contact_ids = contact_ids.clone();

        let (stream_tx, stream_rx) =
            spawn_stream_worker(self.grpc.clone(), contact_ids.clone(), cursor.clone());
        self.stream_tx = Some(stream_tx.clone());

        let orch_handle = spawn_orchestrator_task(
            orchestrator,
            storage,
            stream_tx,
            self.events.clone(),
            self.grpc.clone(),
            cursor.clone(),
            contact_ids,
            self.user_id.clone(),
            self.device_id.clone(),
        );
        // AppLaunched triggers the session GC / prewarm sweep.
        orch_handle.send(construct_core::orchestration::actions::IncomingEvent::AppLaunched);
        self.orch_handle = Some(orch_handle.clone());

        if !otpks.is_empty() {
            tracing::info!("OTPKs generated: {} keys", otpks.len());
            let did = self.device_id.clone();
            let grpc = self.grpc.clone();
            tokio::spawn(async move {
                grpc.set_device_id(Some(did.clone()));
                if let Err(e) = crate::grpc::upload_pre_keys(&grpc, &did, otpks, false).await {
                    tracing::warn!("OTPK upload failed: {e}");
                }
            });
        }

        inbound::spawn_relay(
            stream_rx,
            orch_handle,
            cursor,
            self.events.clone(),
            identity_secret_for_sealed,
        );
        Ok(contacts)
    }

    // ── Tokens ──────────────────────────────────────────────────────────────────

    pub(crate) fn refresh_token_now(&self) {
        let Some(session) = self.current_session.clone() else {
            return;
        };
        let tx = self.events.clone();
        let mut rx = crate::bridge::spawn_token_refresh_now(
            self.grpc.clone(),
            session.device_id,
            session.refresh_token,
        );
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = tx.send(ClientEvent::TokenRefresh(msg));
            }
        });
    }

    fn start_token_refresh(&self, session: &Session) {
        let tx = self.events.clone();
        let mut rx = crate::bridge::spawn_token_refresh(
            self.grpc.clone(),
            session.device_id.clone(),
            session.refresh_token.clone(),
            session.expires_at,
        );
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = tx.send(ClientEvent::TokenRefresh(msg));
            }
        });
    }

    /// Take in a token-refresh result. `Err` is a status line for the front end.
    pub(crate) fn apply_token_refresh(&mut self, msg: TokenRefreshMsg) -> Result<(), String> {
        match msg {
            TokenRefreshMsg::Refreshed {
                access_token,
                refresh_token,
                expires_at,
            } => {
                self.access_token = access_token.clone();
                self.grpc.set_token(Some(access_token.clone()));
                if let Some(mut session) = self.current_session.clone() {
                    session.access_token = access_token;
                    session.refresh_token = refresh_token;
                    session.expires_at = expires_at;
                    self.persist_session(session);
                }
                Ok(())
            }
            TokenRefreshMsg::FailedTransport(e) => {
                tracing::warn!("Token refresh transport failure ({e}) — keeping tokens");
                Ok(())
            }
            TokenRefreshMsg::FailedAuth(e) => {
                tracing::warn!("Token refresh rejected ({e}) — attempting device re-auth");
                self.start_device_reauth()
            }
        }
    }

    /// Fall back to device signing-key authentication when the refresh token is expired or
    /// rejected (e.g. key rotation on redeploy). Success arrives as a normal
    /// [`AuthMsg::Success`], which updates tokens and persists the session.
    fn start_device_reauth(&self) -> Result<(), String> {
        let Some(session) = self.current_session.clone() else {
            return Err("Device re-auth failed: no session in memory".into());
        };
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full.clone(),
                        pending_save: Some(full),
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("Device re-auth failed: {e}")),
            };
            let _ = tx.send(ClientEvent::Auth(msg));
        });
        Ok(())
    }

    fn persist_session(&mut self, session: Session) {
        // Keep the in-memory copy fresh so token refreshes need no disk read.
        self.current_session = Some(session.clone());
        self.start_token_refresh(&session);
        if let Some(ref sk) = self.session_key {
            let _ = config::save_session_encrypted(&session, sk);
        } else if self.no_encrypt {
            let _ = config::save_session(&session);
        }
    }

    // ── Messages ────────────────────────────────────────────────────────────────

    /// Hand a text message to the orchestrator; returns its message id.
    pub(crate) fn send_text(&self, contact_id: &str, text: &str) -> String {
        let message_id = Uuid::new_v4().to_string();
        if let Some(ref orch) = self.orch_handle {
            orch.send(
                construct_core::orchestration::actions::IncomingEvent::OutgoingMessage {
                    contact_id: contact_id.to_string(),
                    message_id: message_id.clone(),
                    plaintext: text.as_bytes().to_vec(),
                    content_type: 0,
                },
            );
        }
        message_id
    }

    /// The last `limit` stored messages with one person, oldest first.
    pub(crate) fn history(&self, peer_id: &str, limit: usize) -> Vec<StoredMessage> {
        self.read_storage
            .as_ref()
            .and_then(|s| s.get_messages(peer_id, limit).ok())
            .unwrap_or_default()
    }

    // ── Contacts ────────────────────────────────────────────────────────────────

    /// Look a person up: an invite link is redeemed, anything else is a username search.
    /// Results arrive as [`ClientEvent::ContactSearchResult`] / `InviteAccepted` /
    /// `ContactSearchError`; `Err` is a message for the user, nothing started.
    pub(crate) fn find_contact(&self, raw: &str) -> Result<FindStarted, String> {
        let raw = raw.trim();
        if crate::invite::looks_like_invite(raw) {
            self.redeem_invite(raw)?;
            return Ok(FindStarted::InviteRedemption);
        }
        let query = crate::grpc::users::normalize_username(raw);
        if !crate::grpc::users::username_is_searchable(&query) {
            return Err("Username: 3–30 chars, letters/digits/_  (no @)".into());
        }
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let event = match crate::grpc::find_user(&grpc, &query).await {
                Ok(Some(user_id)) => ClientEvent::ContactSearchResult(vec![SearchResult {
                    user_id,
                    username: query.clone(),
                    display_name: query,
                }]),
                Ok(None) => ClientEvent::ContactSearchResult(vec![]),
                Err(e) => ClientEvent::ContactSearchError(e.to_string()),
            };
            let _ = tx.send(event);
        });
        Ok(FindStarted::UsernameSearch)
    }

    fn redeem_invite(&self, raw: &str) -> Result<(), String> {
        let invite = crate::invite::parse_invite(raw).map_err(|e| format!("Bad invite: {e:#}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if invite.is_expired(now) {
            return Err("Invite expired".into());
        }
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        let username = invite
            .un
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| invite.uuid[..8.min(invite.uuid.len())].to_string());
        tokio::spawn(async move {
            let event = match crate::grpc::accept_invite(&grpc, &invite).await {
                Ok(accepted) => ClientEvent::InviteAccepted {
                    user_id: accepted.user_id,
                    username,
                },
                Err(e) => ClientEvent::ContactSearchError(format!("Invite: {e}")),
            };
            let _ = tx.send(event);
        });
        Ok(())
    }

    /// Store a person, subscribe the stream to them, and tell the orchestrator.
    pub(crate) fn add_contact(&mut self, user_id: &str, username: &str) {
        if let Some(ref storage) = self.read_storage {
            let _ = storage.upsert_contact(&StoredContact {
                user_id: user_id.to_string(),
                display_name: username.to_string(),
                identity_key_b64: String::new(),
            });
        }
        if !self.contact_ids.iter().any(|id| id == user_id) {
            self.contact_ids.push(user_id.to_string());
        }
        self.resubscribe_stream();
        if let Some(ref orch) = self.orch_handle {
            orch.remember_contact(user_id.to_string());
        }
    }

    /// Remove a person and their messages.
    pub(crate) fn delete_contact(&mut self, peer_id: &str) -> Result<(), String> {
        if let Some(Err(e)) = self
            .read_storage
            .as_ref()
            .map(|s| s.delete_contact(peer_id))
        {
            return Err(format!("Delete failed: {e}"));
        }
        if let Some(ref orch) = self.orch_handle {
            orch.forget_contact(peer_id.to_string());
        }
        self.contact_ids.retain(|id| id != peer_id);
        self.resubscribe_stream();
        Ok(())
    }

    /// Re-subscribe the stream for the full contact set — never a subset.
    fn resubscribe_stream(&self) {
        let Some(ref stream_tx) = self.stream_tx else {
            return;
        };
        let stream_cursor = self
            .read_storage
            .as_ref()
            .and_then(|storage| storage.load_stream_cursor().ok().flatten());
        let _ = stream_tx.try_send(crate::streaming::StreamCmd::Subscribe(
            self.contact_ids.clone(),
            stream_cursor,
        ));
    }

    // ── Identity ────────────────────────────────────────────────────────────────

    /// Our identity key and the person's, for the safety number. The person's is zeros until
    /// their key has been fetched.
    pub(crate) fn safety_number_keys(
        &self,
        contact_id: &str,
    ) -> Result<([u8; 32], [u8; 32]), String> {
        let ours = self
            .our_identity_key
            .as_deref()
            .map(key32)
            .ok_or("Identity key not available")?;
        let theirs = self
            .read_storage
            .as_ref()
            .and_then(|s| s.get_contact_by_id(contact_id).ok().flatten())
            .filter(|c| !c.identity_key_b64.is_empty())
            .and_then(|c| {
                base64::engine::general_purpose::STANDARD
                    .decode(&c.identity_key_b64)
                    .ok()
            })
            .map(|v| key32(&v))
            .unwrap_or([0u8; 32]);
        Ok((ours, theirs))
    }

    /// Write our identity public key to `~/construct_identity_<user>.txt`; returns the path.
    pub(crate) fn export_identity_key(&self) -> Result<String, String> {
        let key = self
            .our_identity_key
            .as_ref()
            .ok_or("Identity key not available")?;
        let hex = hex::encode(key);
        let path = format!(
            "{}/construct_identity_{}.txt",
            std::env::var("HOME").unwrap_or_else(|_| ".".into()),
            &self.user_id,
        );
        std::fs::write(
            &path,
            format!("identity_public_key_hex={hex}\nuser_id={}\n", self.user_id),
        )
        .map_err(|e| format!("Export failed: {e}"))?;
        Ok(path)
    }

    /// Clear the session from disk and stop everything running for it.
    pub(crate) fn logout(&mut self) -> Result<(), String> {
        config::clear_session().map_err(|e| format!("Logout error: {e}"))?;
        // Dropping the handle stops the orchestrator task; the stream worker is told.
        self.orch_handle = None;
        if let Some(ref tx) = self.stream_tx.take() {
            let _ = tx.try_send(crate::streaming::StreamCmd::Shutdown);
        }
        if let Some(ref storage) = self.read_storage {
            let _ = storage.clear_stream_cursor();
        }
        self.grpc.set_token(None);
        self.grpc.set_device_id(None);
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            grpc.invalidate_h3().await;
        });
        self.read_storage = None;
        self.session_key = None;
        self.current_session = None;
        self.pending_session = None;
        self.our_identity_key = None;
        self.user_id.clear();
        self.device_id.clear();
        self.access_token.clear();
        self.contact_ids.clear();
        Ok(())
    }
}

pub(crate) fn transport_label(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Direct => "direct",
        TransportConfig::Obfs4 { .. } => "obfs4",
        TransportConfig::Obfs4Tls { .. } => "obfs4+tls",
        TransportConfig::CdnFront { .. } => "cdn-front",
    }
}

/// Truncate or zero-pad a key slice to exactly 32 bytes.
fn key32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = v.len().min(32);
    out[..len].copy_from_slice(&v[..len]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        let (tx, _rx) = mpsc::unbounded_channel();
        Client::new(
            ClientConfig {
                server_url: "https://localhost".into(),
                transport: TransportConfig::Direct,
                no_encrypt: true,
                pq_active: true,
            },
            tx,
        )
    }

    fn last_subscription(rx: &mut mpsc::Receiver<crate::streaming::StreamCmd>) -> Vec<String> {
        let mut last = None;
        while let Ok(cmd) = rx.try_recv() {
            if let crate::streaming::StreamCmd::Subscribe(ids, _) = cmd {
                last = Some(ids);
            }
        }
        last.expect("a subscription was sent")
    }

    /// Adding or removing one person re-subscribes for everyone, not just for them — a
    /// subscription for a subset silently stops delivery from the rest.
    #[test]
    fn the_stream_is_resubscribed_for_the_full_contact_set() {
        let mut client = client();
        let (stream_tx, mut stream_rx) = mpsc::channel(8);
        client.stream_tx = Some(stream_tx);

        client.add_contact("alice", "Alice");
        client.add_contact("bob", "Bob");
        assert_eq!(last_subscription(&mut stream_rx), vec!["alice", "bob"]);

        client.add_contact("alice", "Alice");
        assert_eq!(
            last_subscription(&mut stream_rx),
            vec!["alice", "bob"],
            "adding someone already there does not duplicate them"
        );

        client.delete_contact("alice").unwrap();
        assert_eq!(last_subscription(&mut stream_rx), vec!["bob"]);
    }
}

/// The client layer must not know how it is shown. A front-end type here would tie the desktop
/// shell to the terminal one, which is the coupling this module exists to remove.
#[cfg(test)]
mod boundary_tests {
    const SOURCES: &[(&str, &str)] = &[
        ("client/mod.rs", include_str!("mod.rs")),
        ("client/inbound.rs", include_str!("inbound.rs")),
    ];
    const FORBIDDEN: &[&str] = &[
        "ratatui",
        "crossterm",
        "crate::screens",
        "crate::app",
        "crate::tui",
    ];

    #[test]
    fn the_client_layer_imports_no_front_end() {
        for (file, source) in SOURCES {
            // Only code above the test modules counts — the list itself names the forbidden.
            let code = source.split("#[cfg(test)]").next().unwrap_or(source);
            for needle in FORBIDDEN {
                assert!(!code.contains(needle), "{file} mentions `{needle}`");
            }
        }
    }
}
