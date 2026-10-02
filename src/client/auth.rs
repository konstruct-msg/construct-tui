//! Getting in and out: restore, unlock, register, link, the passphrase for a new account, the
//! outcome of an authentication, and logout.

use tokio::sync::mpsc;

use super::{Client, ClientEvent};
use crate::{
    auth::RegistrationStep,
    bridge::BridgeEvent,
    config::{self, Session, SessionState},
    storage::StoredContact,
};

/// The outcome of an authentication attempt, sent from the task that ran it.
#[derive(Debug)]
pub(crate) enum AuthMsg {
    Success(Box<AuthSuccess>),
    Failure(String),
}

#[derive(Debug)]
pub(crate) struct AuthSuccess {
    pub(super) user_id: String,
    pub(super) device_id: String,
    pub(super) access_token: String,
    /// Full session including private keys — used to construct the Orchestrator.
    pub(super) full_session: Session,
    /// When `Some`, this session must be persisted to disk (new/updated).
    pub(super) pending_save: Option<Session>,
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

impl Client {
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
