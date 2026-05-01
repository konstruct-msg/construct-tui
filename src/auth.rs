//! High-level authentication flow for construct-tui.
//!
//! On first run: generate device keys → PoW → RegisterDevice → save Session.
//! On returning: load Session → AuthenticateDevice → update tokens.

use anyhow::{Context, Result};

use construct_core::{
    crypto::{
        SuiteID,
        keys::{Ed25519KeyPair, X25519KeyPair, build_prologue},
    },
    device_id::derive_device_id,
};
use ed25519_dalek::Signer;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use crate::{
    config::{Session, load_session, save_session},
    grpc::{ConstructClient, services::DevicePublicKeys},
};

/// Each step of registration, sent to the UI as it progresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStep {
    GeneratingSigningKey,
    GeneratingIdentityKey,
    GeneratingPreKey,
    SigningPreKey,
    Connecting,
    SolvingPoW,
    Registering,
}

impl RegistrationStep {
    /// Index corresponding to `screens::registration::STEPS` order.
    pub fn index(self) -> usize {
        match self {
            Self::GeneratingSigningKey => 0,
            Self::GeneratingIdentityKey => 1,
            Self::GeneratingPreKey => 2,
            Self::SigningPreKey => 3,
            Self::Connecting => 4,
            Self::SolvingPoW => 5,
            Self::Registering => 6,
        }
    }
}

/// Minimum time each step stays visible so the user can read it (ms).
const MIN_STEP_MS: u64 = 500;

/// Result of a successful auth (returned to the UI layer).
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    /// The full session for new registrations/links, or an updated session after
    /// encrypted-session restore (contains refreshed tokens). `None` for plaintext restores
    /// (those handle their own persistence in `try_restore_session`).
    pub session: Option<crate::config::Session>,
}

/// Try to authenticate using a saved session.
/// Returns `None` if no session file exists.
pub async fn try_restore_session(server_url: &str) -> Result<Option<AuthResult>> {
    let Some(session) = load_session()? else {
        return Ok(None);
    };

    let mut client = ConstructClient::connect(server_url)
        .await
        .context("connecting to server")?;

    let resp = client
        .authenticate(&session.device_id, &session.signing_key_hex)
        .await
        .context("re-authenticating saved session")?;

    // Refresh stored tokens
    let mut updated = session.clone();
    updated.access_token = resp.access_token.clone();
    updated.refresh_token = resp.refresh_token.clone();
    updated.expires_at = resp.expires_at;
    save_session(&updated)?;

    let user_id = updated.user_id.clone();
    let device_id = updated.device_id.clone();
    Ok(Some(AuthResult {
        user_id,
        device_id,
        access_token: resp.access_token,
        session: Some(updated), // always return session so App can start the Orchestrator
    }))
}

/// Register a brand-new device and save the resulting session.
/// `username` is optional (display name hint sent to the server).
/// `progress_tx` receives step updates for the UI checklist; send errors are silently ignored.
pub async fn register_new_device(
    server_url: &str,
    username: Option<&str>,
    progress_tx: &mpsc::UnboundedSender<RegistrationStep>,
) -> Result<AuthResult> {
    let step = |s: RegistrationStep| {
        let _ = progress_tx.send(s);
    };

    // 1. Generate device keys — each step has a minimum display time
    step(RegistrationStep::GeneratingSigningKey);
    let signing_pair = Ed25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::GeneratingIdentityKey);
    let identity_pair = X25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::GeneratingPreKey);
    let spk_pair = X25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::SigningPreKey);
    // 2. Derive device_id from identity public key
    let device_id = derive_device_id(&identity_pair.public_key);
    // 3. Sign the SPK: prologue || spk_public_key (standard X3DH SPK signing)
    let prologue = build_prologue(SuiteID::CLASSIC);
    let mut spk_msg = prologue;
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let sk = signing_pair.get_signing_key();
    let spk_sig = sk.sign(&spk_msg);
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    // 4. Build DevicePublicKeys proto message
    let public_keys = DevicePublicKeys {
        verifying_key: signing_pair.public_key.to_vec(),
        identity_public: identity_pair.public_key.to_vec(),
        signed_prekey_public: spk_pair.public_key.to_vec(),
        signed_prekey_signature: spk_sig.to_bytes().to_vec(),
        crypto_suite: "Curve25519+Ed25519".into(),
    };

    // 5. Connect to server
    step(RegistrationStep::Connecting);
    let mut client = ConstructClient::connect(server_url)
        .await
        .context("connecting to server")?;
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    // 6. Solve proof-of-work and register (variable duration — no artificial delay)
    step(RegistrationStep::SolvingPoW);
    let resp = client
        .register(username, &device_id, public_keys)
        .await
        .context("registering new device")?;

    // 7. Brief "Registering identity" confirmation before transitioning
    step(RegistrationStep::Registering);
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    // 8. Build session (caller is responsible for saving — encrypted or plaintext)
    let session = Session {
        signing_key_hex: hex::encode(*signing_pair.private_key),
        identity_key_hex: hex::encode(*identity_pair.private_key),
        device_id: device_id.clone(),
        user_id: resp.user_id.clone(),
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at: resp.expires_at,
        spk_key_hex: hex::encode(*spk_pair.private_key),
        spk_sig_hex: hex::encode(spk_sig.to_bytes()),
    };

    Ok(AuthResult {
        user_id: resp.user_id,
        device_id,
        access_token: resp.access_token,
        session: Some(session),
    })
}

/// Link this TUI client to an existing account using a link token
/// generated on another device (iOS/Desktop Settings → Add Device).
///
/// Generates fresh device keys, then calls `ConfirmDeviceLink` with the token.
pub async fn link_existing_device(server_url: &str, link_token: &str) -> Result<AuthResult> {
    // 1. Generate fresh device keys (same as register_new_device)
    let signing_pair = Ed25519KeyPair::generate();
    let identity_pair = X25519KeyPair::generate();
    let spk_pair = X25519KeyPair::generate();

    let device_id = derive_device_id(&identity_pair.public_key);

    let prologue = build_prologue(SuiteID::CLASSIC);
    let mut spk_msg = prologue;
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let sk = signing_pair.get_signing_key();
    let spk_sig = sk.sign(&spk_msg);

    let public_keys = DevicePublicKeys {
        verifying_key: signing_pair.public_key.to_vec(),
        identity_public: identity_pair.public_key.to_vec(),
        signed_prekey_public: spk_pair.public_key.to_vec(),
        signed_prekey_signature: spk_sig.to_bytes().to_vec(),
        crypto_suite: "Curve25519+Ed25519".into(),
    };

    // 2. Confirm link — server verifies the token and returns JWT
    let mut client = ConstructClient::connect(server_url)
        .await
        .context("connecting to server")?;

    let resp = client
        .confirm_device_link(link_token, &device_id, public_keys)
        .await
        .context("confirm_device_link RPC failed")?;

    // 3. Build session (caller is responsible for saving — encrypted or plaintext)
    let session = Session {
        signing_key_hex: hex::encode(*signing_pair.private_key),
        identity_key_hex: hex::encode(*identity_pair.private_key),
        device_id: device_id.clone(),
        user_id: resp.user_id.clone(),
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at: resp.expires_at,
        spk_key_hex: hex::encode(*spk_pair.private_key),
        spk_sig_hex: hex::encode(spk_sig.to_bytes()),
    };

    Ok(AuthResult {
        user_id: resp.user_id,
        device_id,
        access_token: resp.access_token,
        session: Some(session),
    })
}

/// Authenticate using a session that was already loaded from disk (e.g. after decryption).
/// Unlike `try_restore_session`, this does NOT touch the session file — the caller is
/// responsible for re-saving the session with updated tokens.
pub async fn authenticate_saved_session(
    mut session: Session,
    server_url: &str,
) -> Result<AuthResult> {
    let mut client = ConstructClient::connect(server_url)
        .await
        .context("connecting to server")?;

    let resp = client
        .authenticate(&session.device_id, &session.signing_key_hex)
        .await
        .context("re-authenticating session")?;

    // Update tokens in-memory
    session.access_token = resp.access_token.clone();
    session.refresh_token = resp.refresh_token.clone();
    session.expires_at = resp.expires_at;

    let user_id = session.user_id.clone();
    let device_id = session.device_id.clone();

    Ok(AuthResult {
        user_id,
        device_id,
        access_token: resp.access_token,
        session: Some(session),
    })
}
