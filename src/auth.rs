//! High-level authentication flow for construct-tui.
//!
//! On first run: generate device keys → PoW → RegisterDevice → save Session.
//! On returning: load Session → AuthenticateDevice → update tokens.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use construct_core::{
    crypto::{
        keys::{build_prologue, Ed25519KeyPair, X25519KeyPair},
        SuiteID,
    },
    device_id::derive_device_id,
};
use ed25519_dalek::Signer;

use crate::{
    config::{load_session, save_session, Session},
    grpc::{
        services::DevicePublicKeys,
        ConstructClient,
    },
};

/// Result of a successful auth (returned to the UI layer).
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
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

    Ok(Some(AuthResult {
        user_id: updated.user_id,
        device_id: updated.device_id,
        access_token: resp.access_token,
    }))
}

/// Register a brand-new device and save the resulting session.
/// `username` is optional (display name hint sent to the server).
pub async fn register_new_device(
    server_url: &str,
    username: Option<&str>,
) -> Result<AuthResult> {
    // 1. Generate device keys
    let signing_pair = Ed25519KeyPair::generate();
    let identity_pair = X25519KeyPair::generate();
    let spk_pair = X25519KeyPair::generate();

    // 2. Derive device_id from identity public key
    let device_id = derive_device_id(&identity_pair.public_key);

    // 3. Sign the SPK: prologue || spk_public_key (standard X3DH SPK signing)
    let prologue = build_prologue(SuiteID::CLASSIC);
    let mut spk_msg = prologue;
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let sk = signing_pair.get_signing_key();
    let spk_sig = sk.sign(&spk_msg);

    // 4. Build DevicePublicKeys proto message
    let public_keys = DevicePublicKeys {
        verifying_key: B64.encode(signing_pair.public_key),
        identity_public: B64.encode(identity_pair.public_key),
        signed_prekey_public: B64.encode(spk_pair.public_key),
        signed_prekey_signature: B64.encode(spk_sig.to_bytes()),
        crypto_suite: "Curve25519+Ed25519".into(),
    };

    // 5. Connect and register (includes PoW)
    let mut client = ConstructClient::connect(server_url)
        .await
        .context("connecting to server")?;

    let resp = client
        .register(username, &device_id, public_keys)
        .await
        .context("registering new device")?;

    // 6. Persist session
    let session = Session {
        signing_key_hex: hex::encode(*signing_pair.private_key),
        identity_key_hex: hex::encode(*identity_pair.private_key),
        device_id: device_id.clone(),
        user_id: resp.user_id.clone(),
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at: resp.expires_at,
    };
    save_session(&session)?;

    Ok(AuthResult {
        user_id: resp.user_id,
        device_id,
        access_token: resp.access_token,
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
        verifying_key: B64.encode(signing_pair.public_key),
        identity_public: B64.encode(identity_pair.public_key),
        signed_prekey_public: B64.encode(spk_pair.public_key),
        signed_prekey_signature: B64.encode(spk_sig.to_bytes()),
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

    // 3. Persist session
    let session = Session {
        signing_key_hex: hex::encode(*signing_pair.private_key),
        identity_key_hex: hex::encode(*identity_pair.private_key),
        device_id: device_id.clone(),
        user_id: resp.user_id.clone(),
        access_token: resp.access_token.clone(),
        refresh_token: resp.refresh_token.clone(),
        expires_at: resp.expires_at,
    };
    save_session(&session)?;

    Ok(AuthResult {
        user_id: resp.user_id,
        device_id,
        access_token: resp.access_token,
    })
}
