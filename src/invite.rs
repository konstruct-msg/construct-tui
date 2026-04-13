//! Generates signed invite QR payloads compatible with the Construct iOS client.
//!
//! Format: Base64(JSON(InviteObject v3))
//! The iOS `MessagePackHelper` is currently JSON-backed (TODO: Protobuf in Phase 6),
//! so the same Base64(JSON) encoding works cross-platform.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Serialize;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Mirrors InviteObject v3 from the iOS client.
/// JSON-encoded then Base64-encoded for QR payload.
#[derive(Serialize)]
struct InviteObject {
    v: u8,
    jti: String,
    uuid: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    server: String,
    #[serde(rename = "ephKey")]
    eph_key: String,
    ts: u64,
    sig: String,
    // `un` intentionally omitted (TUI has no username in session) — omitting
    // the field is equivalent to `un = nil` on iOS, which the server treats as "".
}

/// Generates a signed invite QR payload.
///
/// Returns a Base64 string that the iOS scanner accepts directly.
/// The invite expires in 5 minutes (server-enforced TTL).
pub fn generate_invite_qr(
    user_id: &str,
    device_id: &str,
    server_url: &str,
    signing_key_hex: &str,
) -> Result<String> {
    // Normalize server: strip scheme and trailing slash
    let server = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();

    // Ephemeral X25519 keypair — unique per invite
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let eph_key = BASE64.encode(eph_public.as_bytes());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();

    let jti = Uuid::new_v4().to_string();

    // v3 canonical string: v|jti|uuid|deviceId|server|ephKey|ts|un
    // `un` is empty string when absent (matches iOS `un ?? ""`)
    let canonical = format!("3|{jti}|{user_id}|{device_id}|{server}|{eph_key}|{ts}|");

    let sk_bytes = hex::decode(signing_key_hex).context("invalid signing key hex")?;
    let sk_array: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&sk_array);
    let signature = signing_key.sign(canonical.as_bytes());
    let sig = BASE64.encode(signature.to_bytes());

    let invite = InviteObject {
        v: 3,
        jti,
        uuid: user_id.to_string(),
        device_id: device_id.to_string(),
        server,
        eph_key,
        ts,
        sig,
    };

    let json = serde_json::to_string(&invite).context("failed to serialize invite")?;
    let encoded = BASE64.encode(json.as_bytes());
    // Wrap in the deep-link URL expected by the iOS scanner:
    // konstruct://add?invite=<base64>
    Ok(format!("konstruct://add?invite={encoded}"))
}
