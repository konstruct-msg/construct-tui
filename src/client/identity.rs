//! Our identity: the safety-number pair for a contact, export of the identity key, and the
//! invite our QR code shows.

use base64::Engine as _;

use super::{Client, ClientEvent};

impl Client {
    /// Our identity key and the person's, for the safety number. The person's is zeros until
    /// their key has been fetched.
    pub(super) fn safety_number(&self, contact_id: String) {
        let Some(ours) = self.our_identity_key.as_deref().map(key32) else {
            return self.emit(ClientEvent::Notice("Identity key not available".into()));
        };
        let theirs = self
            .read_storage
            .as_ref()
            .and_then(|s| s.get_contact_by_id(&contact_id).ok().flatten())
            .filter(|c| !c.identity_key_b64.is_empty())
            .and_then(|c| {
                base64::engine::general_purpose::STANDARD
                    .decode(&c.identity_key_b64)
                    .ok()
            })
            .map(|v| key32(&v))
            .unwrap_or([0u8; 32]);
        self.emit(ClientEvent::SafetyNumberKeys {
            contact_id,
            ours,
            theirs,
        });
    }

    /// Write our identity public key to `~/construct_identity_<user>.txt`.
    pub(super) fn export_identity_key(&self) {
        let Some(key) = self.our_identity_key.as_ref() else {
            return self.emit(ClientEvent::Notice("Identity key not available".into()));
        };
        let hex = hex::encode(key);
        let path = format!(
            "{}/construct_identity_{}.txt",
            std::env::var("HOME").unwrap_or_else(|_| ".".into()),
            &self.user_id,
        );
        let notice = match std::fs::write(
            &path,
            format!("identity_public_key_hex={hex}\nuser_id={}\n", self.user_id),
        ) {
            Ok(()) => format!("Key exported → {path}"),
            Err(e) => format!("Export failed: {e}"),
        };
        self.emit(ClientEvent::Notice(notice));
    }

    /// Mint an invite for our QR code. The signing key stays here: the front end gets the
    /// payload, never the key (until 2026-10-02 the settings screen held it to mint invites).
    pub(super) fn mint_invite(&self) {
        let Some(signing_key_hex) = self.current_session.as_ref().map(|s| &s.signing_key_hex)
        else {
            return self.emit(ClientEvent::InviteMinted(Err("Not signed in".into())));
        };
        let result = crate::invite::generate_invite_qr(
            &self.user_id,
            &self.device_id,
            &self.server_url,
            signing_key_hex,
            // No recovery key in this client yet, so no account address to sign.
            None,
        )
        .map_err(|e| format!("{e:#}"));
        self.emit(ClientEvent::InviteMinted(result));
    }
}

/// Truncate or zero-pad a key slice to exactly 32 bytes.
fn key32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = v.len().min(32);
    out[..len].copy_from_slice(&v[..len]);
    out
}
