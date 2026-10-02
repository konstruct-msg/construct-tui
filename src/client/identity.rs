//! Our identity key: the safety-number pair for a contact, and export to a file.

use base64::Engine as _;

use super::Client;

impl Client {
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
}

/// Truncate or zero-pad a key slice to exactly 32 bytes.
fn key32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = v.len().min(32);
    out[..len].copy_from_slice(&v[..len]);
    out
}
