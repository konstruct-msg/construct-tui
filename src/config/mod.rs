use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

/// Persisted device identity (keys + tokens).
/// Stored in `~/.config/construct-tui/session.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Ed25519 device signing key (hex, 64 bytes — private).
    pub signing_key_hex: String,
    /// X25519 identity key (hex, 32 bytes — private).
    pub identity_key_hex: String,
    /// Server-assigned device ID (hex, typically 8 bytes).
    pub device_id: String,
    /// Server-assigned user ID (UUID).
    pub user_id: String,
    /// JWT access token.
    pub access_token: String,
    /// JWT refresh token.
    pub refresh_token: String,
    /// Token expiry (Unix seconds).
    pub expires_at: i64,
}

/// App-level config.
/// Stored in `~/.config/construct-tui/config.json`.
/// Transport layer selection — controls how gRPC traffic reaches the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode")]
pub enum TransportConfig {
    /// Direct TLS — default for uncensored networks.
    Direct,
    /// obfs4 obfuscation via construct-ice bridge line.
    /// Traffic looks like random noise to DPI systems.
    Obfs4 {
        /// Full bridge line: `"cert=BASE64 iat-mode=0"` or full obfs4 addr string.
        bridge_line: String,
    },
    /// obfs4 + outer TLS wrapper — SNI-based CDN fronting.
    Obfs4Tls {
        bridge_line: String,
        /// SNI hostname presented in the outer TLS ClientHello.
        tls_server_name: String,
    },
    /// Domain fronting through a CDN endpoint.
    CdnFront {
        cdn_endpoint: String,
        sni_host: String,
        real_host: String,
    },
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Direct
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: String,
    #[serde(default)]
    pub transport: TransportConfig,
}

/// Encrypted session blob stored on disk.
/// The presence of the `v` field distinguishes it from the legacy plaintext `Session`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedSession {
    /// Format version (always 1).
    pub v: u32,
    /// Argon2id salt (base64, 16 bytes).
    pub salt: String,
    /// AES-256-GCM nonce (base64, 12 bytes).
    pub nonce: String,
    /// Encrypted `Session` JSON (base64 + AES-256-GCM tag).
    pub ciphertext: String,
}

/// What kind of session file is present on disk.
pub enum SessionState {
    /// File exists and is AES-256-GCM encrypted.
    Encrypted,
    /// File exists as legacy plaintext JSON.
    Plaintext,
    /// No session file found.
    None,
}

/// Detect what kind of session file exists without loading keys.
pub fn detect_session() -> SessionState {
    let Ok(path) = session_path() else { return SessionState::None };
    if !path.exists() {
        return SessionState::None;
    }
    let Ok(data) = std::fs::read_to_string(&path) else { return SessionState::None };
    if serde_json::from_str::<EncryptedSession>(&data).is_ok() {
        SessionState::Encrypted
    } else {
        SessionState::Plaintext
    }
}

// ── Encryption helpers ─────────────────────────────────────────────────────────

/// Derive a 32-byte AES key from passphrase via Argon2id.
/// Parameters tuned for Raspberry Pi: 32 MB memory, 3 iterations, 1 thread.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(32_768, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2: {e}"))?;
    Ok(key)
}

/// Save session encrypted with Argon2id + AES-256-GCM.
/// Uses a fresh random salt and nonce on every save.
pub fn save_session_encrypted(session: &Session, passphrase: &[u8]) -> Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM init failed"))?;

    let mut plaintext = serde_json::to_vec(session)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
    plaintext.zeroize();

    let enc = EncryptedSession {
        v: 1,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    };

    let path = session_path()?;
    std::fs::write(&path, serde_json::to_string(&enc)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Decrypt and load session from disk.
/// Returns `None` if the session file doesn't exist.
/// Returns `Err` if the file exists but decryption fails (wrong passphrase or corruption).
pub fn load_session_encrypted(passphrase: &[u8]) -> Result<Option<Session>> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let enc: EncryptedSession =
        serde_json::from_str(&data).context("session file is not in encrypted format")?;

    let salt = B64.decode(&enc.salt).context("bad salt encoding")?;
    let nonce_bytes = B64.decode(&enc.nonce).context("bad nonce encoding")?;
    let ciphertext = B64.decode(&enc.ciphertext).context("bad ciphertext encoding")?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM init failed"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase?"))?;

    let session: Session = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(Some(session))
}


fn default_server() -> String {
    "https://ams.konstruct.cc:443".into()
}

impl Default for Config {
    fn default() -> Self {
        Self { server: default_server(), transport: TransportConfig::Direct }
    }
}

// ── Paths ──────────────────────────────────────────────────────────────────────

fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot locate config dir")?;
    let dir = base.join("construct-tui");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

pub fn session_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("session.json"))
}

// ── Persistence ────────────────────────────────────────────────────────────────

pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let data = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn save_config(cfg: &Config) -> Result<()> {
    let path = config_path()?;
    std::fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn load_session() -> Result<Option<Session>> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    Ok(Some(serde_json::from_str(&data)?))
}

pub fn save_session(session: &Session) -> Result<()> {
    let path = session_path()?;
    // Permissions: owner read/write only
    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(&path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn clear_session() -> Result<()> {
    let path = session_path()?;
    if path.exists() {
        // Overwrite with random bytes before deleting.
        // Mitigates forensic recovery on flash/SD storage (wear-levelling caveat applies).
        let len = std::fs::metadata(&path)?.len() as usize;
        let mut garbage = vec![0u8; len];
        OsRng.fill_bytes(&mut garbage);
        std::fs::write(&path, &garbage)?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}
