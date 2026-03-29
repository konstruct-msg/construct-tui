use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: String,
}

fn default_server() -> String {
    "https://ams.konstruct.cc:443".into()
}

impl Default for Config {
    fn default() -> Self {
        Self { server: default_server() }
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
        std::fs::remove_file(path)?;
    }
    Ok(())
}
