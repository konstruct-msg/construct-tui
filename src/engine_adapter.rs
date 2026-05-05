//! Engine adapter — wraps construct-engine and translates PlatformAction ↔ InternalEvent
//!
//! This module provides the bridge between the TUI event loop and the
//! construct-engine async runtime. It implements `EngineCallback` to receive
//! platform actions from the engine and forwards them as `EngineEvent` to the TUI.
//!
//! Note: Much of this code is prepared for full engine integration and may show
//! dead_code warnings until all UiEvent handlers are wired up in app.rs.

#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

use construct_engine::{ConstructEngine, EngineCallback, EngineConfig, PlatformAction, UiEvent};

/// Events sent from the engine callback to the TUI event loop.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Authentication token set/updated.
    AuthTokenSet {
        user_id: String,
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    },
    /// Registration completed successfully.
    RegistrationComplete { user_id: String, device_id: String },
    /// Clear all auth state (logout or unrecoverable error).
    ClearAuth,
    /// Connection state changed.
    ConnectionStateChanged { connected: bool },
    /// Network error occurred (reconnect in progress).
    NetworkError { message: String },
    /// Stream is ready for messaging.
    StreamReady { stream_cursor: Option<String> },
    /// Stream error occurred.
    StreamError { message: String },
    /// Pre-key bundle received from server.
    PreKeyBundleReady {
        user_id: String,
        bundle_bytes: Vec<u8>,
    },
    /// OTPKs uploaded successfully.
    OtpksUploaded { uploaded: u32, server_count: u32 },
    /// Pre-key count updated (auto-replenish check).
    PreKeyCountUpdated {
        count: u32,
        recommended_minimum: u32,
    },
    /// Signed pre-key rotated.
    SpkRotated { key_id: u32 },
    /// Load a value from the platform keychain.
    LoadKeychain { key: String },
    /// Save a value to the platform keychain.
    SaveKeychain { key: String, data: Vec<u8> },
    /// Session initialization error.
    SessionError { contact_id: String, message: String },
    /// Update message delivery status.
    UpdateMessageStatus { local_id: String, status: u8 },
    /// Display a decrypted message.
    DisplayMessage {
        message_id: String,
        plaintext: Vec<u8>,
        sender_id: String,
        conversation_id: String,
        timestamp: i64,
    },
}

/// Callback implementation that forwards PlatformAction to the TUI event loop.
pub struct TuiEngineCallback {
    event_tx: watch::Sender<Option<EngineEvent>>,
}

impl TuiEngineCallback {
    pub fn new(event_tx: watch::Sender<Option<EngineEvent>>) -> Self {
        Self { event_tx }
    }
}

impl EngineCallback for TuiEngineCallback {
    fn on_action(&self, action: PlatformAction) {
        let event = match action {
            PlatformAction::SetAuthToken {
                user_id,
                access_token,
                refresh_token,
                expires_at,
            } => Some(EngineEvent::AuthTokenSet {
                user_id,
                access_token,
                refresh_token,
                expires_at,
            }),
            PlatformAction::RegistrationComplete { user_id, device_id } => {
                Some(EngineEvent::RegistrationComplete { user_id, device_id })
            }
            PlatformAction::ClearAuth => Some(EngineEvent::ClearAuth),
            PlatformAction::ConnectionStateChanged { connected } => {
                Some(EngineEvent::ConnectionStateChanged { connected })
            }
            PlatformAction::NetworkError { message } => Some(EngineEvent::NetworkError { message }),
            PlatformAction::StreamReady { stream_cursor } => {
                Some(EngineEvent::StreamReady { stream_cursor })
            }
            PlatformAction::StreamError { message } => Some(EngineEvent::StreamError { message }),
            PlatformAction::PreKeyBundleReady {
                user_id,
                bundle_bytes,
            } => Some(EngineEvent::PreKeyBundleReady {
                user_id,
                bundle_bytes,
            }),
            PlatformAction::OtpksUploaded {
                uploaded,
                server_count,
            } => Some(EngineEvent::OtpksUploaded {
                uploaded,
                server_count,
            }),
            PlatformAction::PreKeyCountUpdated {
                count,
                recommended_minimum,
            } => Some(EngineEvent::PreKeyCountUpdated {
                count,
                recommended_minimum,
            }),
            PlatformAction::SpkRotated { key_id } => Some(EngineEvent::SpkRotated { key_id }),
            PlatformAction::LoadKeychain { key } => Some(EngineEvent::LoadKeychain { key }),
            PlatformAction::SaveKeychain { key, data } => {
                Some(EngineEvent::SaveKeychain { key, data })
            }
            PlatformAction::SessionError {
                contact_id,
                message,
            } => Some(EngineEvent::SessionError {
                contact_id,
                message,
            }),
            PlatformAction::UpdateMessageStatus { local_id, status } => {
                Some(EngineEvent::UpdateMessageStatus { local_id, status })
            }
            PlatformAction::DisplayMessage {
                message_id,
                plaintext,
                sender_id,
                conversation_id,
                timestamp,
            } => Some(EngineEvent::DisplayMessage {
                message_id,
                plaintext,
                sender_id,
                conversation_id,
                timestamp,
            }),
            // Ignore other platform actions not needed by TUI
            _ => {
                info!("engine platform action (ignored): {action:?}");
                None
            }
        };

        if let Some(evt) = event
            && let Err(e) = self.event_tx.send(Some(evt))
        {
            warn!("engine event dropped (receiver closed): {e}");
        }
    }
}

/// Engine configuration derived from TUI config.
pub fn build_engine_config(
    server_url: &str,
    user_id: Option<&str>,
    device_id: Option<&str>,
    access_token: Option<&str>,
    keys_cfe_data: &[u8],
) -> EngineConfig {
    // Parse server_url to extract host and port
    let (host, port) = parse_server_url(server_url);

    EngineConfig {
        server_host: host,
        server_port: port,
        my_user_id: user_id.unwrap_or("").to_string(),
        my_device_id: device_id.unwrap_or("").to_string(),
        auth_token: access_token.map(String::from),
        keys_cfe_data: keys_cfe_data.to_vec(),
        verify_certs: true,
        use_masque: false,
        masque_host: None,
        masque_port: None,
        event_buffer: 1000,
    }
}

fn parse_server_url(url: &str) -> (String, u16) {
    // Remove protocol prefix
    let without_proto = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Split host and port
    if let Some((host, port_str)) = without_proto.split_once(':') {
        let port = port_str.parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (without_proto.to_string(), 443)
    }
}

/// Spawn the engine and return a handle for dispatching events.
pub async fn spawn_engine(config: EngineConfig) -> Result<EngineHandle, anyhow::Error> {
    let (event_tx, event_rx) = watch::channel::<Option<EngineEvent>>(None);
    let callback = Box::new(TuiEngineCallback::new(event_tx.clone()));

    let engine = Arc::new(ConstructEngine::new(config, callback)?);
    engine.start()?;

    Ok(EngineHandle { engine, event_rx })
}

/// Handle for interacting with the running engine.
pub struct EngineHandle {
    engine: Arc<ConstructEngine>,
    event_rx: watch::Receiver<Option<EngineEvent>>,
}

impl EngineHandle {
    /// Send a UI event to the engine.
    pub fn dispatch(&self, event: UiEvent) {
        self.engine.dispatch(event);
    }

    /// Get a cloned receiver for the TUI event loop.
    pub fn event_receiver(&self) -> watch::Receiver<Option<EngineEvent>> {
        self.event_rx.clone()
    }

    /// Shutdown the engine gracefully.
    pub fn shutdown(&self) {
        self.engine.shutdown();
    }

    /// Get reference to the engine for direct access.
    pub fn engine(&self) -> &ConstructEngine {
        &self.engine
    }
}
