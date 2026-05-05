//! Message streaming via construct-engine.

use tokio::sync::mpsc;

// Re-export Envelope type from engine's proto module
pub use construct_engine::proto::core::v1::Envelope;

// ── Public API ────────────────────────────────────────────────────────────────

/// Commands sent **to** the stream handler from the app.
#[derive(Debug)]
#[allow(dead_code)]
pub enum StreamCmd {
    /// Send an envelope to a recipient.
    Send(Box<Envelope>),
    /// Subscribe to updates for conversations.
    Subscribe(Vec<String>, Option<String>),
    /// Close the message stream.
    Close,
    /// Shut the handler down cleanly.
    Shutdown,
}

/// Events sent **from** the stream handler to the app.
#[derive(Debug)]
#[allow(dead_code)]
pub enum StreamEvent {
    /// An incoming message envelope.
    Message(Box<Envelope>),
    /// Delivery receipt ACK from server (echoed message_id).
    Ack(String),
    /// Connection state changed.
    Connected,
    Disconnected,
}

/// Start the streaming handler and return (cmd_tx, event_rx).
///
/// The handler runs in a background tokio task and forwards commands
/// to the construct-engine via UiEvent.
pub fn spawn_stream_worker(
    _server_url: String,
    _access_token: String,
    _subscribed_users: Vec<String>,
) -> (mpsc::Sender<StreamCmd>, mpsc::Receiver<StreamEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<StreamCmd>(64);
    let (event_tx, event_rx) = mpsc::channel::<StreamEvent>(256);

    // For now, just spawn a dummy loop that will be replaced by engine integration
    tokio::spawn(async move {
        // The engine handles all streaming internally.
        // This is a placeholder that will be removed when app.rs is updated
        // to use engine_adapter directly.

        // Send initial Connected event
        let _ = event_tx.send(StreamEvent::Connected).await;

        // Wait for commands
        let mut _cmd_rx = cmd_rx;
        while let Some(_cmd) = _cmd_rx.recv().await {
            // Commands will be handled by engine via app.rs
            // This is a stub for backward compatibility
        }

        let _ = event_tx.send(StreamEvent::Disconnected).await;
    });

    (cmd_tx, event_rx)
}

/// Helper to encode an Envelope for sending via engine.
#[allow(dead_code)]
pub fn encode_envelope(
    conversation_id: String,
    encrypted_payload: Vec<u8>,
    message_id: String,
) -> Envelope {
    Envelope {
        conversation_id,
        encrypted_payload: encrypted_payload.into(),
        message_id_type: Some(
            construct_engine::proto::core::v1::envelope::MessageIdType::MessageId(message_id),
        ),
        ..Default::default()
    }
}
