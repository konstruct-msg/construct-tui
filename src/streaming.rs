//! Bidirectional gRPC message stream with automatic reconnect.
//!
//! `StreamWorker` manages a long-lived `MessagingService/MessageStream` connection.
//! On disconnect it backs off exponentially (1 s → 2 s → 4 s … max 30 s) and
//! re-subscribes to the same conversation set.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::{
    Request,
    transport::{ClientTlsConfig, Endpoint},
};

use crate::grpc::shared::proto::core::v1::Envelope;
use crate::grpc::shared::proto::services::v1::{
    Heartbeat, MessageStreamRequest, MessageStreamResponse, SubscribeRequest,
    message_stream_request::Request as StreamReq, messaging_service_client::MessagingServiceClient,
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Commands sent **to** the stream worker from the app.
#[derive(Debug)]
pub enum StreamCmd {
    /// Send an envelope to a recipient.
    Send(Box<Envelope>),
    /// Subscribe to updates for this user (call when entering a conversation).
    Subscribe(String),
    /// Shut the worker down cleanly.
    Shutdown,
}

/// Events sent **from** the stream worker to the app.
#[derive(Debug)]
pub enum StreamEvent {
    /// An incoming message envelope.
    Message(Box<Envelope>),
    /// Delivery receipt ACK from server (echoed message_id).
    Ack(String),
    /// Connection state changed.
    Connected,
    Disconnected,
}

/// Start the streaming worker and return (cmd_tx, event_rx).
///
/// The worker runs in a background tokio task. It:
/// 1. Connects to the server.
/// 2. Opens `MessageStream`.
/// 3. Subscribes to `subscribed_users` on first connect and after each reconnect.
/// 4. Forwards incoming envelopes to `event_tx`.
/// 5. Forwards `StreamCmd::Send` envelopes to the gRPC stream.
/// 6. On any error: backs off, then reconnects.
pub fn spawn_stream_worker(
    server_url: String,
    access_token: String,
    subscribed_users: Vec<String>,
) -> (mpsc::Sender<StreamCmd>, mpsc::Receiver<StreamEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<StreamCmd>(64);
    let (event_tx, event_rx) = mpsc::channel::<StreamEvent>(256);

    tokio::spawn(stream_loop(
        server_url,
        access_token,
        subscribed_users,
        cmd_rx,
        event_tx,
    ));

    (cmd_tx, event_rx)
}

// ── Internal loop ─────────────────────────────────────────────────────────────

async fn stream_loop(
    server_url: String,
    access_token: String,
    mut subscribed_users: Vec<String>,
    mut cmd_rx: mpsc::Receiver<StreamCmd>,
    event_tx: mpsc::Sender<StreamEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);

    loop {
        // Attempt to open the stream.
        match run_stream(
            &server_url,
            &access_token,
            &subscribed_users,
            &mut cmd_rx,
            &event_tx,
        )
        .await
        {
            Ok(false) => {
                // Clean shutdown requested.
                return;
            }
            Ok(true) => {
                // Unexpected close — reconnect.
                let _ = event_tx.send(StreamEvent::Disconnected).await;
            }
            Err(e) => {
                tracing_or_eprintln!("stream error: {e:#}");
                let _ = event_tx.send(StreamEvent::Disconnected).await;
            }
        }

        // Check for shutdown or Subscribe commands while waiting.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => { break; }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        StreamCmd::Shutdown => return,
                        StreamCmd::Subscribe(uid) => {
                            if !subscribed_users.contains(&uid) {
                                subscribed_users.push(uid);
                            }
                        }
                        StreamCmd::Send(_) => {
                            // Drop sends during reconnect — caller should queue them.
                        }
                    }
                }
                else => return,
            }
        }

        // Double the backoff, capped at MAX_BACKOFF.
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Run one iteration of the stream. Returns:
/// - `Ok(false)` → clean Shutdown command received
/// - `Ok(true)` → stream closed unexpectedly (reconnect needed)
/// - `Err(_)` → error (reconnect needed)
async fn run_stream(
    server_url: &str,
    access_token: &str,
    subscribed_users: &[String],
    cmd_rx: &mut mpsc::Receiver<StreamCmd>,
    event_tx: &mpsc::Sender<StreamEvent>,
) -> Result<bool> {
    // Connect with TLS.
    let tls = ClientTlsConfig::new().with_native_roots();
    let channel = Endpoint::from_shared(server_url.to_string())
        .context("invalid server URL")?
        .tls_config(tls)?
        .connect()
        .await
        .context("gRPC connect")?;

    let mut client = MessagingServiceClient::new(channel);

    // Build outbound sender channel.
    let (out_tx, mut out_rx) = mpsc::channel::<MessageStreamRequest>(64);

    // Subscribe to all known conversations immediately.
    for user_id in subscribed_users {
        let _ = out_tx.send(subscribe_req(user_id.clone())).await;
    }

    // Spawn outbound feeder task.
    let out_tx_clone = out_tx.clone();
    // We use an outbound stream driven by out_rx.
    let outbound = async_stream::stream! {
        while let Some(req) = out_rx.recv().await {
            yield req;
        }
    };

    // Attach bearer token.
    let mut request = Request::new(outbound);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", access_token)
            .parse()
            .context("token header")?,
    );

    let response = client
        .message_stream(request)
        .await
        .context("message_stream RPC")?;
    let mut inbound = response.into_inner();

    let _ = event_tx.send(StreamEvent::Connected).await;

    // Heartbeat interval.
    let mut hb_interval = tokio::time::interval(Duration::from_secs(25));
    hb_interval.tick().await; // skip immediate first tick

    loop {
        tokio::select! {
            // Incoming message from server.
            result = inbound.message() => {
                match result {
                    Ok(Some(resp)) => handle_server_message(resp, event_tx).await,
                    Ok(None) => return Ok(true), // server closed stream
                    Err(e) => return Err(e.into()),
                }
            }

            // Command from the app.
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    StreamCmd::Shutdown => return Ok(false),
                    StreamCmd::Subscribe(uid) => {
                        let _ = out_tx_clone.send(subscribe_req(uid)).await;
                    }
                    StreamCmd::Send(envelope) => {
                        let req = MessageStreamRequest {
                            request: Some(StreamReq::Send(*envelope)),
                            request_id: uuid::Uuid::new_v4().to_string(),
                            attempt_id: None,
                        };
                        let _ = out_tx_clone.send(req).await;
                    }
                }
            }

            // Heartbeat.
            _ = hb_interval.tick() => {
                let req = MessageStreamRequest {
                    request: Some(StreamReq::Heartbeat(Heartbeat { timestamp: now_ms() })),
                    request_id: uuid::Uuid::new_v4().to_string(),
                    attempt_id: None,
                };
                let _ = out_tx_clone.send(req).await;
            }
        }
    }
}

async fn handle_server_message(resp: MessageStreamResponse, event_tx: &mpsc::Sender<StreamEvent>) {
    use crate::grpc::shared::proto::services::v1::message_stream_response::Response;
    let Some(response) = resp.response else {
        return;
    };
    match response {
        Response::Message(envelope) => {
            let _ = event_tx.send(StreamEvent::Message(Box::new(envelope))).await;
        }
        Response::Ack(ack) => {
            let _ = event_tx.send(StreamEvent::Ack(ack.message_id)).await;
        }
        Response::Error(e) => {
            eprintln!(
                "[stream] server error: {:?} — {}",
                e.error_code, e.error_message
            );
        }
        _ => {} // receipt, typing, etc — ignored for now
    }
}

fn subscribe_req(user_id: String) -> MessageStreamRequest {
    MessageStreamRequest {
        request: Some(StreamReq::Subscribe(SubscribeRequest {
            conversation_ids: vec![user_id],
            ..Default::default()
        })),
        request_id: uuid::Uuid::new_v4().to_string(),
        attempt_id: None,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// Minimal tracing shim so we don't depend on `tracing` crate yet.
macro_rules! tracing_or_eprintln {
    ($($arg:tt)*) => { eprintln!("[stream] {}", format!($($arg)*)) };
}
use tracing_or_eprintln;
