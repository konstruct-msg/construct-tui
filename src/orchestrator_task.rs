//! Actor-style task that owns the `Orchestrator` and dispatches `Action`s.
//!
//! # Pattern
//!
//! ```text
//! App / StreamWorker
//!   ──── IncomingEvent ──→ OrchestratorTask
//!                              │  orchestrator.handle_event(event)
//!                              │  → Vec<Action>
//!                              │  dispatch each Action:
//!                              │    storage   ──→ SQLite
//!                              │    gRPC      ──→ KeyUserClient (async sub-task)
//!                              │    stream    ──→ StreamCmd channel
//!                              │    timer     ──→ tokio::time (sub-task → self_tx)
//!                              │    ui        ──→ internal_tx (BridgeEvent)
//!                              └────────────────────────────────────────────────
//! ```

use std::collections::HashMap;

use anyhow::Result;
use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use construct_core::orchestration::{
    actions::{Action, IncomingEvent},
    orchestrator::Orchestrator,
};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::bridge::BridgeEvent;
use crate::grpc::core_types::{ContentType, Envelope, UserId, envelope::MessageIdType};
use crate::storage::Storage;
use crate::streaming::StreamCmd;

// ── Public handle ─────────────────────────────────────────────────────────────

/// Cheaply cloneable handle for sending events to the Orchestrator task.
#[derive(Clone)]
pub struct OrchestratorHandle {
    pub tx: mpsc::UnboundedSender<IncomingEvent>,
}

impl OrchestratorHandle {
    /// Send an event to the orchestrator (fire-and-forget).
    pub fn send(&self, event: IncomingEvent) {
        let _ = self.tx.send(event);
    }
}

// ── Startup ───────────────────────────────────────────────────────────────────

/// Spawn the orchestrator task and return a handle to it.
///
/// * `orchestrator` — fully constructed (keys loaded, sessions pre-populated)
/// * `storage` — open SQLite storage
/// * `stream_tx` — command channel to the gRPC stream worker
/// * `internal_tx` — channel back to the UI app event loop (BridgeEvent)
/// * `grpc_url` / `access_token` — for FetchPublicKeyBundle and key upload
/// * `my_user_id` / `my_device_id` — local identity for Envelope construction
#[allow(clippy::too_many_arguments)]
pub fn spawn_orchestrator_task(
    orchestrator: Orchestrator,
    storage: Storage,
    stream_tx: mpsc::Sender<StreamCmd>,
    internal_tx: mpsc::UnboundedSender<crate::app::InternalEventProxy>,
    grpc_url: String,
    access_token: String,
    my_user_id: String,
    my_device_id: String,
) -> OrchestratorHandle {
    let (tx, rx) = mpsc::unbounded_channel::<IncomingEvent>();
    let handle = OrchestratorHandle { tx: tx.clone() };

    tokio::spawn(run(
        orchestrator,
        storage,
        stream_tx,
        internal_tx,
        grpc_url,
        access_token,
        my_user_id,
        my_device_id,
        tx,
        rx,
    ));

    handle
}

// ── Main loop ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run(
    mut orchestrator: Orchestrator,
    mut storage: Storage,
    stream_tx: mpsc::Sender<StreamCmd>,
    internal_tx: mpsc::UnboundedSender<crate::app::InternalEventProxy>,
    grpc_url: String,
    access_token: String,
    my_user_id: String,
    my_device_id: String,
    self_tx: mpsc::UnboundedSender<IncomingEvent>,
    mut rx: mpsc::UnboundedReceiver<IncomingEvent>,
) {
    let mut timers: HashMap<String, AbortHandle> = HashMap::new();

    while let Some(event) = rx.recv().await {
        let actions = orchestrator.handle_event(event);

        // Collect any inline follow-up events (from synchronous Action handlers).
        let mut follow_ups: Vec<IncomingEvent> = Vec::new();

        for action in actions {
            dispatch(
                action,
                &mut orchestrator,
                &mut storage,
                &stream_tx,
                &internal_tx,
                &grpc_url,
                &access_token,
                &my_user_id,
                &my_device_id,
                &self_tx,
                &mut timers,
                &mut follow_ups,
            )
            .await;
        }

        // Process inline follow-ups (e.g. SessionInitCompleted after InitSession).
        // One level of depth is enough — they should only produce simple actions.
        for follow_up in follow_ups {
            let more = orchestrator.handle_event(follow_up);
            for action in more {
                dispatch(
                    action,
                    &mut orchestrator,
                    &mut storage,
                    &stream_tx,
                    &internal_tx,
                    &grpc_url,
                    &access_token,
                    &my_user_id,
                    &my_device_id,
                    &self_tx,
                    &mut timers,
                    &mut Vec::new(), // no further follow-up nesting
                )
                .await;
            }
        }
    }
}

// ── Action dispatch ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    action: Action,
    orchestrator: &mut Orchestrator,
    storage: &mut Storage,
    stream_tx: &mpsc::Sender<StreamCmd>,
    internal_tx: &mpsc::UnboundedSender<crate::app::InternalEventProxy>,
    grpc_url: &str,
    access_token: &str,
    my_user_id: &str,
    my_device_id: &str,
    self_tx: &mpsc::UnboundedSender<IncomingEvent>,
    timers: &mut HashMap<String, AbortHandle>,
    follow_ups: &mut Vec<IncomingEvent>,
) {
    match action {
        // ── Crypto (platform must handle synchronously) ────────────────────
        Action::InitSession {
            contact_id,
            bundle_json,
        } => {
            // Detect RESPONDER case: the peer already sent us their X3DH first message
            // (msgNum=0) which is queued in the orchestrator's pending queue.
            // In that case we must init as RESPONDER (not INITIATOR) using their
            // wire payload so that the X3DH shared secret matches on both sides.
            if orchestrator.pending_message_count(&contact_id) > 0 {
                // RESPONDER path — take the first pending wire payload.
                if let Some(wire) = orchestrator.peek_first_pending_wire_payload(&contact_id) {
                    match orchestrator.init_receiving_session_from_wire_payload(
                        &contact_id,
                        bundle_json.as_bytes(),
                        &wire,
                    ) {
                        Ok(_) => {
                            tracing::info!(
                                target: "orchestrator_task",
                                contact_id = %contact_id,
                                "InitSession (Responder): session established from wire payload"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "orchestrator_task",
                                contact_id = %contact_id,
                                error = %e,
                                "InitSession (Responder): init_receiving_session failed"
                            );
                            return;
                        }
                    }
                } else {
                    tracing::warn!(
                        target: "orchestrator_task",
                        contact_id = %contact_id,
                        "InitSession (Responder): pending_count>0 but no wire payload — falling back to Initiator"
                    );
                    if let Ok(bundle) = serde_json::from_str::<X3DHPublicKeyBundle>(&bundle_json) {
                        let _ = orchestrator.init_session_with_bundle(
                            &contact_id,
                            bundle,
                            None,
                            None,
                            None,
                        );
                    }
                }
            } else {
                // INITIATOR path — no pending messages, we are starting fresh.
                if let Ok(bundle) = serde_json::from_str::<X3DHPublicKeyBundle>(&bundle_json) {
                    let _ = orchestrator.init_session_with_bundle(
                        &contact_id,
                        bundle,
                        None,
                        None,
                        None,
                    );
                }
            }
            follow_ups.push(IncomingEvent::SessionInitCompleted {
                contact_id,
                session_data: vec![],
            });
        }

        // These are handled internally by the Orchestrator itself.
        Action::DecryptMessage { .. }
        | Action::EncryptMessage { .. }
        | Action::ApplyPQContribution { .. }
        | Action::ArchiveSession { .. } => {}

        // ── Decrypted message ready ─────────────────────────────────────────
        Action::MessageDecrypted {
            contact_id,
            message_id,
            plaintext,
        } => {
            let text = String::from_utf8_lossy(&plaintext).into_owned();
            // Persist to storage.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let _ = storage.store_message(&crate::storage::StoredMessage {
                id: message_id.clone(),
                peer_id: contact_id.clone(),
                text: text.clone(),
                direction: "received".into(),
                timestamp_ms: now_ms,
                delivery_status: String::new(),
            });

            // Notify UI.
            let _ = internal_tx.send(crate::app::InternalEventProxy::Bridge(
                BridgeEvent::NewMessage {
                    peer_id: contact_id,
                    message_id,
                    text,
                    timestamp_ms: now_ms,
                },
            ));
        }

        Action::CallSignalDecrypted { .. } => {
            // Calls not yet implemented in TUI.
        }

        // ── Session healing ─────────────────────────────────────────────────
        Action::SessionHealNeeded { contact_id, role } => {
            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                role = %role,
                "Session heal needed — attempting recovery"
            );

            if role == "Initiator" {
                // ── TUI wins the tie-break (higher userId) ──────────────────
                // Notify the peer to reset its conflicting INITIATOR session,
                // then re-initialize our own session with fresh ephemeral keys.
                // After re-init the session ping (msgNum=0) will let the peer
                // establish itself as RESPONDER.
                let end_sess = build_control_envelope(
                    my_user_id,
                    my_device_id,
                    &contact_id,
                    ContentType::SessionReset,
                    vec![0u8; 16],
                    uuid_v4(),
                );
                let _ = stream_tx.try_send(StreamCmd::Send(Box::new(end_sess)));

                // Re-fetch bundle and re-init INITIATOR session.
                match fetch_bundle_json(grpc_url, access_token, my_user_id, &contact_id).await {
                    Ok(bundle_json) => {
                        if let Ok(bundle) =
                            serde_json::from_str::<X3DHPublicKeyBundle>(&bundle_json)
                        {
                            let _ = orchestrator.init_session_with_bundle(
                                &contact_id,
                                bundle,
                                None,
                                None,
                                None,
                            );
                        }
                        follow_ups.push(IncomingEvent::SessionInitCompleted {
                            contact_id: contact_id.clone(),
                            session_data: vec![],
                        });
                        // Send a session ping so the peer can init as RESPONDER
                        // without waiting for the user to type a message.
                        follow_ups.push(IncomingEvent::OutgoingMessage {
                            contact_id: contact_id.clone(),
                            message_id: uuid_v4(),
                            plaintext: b"\x00PING\x00".to_vec(),
                            content_type: 0,
                        });
                    }
                    Err(e) => tracing::error!(
                        target: "orchestrator_task",
                        contact_id = %contact_id,
                        error = %e,
                        "Heal (Initiator): bundle fetch failed"
                    ),
                }
            } else {
                // ── TUI loses the tie-break (lower userId = Responder) ───────
                // The peer's msgNum=0 is queued in the Rust healing_queue.
                // Fetch the peer's bundle and initialize the RESPONDER session
                // using the queued wire payload.
                let wire_payload = orchestrator.take_heal_payload(&contact_id);
                match wire_payload {
                    None => tracing::error!(
                        target: "orchestrator_task",
                        contact_id = %contact_id,
                        "Heal (Responder): no queued wire payload — cannot heal"
                    ),
                    Some(wire) => {
                        match fetch_bundle_json(grpc_url, access_token, my_user_id, &contact_id)
                            .await
                        {
                            Ok(bundle_json) => {
                                match orchestrator.init_receiving_session_from_wire_payload(
                                    &contact_id,
                                    bundle_json.as_bytes(),
                                    &wire,
                                ) {
                                    Ok(_) => {
                                        tracing::info!(
                                            target: "orchestrator_task",
                                            contact_id = %contact_id,
                                            "Heal (Responder): session established"
                                        );
                                        follow_ups.push(IncomingEvent::SessionInitCompleted {
                                            contact_id: contact_id.clone(),
                                            session_data: vec![],
                                        });
                                    }
                                    Err(e) => {
                                        // Crypto failed — notify peer to start fresh.
                                        tracing::warn!(
                                            target: "orchestrator_task",
                                            contact_id = %contact_id,
                                            error = %e,
                                            "Heal (Responder): init_receiving_session failed — sending END_SESSION"
                                        );
                                        let end_sess = build_control_envelope(
                                            my_user_id,
                                            my_device_id,
                                            &contact_id,
                                            ContentType::SessionReset,
                                            vec![0u8; 16],
                                            uuid_v4(),
                                        );
                                        let _ =
                                            stream_tx.try_send(StreamCmd::Send(Box::new(end_sess)));
                                    }
                                }
                            }
                            Err(e) => tracing::error!(
                                target: "orchestrator_task",
                                contact_id = %contact_id,
                                error = %e,
                                "Heal (Responder): bundle fetch failed"
                            ),
                        }
                    }
                }
            }
        }

        Action::HealSuppressed {
            contact_id: _,
            retry_after_ms,
        } => {
            // Retry after the cooldown expires.
            let tx = self_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(retry_after_ms)).await;
                let _ = tx.send(IncomingEvent::AppLaunched);
            });
        }

        // ── Persistence ─────────────────────────────────────────────────────
        Action::SaveSessionToSecureStore { key, data } => {
            let _ = storage.secure_save(&key, &data);
        }

        Action::LoadSessionFromSecureStore { key } => {
            let data = storage.secure_load(&key).ok().flatten();
            follow_ups.push(IncomingEvent::SessionLoaded { key, data });
        }

        Action::PersistMessage { message_json } => {
            let _ = storage.persist_record("msg", &message_json);
        }

        Action::PersistAck {
            message_id,
            timestamp,
        } => {
            let _ = storage.store_ack(&message_id, timestamp as i64);
        }

        Action::PruneAckStore { cutoff_ts } => {
            let _ = storage.prune_acks(cutoff_ts as i64);
        }

        Action::MarkMessageDelivered { message_id } => {
            let _ = storage.mark_delivered(&message_id);
        }

        Action::CheckAckInDb { message_id } => {
            let is_processed = storage.has_ack(&message_id).unwrap_or(false);
            follow_ups.push(IncomingEvent::AckDbResult {
                message_id,
                is_processed,
            });
        }

        // ── Network ─────────────────────────────────────────────────────────
        Action::FetchPublicKeyBundle { user_id } => {
            let tx = self_tx.clone();
            let grpc_url = grpc_url.to_string();
            let access_token = access_token.to_string();
            let my_uid = my_user_id.to_string();
            let uid = user_id.clone();
            tokio::spawn(async move {
                let bundle_json = fetch_bundle_json(&grpc_url, &access_token, &my_uid, &uid).await;
                let _ = tx.send(IncomingEvent::KeyBundleFetched {
                    user_id: uid,
                    bundle_json: bundle_json.unwrap_or_default(),
                });
            });
        }

        Action::SendEncryptedMessage {
            to,
            payload,
            message_id,
            content_type,
        } => {
            let content_type_proto = content_type_from_u8(content_type);
            let envelope = build_envelope(
                my_user_id,
                my_device_id,
                &to,
                payload,
                message_id,
                content_type_proto,
            );
            let _ = stream_tx.try_send(StreamCmd::Send(Box::new(envelope)));
        }

        Action::SendReceipt { message_id, status } => {
            // TODO: construct DeliveryReceipt proto and send via stream.
            tracing::debug!(
                target: "orchestrator_task",
                message_id = %message_id,
                status = ?status,
                "SendReceipt (not yet wired)"
            );
        }

        Action::SendEndSession { contact_id } => {
            // Build a control envelope with CONTENT_TYPE_SESSION_RESET.
            let envelope = build_control_envelope(
                my_user_id,
                my_device_id,
                &contact_id,
                ContentType::SessionReset,
                vec![],
                format!("end-session-{contact_id}"),
            );
            let _ = stream_tx.try_send(StreamCmd::Send(Box::new(envelope)));
        }

        Action::SendHeartbeat { contact_id } => {
            // Encrypted heartbeat — routed as OutgoingMessage with content_type = HEARTBEAT.
            // Content-type 0 is a regular E2EE message; we use that with a special payload.
            let message_id = uuid_v4();
            let _ = self_tx.send(IncomingEvent::OutgoingMessage {
                contact_id,
                message_id,
                plaintext: b"\x00HEARTBEAT\x00".to_vec(),
                content_type: 0,
            });
        }

        // ── UI notifications ─────────────────────────────────────────────────
        Action::NotifyNewMessage { chat_id, preview } => {
            let _ = internal_tx.send(crate::app::InternalEventProxy::Bridge(
                BridgeEvent::NewMessage {
                    peer_id: chat_id,
                    message_id: String::new(),
                    text: preview,
                    timestamp_ms: now_ms(),
                },
            ));
        }

        Action::NotifySessionCreated { contact_id } => {
            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                "Session created"
            );
        }

        Action::NotifyError { code, message } => {
            let _ = internal_tx.send(crate::app::InternalEventProxy::Bridge(BridgeEvent::Error(
                format!("[{code}] {message}"),
            )));
        }

        Action::NotifyLinkedDevicesOfSessionReset { .. } => {
            // Multi-device not yet implemented in TUI.
        }

        // ── Timers ──────────────────────────────────────────────────────────
        Action::ScheduleTimer { timer_id, delay_ms } => {
            let tx = self_tx.clone();
            let tid = timer_id.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let _ = tx.send(IncomingEvent::TimerFired { timer_id: tid });
            });
            timers.insert(timer_id, handle.abort_handle());
        }

        Action::CancelTimer { timer_id } => {
            if let Some(handle) = timers.remove(&timer_id) {
                handle.abort();
            }
        }

        Action::SessionTerminated { contact_id, .. } => {
            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                "Session terminated (archive stored by orchestrator)"
            );
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Fetch a pre-key bundle from the gRPC key service and return it as
/// the JSON string expected by `Orchestrator::init_session_with_bundle`.
async fn fetch_bundle_json(
    grpc_url: &str,
    access_token: &str,
    my_user_id: &str,
    user_id: &str,
) -> Result<String> {
    let mut client =
        crate::grpc::KeyUserClient::connect(grpc_url, access_token, my_user_id).await?;
    client.get_pre_key_bundle_json(user_id).await
}

fn build_envelope(
    from_user: &str,
    from_device: &str,
    to_user: &str,
    payload: Vec<u8>,
    message_id: String,
    content_type: ContentType,
) -> Envelope {
    use crate::grpc::core_types::DeviceId;

    Envelope {
        sender: Some(UserId {
            user_id: from_user.to_string(),
            domain: None,
            display_name: None,
        }),
        sender_device: Some(DeviceId {
            user: None,
            device_id: from_device.to_string(),
            ..Default::default()
        }),
        recipient: Some(UserId {
            user_id: to_user.to_string(),
            domain: None,
            display_name: None,
        }),
        recipient_device: None,
        content_type: content_type as i32,
        message_id_type: Some(MessageIdType::MessageId(message_id)),
        encrypted_payload: payload,
        conversation_id: {
            // Must match iOS ConversationId.direct() — sort user IDs lexicographically
            // so both sides produce the same key regardless of message direction.
            let (a, b) = if from_user < to_user {
                (from_user, to_user)
            } else {
                (to_user, from_user)
            };
            format!("direct:{}:{}", a, b)
        },
        ..Default::default()
    }
}

fn build_control_envelope(
    from_user: &str,
    from_device: &str,
    to_user: &str,
    content_type: ContentType,
    payload: Vec<u8>,
    message_id: String,
) -> Envelope {
    build_envelope(
        from_user,
        from_device,
        to_user,
        payload,
        message_id,
        content_type,
    )
}

fn content_type_from_u8(v: u8) -> ContentType {
    match v {
        1 => ContentType::E2eeSignal,
        12 => ContentType::CallSignal,
        20 => ContentType::KeyExchange,
        21 => ContentType::SessionReset,
        24 => ContentType::SessionResetInit,
        _ => ContentType::E2eeSignal,
    }
}

fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u16::from_be_bytes(b[4..6].try_into().unwrap()),
        u16::from_be_bytes(b[6..8].try_into().unwrap()),
        u16::from_be_bytes(b[8..10].try_into().unwrap()),
        {
            let mut arr = [0u8; 8];
            arr[2..].copy_from_slice(&b[10..]);
            u64::from_be_bytes(arr)
        }
    )
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
