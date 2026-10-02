//! Sending a text message and reading a conversation's history.

use uuid::Uuid;

use super::Client;
use crate::storage::StoredMessage;

impl Client {
    /// Hand a text message to the orchestrator; returns its message id.
    pub(crate) fn send_text(&self, contact_id: &str, text: &str) -> String {
        let message_id = Uuid::new_v4().to_string();
        if let Some(ref orch) = self.orch_handle {
            orch.send(
                construct_core::orchestration::actions::IncomingEvent::OutgoingMessage {
                    contact_id: contact_id.to_string(),
                    message_id: message_id.clone(),
                    plaintext: text.as_bytes().to_vec(),
                    content_type: 0,
                },
            );
        }
        message_id
    }

    /// The last `limit` stored messages with one person, oldest first.
    pub(crate) fn history(&self, peer_id: &str, limit: usize) -> Vec<StoredMessage> {
        self.read_storage
            .as_ref()
            .and_then(|s| s.get_messages(peer_id, limit).ok())
            .unwrap_or_default()
    }
}
