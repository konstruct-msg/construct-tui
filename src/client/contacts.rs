//! People: username search, invite redemption, adding and removing, and the contact set the
//! message stream is subscribed for.

use super::{Client, ClientEvent};
use crate::storage::StoredContact;

/// One FindUser hit.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// What [`Client::find_contact`] started.
pub(crate) enum FindStarted {
    UsernameSearch,
    InviteRedemption,
}

impl Client {
    /// Look a person up: an invite link is redeemed, anything else is a username search.
    /// Results arrive as [`ClientEvent::ContactSearchResult`] / `InviteAccepted` /
    /// `ContactSearchError`; `Err` is a message for the user, nothing started.
    pub(crate) fn find_contact(&self, raw: &str) -> Result<FindStarted, String> {
        let raw = raw.trim();
        if crate::invite::looks_like_invite(raw) {
            self.redeem_invite(raw)?;
            return Ok(FindStarted::InviteRedemption);
        }
        let query = crate::grpc::users::normalize_username(raw);
        if !crate::grpc::users::username_is_searchable(&query) {
            return Err("Username: 3–30 chars, letters/digits/_  (no @)".into());
        }
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let event = match crate::grpc::find_user(&grpc, &query).await {
                Ok(Some(user_id)) => ClientEvent::ContactSearchResult(vec![SearchResult {
                    user_id,
                    username: query.clone(),
                    display_name: query,
                }]),
                Ok(None) => ClientEvent::ContactSearchResult(vec![]),
                Err(e) => ClientEvent::ContactSearchError(e.to_string()),
            };
            let _ = tx.send(event);
        });
        Ok(FindStarted::UsernameSearch)
    }

    fn redeem_invite(&self, raw: &str) -> Result<(), String> {
        let invite = crate::invite::parse_invite(raw).map_err(|e| format!("Bad invite: {e:#}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if invite.is_expired(now) {
            return Err("Invite expired".into());
        }
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        let username = invite
            .un
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| invite.uuid[..8.min(invite.uuid.len())].to_string());
        tokio::spawn(async move {
            let event = match crate::grpc::accept_invite(&grpc, &invite).await {
                Ok(accepted) => ClientEvent::InviteAccepted {
                    user_id: accepted.user_id,
                    username,
                },
                Err(e) => ClientEvent::ContactSearchError(format!("Invite: {e}")),
            };
            let _ = tx.send(event);
        });
        Ok(())
    }

    /// Store a person, subscribe the stream to them, and tell the orchestrator.
    pub(crate) fn add_contact(&mut self, user_id: &str, username: &str) {
        if let Some(ref storage) = self.read_storage {
            let _ = storage.upsert_contact(&StoredContact {
                user_id: user_id.to_string(),
                display_name: username.to_string(),
                identity_key_b64: String::new(),
            });
        }
        if !self.contact_ids.iter().any(|id| id == user_id) {
            self.contact_ids.push(user_id.to_string());
        }
        self.resubscribe_stream();
        if let Some(ref orch) = self.orch_handle {
            orch.remember_contact(user_id.to_string());
        }
    }

    /// Remove a person and their messages.
    pub(crate) fn delete_contact(&mut self, peer_id: &str) -> Result<(), String> {
        if let Some(Err(e)) = self
            .read_storage
            .as_ref()
            .map(|s| s.delete_contact(peer_id))
        {
            return Err(format!("Delete failed: {e}"));
        }
        if let Some(ref orch) = self.orch_handle {
            orch.forget_contact(peer_id.to_string());
        }
        self.contact_ids.retain(|id| id != peer_id);
        self.resubscribe_stream();
        Ok(())
    }

    /// Re-subscribe the stream for the full contact set — never a subset.
    fn resubscribe_stream(&self) {
        let Some(ref stream_tx) = self.stream_tx else {
            return;
        };
        let stream_cursor = self
            .read_storage
            .as_ref()
            .and_then(|storage| storage.load_stream_cursor().ok().flatten());
        let _ = stream_tx.try_send(crate::streaming::StreamCmd::Subscribe(
            self.contact_ids.clone(),
            stream_cursor,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::config::TransportConfig;
    use tokio::sync::mpsc;

    fn client() -> Client {
        let (tx, _rx) = mpsc::unbounded_channel();
        Client::new(
            ClientConfig {
                server_url: "https://localhost".into(),
                transport: TransportConfig::Direct,
                no_encrypt: true,
                pq_active: true,
            },
            tx,
        )
    }

    fn last_subscription(rx: &mut mpsc::Receiver<crate::streaming::StreamCmd>) -> Vec<String> {
        let mut last = None;
        while let Ok(cmd) = rx.try_recv() {
            if let crate::streaming::StreamCmd::Subscribe(ids, _) = cmd {
                last = Some(ids);
            }
        }
        last.expect("a subscription was sent")
    }

    /// Adding or removing one person re-subscribes for everyone, not just for them — a
    /// subscription for a subset silently stops delivery from the rest.
    #[test]
    fn the_stream_is_resubscribed_for_the_full_contact_set() {
        let mut client = client();
        let (stream_tx, mut stream_rx) = mpsc::channel(8);
        client.stream_tx = Some(stream_tx);

        client.add_contact("alice", "Alice");
        client.add_contact("bob", "Bob");
        assert_eq!(last_subscription(&mut stream_rx), vec!["alice", "bob"]);

        client.add_contact("alice", "Alice");
        assert_eq!(
            last_subscription(&mut stream_rx),
            vec!["alice", "bob"],
            "adding someone already there does not duplicate them"
        );

        client.delete_contact("alice").unwrap();
        assert_eq!(last_subscription(&mut stream_rx), vec!["bob"]);
    }
}
