use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use tonic::{
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

use crate::grpc::services::{
    auth_service_client::AuthServiceClient,
    check_join_request_status_response::Status as JoinStatus,
    device_link_service_client::DeviceLinkServiceClient,
    AuthenticateDeviceRequest,
    AuthTokensResponse,
    CheckJoinRequestStatusRequest,
    ConfirmDeviceLinkRequest,
    DevicePublicKeys,
    GetPowChallengeRequest,
    JoinRequestPayload,
    PowSolution as ProtoPowSolution,
    RegisterDeviceRequest,
};

/// Result of polling CheckJoinRequestStatus.
#[derive(Debug)]
pub enum JoinPollResult {
    Pending,
    Approved(AuthTokensResponse),
    Rejected,
    Expired,
}

/// Construct server gRPC client wrapper.
pub struct ConstructClient {
    auth: AuthServiceClient<Channel>,
    link: DeviceLinkServiceClient<Channel>,
}

impl ConstructClient {
    /// Connect to the Construct gRPC server over TLS.
    pub async fn connect(server_url: &str) -> Result<Self> {
        let tls = ClientTlsConfig::new().with_native_roots();
        let channel = Endpoint::from_shared(server_url.to_string())
            .context("invalid server URL")?
            .tls_config(tls)?
            .connect()
            .await
            .context("gRPC connect failed")?;

        Ok(Self {
            auth: AuthServiceClient::new(channel.clone()),
            link: DeviceLinkServiceClient::new(channel),
        })
    }

    /// Link this device to an existing account using a token from the primary device.
    /// The token is the `link_token` from `InitiateDeviceLinkResponse` (shown as QR on phone).
    pub async fn confirm_device_link(
        &mut self,
        link_token: &str,
        device_id: &str,
        public_keys: DevicePublicKeys,
    ) -> Result<AuthTokensResponse> {
        let req = ConfirmDeviceLinkRequest {
            link_token: link_token.to_string(),
            device_id: device_id.to_string(),
            public_keys: Some(public_keys),
        };
        let resp = self
            .link
            .confirm_device_link(Request::new(req))
            .await
            .context("confirm_device_link RPC failed")?
            .into_inner();
        Ok(resp)
    }

    /// Authenticate an existing device.
    /// Signs "KonstruktAuth-v1\n{device_id}\n{timestamp}" with Ed25519.
    pub async fn authenticate(
        &mut self,
        device_id: &str,
        signing_key_hex: &str,
    ) -> Result<AuthTokensResponse> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let message = format!("KonstruktAuth-v1\n{}\n{}", device_id, timestamp);
        let sk_bytes = hex::decode(signing_key_hex).context("invalid signing key hex")?;
        let sk_array: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&sk_array);
        let signature = signing_key.sign(message.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        let req = AuthenticateDeviceRequest {
            device_id: device_id.to_string(),
            timestamp,
            signature: signature_hex,
        };

        let resp = self
            .auth
            .authenticate_device(Request::new(req))
            .await
            .context("authenticate_device RPC failed")?
            .into_inner();

        Ok(resp)
    }

    /// Register a brand-new device (PoW + public keys).
    pub async fn register(
        &mut self,
        username: Option<&str>,
        device_id: &str,
        public_keys: DevicePublicKeys,
    ) -> Result<AuthTokensResponse> {
        // 1. Get PoW challenge
        let challenge_resp = self
            .auth
            .get_pow_challenge(Request::new(GetPowChallengeRequest {}))
            .await
            .context("get_pow_challenge RPC failed")?
            .into_inner();

        // 2. Solve PoW — CPU-intensive, run on blocking thread pool
        let challenge = challenge_resp.challenge.clone();
        let difficulty = challenge_resp.difficulty;
        let solution = tokio::task::spawn_blocking(move || {
            construct_core::pow::compute_pow(&challenge, difficulty)
        })
        .await
        .context("PoW task panicked")?;

        // 3. Submit registration
        let req = RegisterDeviceRequest {
            username: username.map(|s| s.to_string()),
            device_id: device_id.to_string(),
            public_keys: Some(public_keys),
            pow_solution: Some(ProtoPowSolution {
                challenge: challenge_resp.challenge,
                nonce: solution.nonce,
                hash: solution.hash,
            }),
        };

        let resp = self
            .auth
            .register_device(Request::new(req))
            .await
            .context("register_device RPC failed")?
            .into_inner();

        Ok(resp)
    }

    /// Flow B step 1: submit this device's keys so the phone can scan / approve.
    pub async fn submit_join_request(
        &mut self,
        device_id: &str,
        public_keys: &DevicePublicKeys,
        device_name: &str,
        platform: &str,
    ) -> Result<()> {
        let payload = JoinRequestPayload {
            pending_device_id: device_id.to_string(),
            identity_public_b64: public_keys.identity_public.clone(),
            verifying_key_b64: public_keys.verifying_key.clone(),
            signed_prekey_public_b64: public_keys.signed_prekey_public.clone(),
            signed_prekey_signature_b64: public_keys.signed_prekey_signature.clone(),
            device_name: device_name.to_string(),
            platform: platform.to_string(),
        };
        self.link
            .submit_join_request(Request::new(payload))
            .await
            .context("submit_join_request RPC failed")?;
        Ok(())
    }

    /// Flow B step 2: poll for phone approval.
    pub async fn check_join_request_status(
        &mut self,
        pending_device_id: &str,
    ) -> Result<JoinPollResult> {
        let resp = self
            .link
            .check_join_request_status(Request::new(CheckJoinRequestStatusRequest {
                pending_device_id: pending_device_id.to_string(),
            }))
            .await
            .context("check_join_request_status RPC failed")?
            .into_inner();

        let result = match JoinStatus::try_from(resp.status).unwrap_or(JoinStatus::Pending) {
            JoinStatus::Approved => {
                let tokens = resp.tokens.ok_or_else(|| {
                    anyhow::anyhow!("APPROVED status but no tokens in response")
                })?;
                JoinPollResult::Approved(tokens)
            }
            JoinStatus::Rejected => JoinPollResult::Rejected,
            JoinStatus::Expired => JoinPollResult::Expired,
            JoinStatus::Pending => JoinPollResult::Pending,
        };
        Ok(result)
    }
}
