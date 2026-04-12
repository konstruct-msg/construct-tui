#![allow(dead_code)]
use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use tonic::{
    Request,
    transport::{Channel, ClientTlsConfig, Endpoint},
};

use crate::grpc::services::{
    AuthTokensResponse, AuthenticateDeviceRequest, CheckJoinRequestStatusRequest,
    ConfirmDeviceLinkRequest, DevicePublicKeys, GetPowChallengeRequest, JoinRequestPayload,
    PowSolution as ProtoPowSolution, RegisterDeviceRequest, auth_service_client::AuthServiceClient,
    check_join_request_status_response::Status as JoinStatus,
    device_link_service_client::DeviceLinkServiceClient,
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
    /// Signs "{device_id}{timestamp}" with Ed25519 (must match server format).
    pub async fn authenticate(
        &mut self,
        device_id: &str,
        signing_key_hex: &str,
    ) -> Result<AuthTokensResponse> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let message = format!("{}{}", device_id, timestamp);
        let sk_bytes = hex::decode(signing_key_hex).context("invalid signing key hex")?;
        let sk_array: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&sk_array);
        let signature = signing_key.sign(message.as_bytes());
        let signature_b64 = {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.encode(signature.to_bytes())
        };

        let req = AuthenticateDeviceRequest {
            device_id: device_id.to_string(),
            timestamp,
            signature: signature_b64,
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
                let tokens = resp
                    .tokens
                    .ok_or_else(|| anyhow::anyhow!("APPROVED status but no tokens in response"))?;
                JoinPollResult::Approved(tokens)
            }
            JoinStatus::Rejected => JoinPollResult::Rejected,
            JoinStatus::Expired => JoinPollResult::Expired,
            JoinStatus::Pending => JoinPollResult::Pending,
        };
        Ok(result)
    }
}

/// Authenticated client for key and user service operations.
/// Requires a valid JWT access token (set via `with_token()`).
pub struct KeyUserClient {
    channel: Channel,
    access_token: String,
    user_id: String,
}

impl KeyUserClient {
    pub async fn connect(server_url: &str, access_token: &str, user_id: &str) -> Result<Self> {
        let tls = ClientTlsConfig::new().with_native_roots();
        let channel = Endpoint::from_shared(server_url.to_string())
            .context("invalid server URL")?
            .tls_config(tls)?
            .connect()
            .await
            .context("gRPC connect failed")?;
        Ok(Self {
            channel,
            access_token: access_token.to_string(),
            user_id: user_id.to_string(),
        })
    }

    fn bearer<T>(&self, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.access_token)
                .parse()
                .expect("valid token chars"),
        );
        // Services validate caller identity from x-user-id, which is normally
        // injected by the Envoy auth interceptor.  Direct clients must set it.
        req.metadata_mut().insert(
            "x-user-id",
            self.user_id.parse().expect("valid user_id chars"),
        );
        req
    }

    /// Fetch the pre-key bundle for `user_id` and serialize it to the
    /// JSON format expected by `Orchestrator::init_session_with_bundle`.
    pub async fn get_pre_key_bundle_json(&mut self, user_id: &str) -> Result<String> {
        use crate::grpc::services::{GetPreKeyBundleRequest, key_service_client::KeyServiceClient};

        let mut key_svc = KeyServiceClient::new(self.channel.clone());
        let resp = key_svc
            .get_pre_key_bundle(self.bearer(GetPreKeyBundleRequest {
                user_id: user_id.to_string(),
                device_id: None,
                preferred_suite: None,
            }))
            .await
            .context("GetPreKeyBundle RPC failed")?
            .into_inner();

        let b = resp.bundle.context("no bundle in response")?;

        // Serialize to the JSON format expected by Orchestrator::init_session_with_bundle
        let bundle_json = serde_json::json!({
            "identity_public": b.identity_key.to_vec(),
            "signed_prekey_public": b.signed_pre_key.to_vec(),
            "signature": b.signed_pre_key_signature.to_vec(),
            "verifying_key": resp.verifying_key.to_vec(),
            "suite_id": 1u16,
            "one_time_prekey_public": b.one_time_pre_key.map(|k| k.to_vec()),
            "one_time_prekey_id": b.one_time_pre_key_id,
            "spk_uploaded_at": b.spk_uploaded_at as u64,
            "spk_rotation_epoch": b.spk_rotation_epoch,
        });

        Ok(bundle_json.to_string())
    }

    /// Upload a batch of one-time pre-keys for this device.
    pub async fn upload_pre_keys(
        &mut self,
        device_id: &str,
        keys: Vec<(u32, Vec<u8>)>,
    ) -> Result<()> {
        use crate::grpc::services::{
            OneTimePreKey, UploadPreKeysRequest, key_service_client::KeyServiceClient,
        };
        let pre_keys = keys
            .into_iter()
            .map(|(key_id, public_key)| OneTimePreKey { key_id, public_key })
            .collect();

        let mut key_svc = KeyServiceClient::new(self.channel.clone());
        key_svc
            .upload_pre_keys(self.bearer(UploadPreKeysRequest {
                device_id: device_id.to_string(),
                pre_keys,
                signed_pre_key: None,
                replace_existing: true,
                kyber_pre_keys: vec![],
                kyber_signed_pre_key: None,
            }))
            .await
            .context("UploadPreKeys RPC failed")?;
        Ok(())
    }

    /// Find a user by their username and return the user_id.
    pub async fn find_user(&mut self, username: &str) -> Result<Option<String>> {
        use crate::grpc::services::{FindUserRequest, user_service_client::UserServiceClient};
        use tonic::Code;

        let mut user_svc = UserServiceClient::new(self.channel.clone());
        match user_svc
            .find_user(self.bearer(FindUserRequest {
                username: username.to_string(),
            }))
            .await
        {
            Ok(resp) => Ok(Some(resp.into_inner().user_id)),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(anyhow::anyhow!(
                "FindUser RPC failed: {} ({})",
                status.message(),
                status.code()
            )),
        }
    }
}
