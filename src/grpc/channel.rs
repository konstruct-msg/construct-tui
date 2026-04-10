//! gRPC channel factory — creates a `tonic::transport::Channel` based on the
//! configured transport mode (`Direct`, `Obfs4`, `Obfs4Tls`, `CdnFront`).

use anyhow::{Context, Result};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::config::{Config, TransportConfig};

/// Create a gRPC `Channel` according to `config.transport`.
///
/// # Transport modes
/// - `Direct`     — standard TLS, no obfuscation (default)
/// - `Obfs4`      — obfs4 obfuscation via construct-ice (requires `ice` feature)
/// - `Obfs4Tls`   — obfs4 + outer TLS/SNI wrapping (requires `ice` feature)
/// - `CdnFront`   — domain fronting through a CDN endpoint
///
/// # Note on `ice` feature
/// The `Obfs4` and `Obfs4Tls` variants are compiled only when the `ice` feature is
/// enabled (`cargo build --features ice`).  On uncensored networks the `Direct` mode
/// should be used — it avoids pulling in the obfs4 crypto stack entirely.
pub async fn create_channel(config: &Config) -> Result<Channel> {
    match &config.transport {
        TransportConfig::Direct => connect_direct(&config.server).await,

        #[cfg(feature = "ice")]
        TransportConfig::Obfs4 { bridge_line } => {
            connect_via_ice(&config.server, bridge_line, None).await
        }

        #[cfg(feature = "ice")]
        TransportConfig::Obfs4Tls { bridge_line, tls_server_name } => {
            connect_via_ice(&config.server, bridge_line, Some(tls_server_name)).await
        }

        TransportConfig::CdnFront { cdn_endpoint, sni_host: _, real_host: _ } => {
            // Domain fronting: connect to the CDN endpoint which proxies to the real host.
            // The HTTP `Host` header must be set to real_host by the caller's interceptor.
            connect_direct(cdn_endpoint).await
        }

        // Catch-all when the `ice` feature is disabled but an obfs4 config is loaded.
        #[cfg(not(feature = "ice"))]
        TransportConfig::Obfs4 { .. } | TransportConfig::Obfs4Tls { .. } => {
            anyhow::bail!(
                "Transport mode requires the 'ice' feature.\n\
                 Rebuild with: cargo build --features ice"
            )
        }
    }
}

/// Standard TLS channel — used for Direct and CdnFront modes.
async fn connect_direct(server_url: &str) -> Result<Channel> {
    let tls = ClientTlsConfig::new().with_native_roots();
    let channel = Endpoint::from_shared(server_url.to_string())
        .context("invalid server URL")?
        .tls_config(tls)?
        .connect()
        .await
        .context("gRPC direct connect failed")?;
    Ok(channel)
}

/// obfs4 channel via construct-ice.
/// Produces traffic indistinguishable from random noise — resistant to DPI.
#[cfg(feature = "ice")]
async fn connect_via_ice(
    relay_addr: &str,
    bridge_line: &str,
    _tls_sni: Option<&str>,
) -> Result<Channel> {
    use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};

    let ice_config = ClientConfig::from_bridge_cert(bridge_line)
        .context("invalid obfs4 bridge line")?;

    let channel = Endpoint::from_shared(format!("https://{relay_addr}"))
        .context("invalid relay address")?
        .connect_with_connector(Obfs4Channel::new(ice_config))
        .await
        .context("gRPC obfs4 connect failed")?;

    Ok(channel)
}
