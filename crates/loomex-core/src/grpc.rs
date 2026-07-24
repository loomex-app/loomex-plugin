use std::time::Duration;

use tonic::codec::CompressionEncoding;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{IntoStreamingRequest, Request, Response, Streaming};

use crate::device::STREAM_TOKEN_AUDIENCE;
use crate::protocol::StreamIdentity;
use crate::{CoreError, CoreResult};

pub mod pb {
    tonic::include_proto!("loomex.runner.v1");
}

#[derive(Clone, PartialEq, Eq)]
pub struct StreamCredential {
    pub stream_token: String,
    pub audience: String,
    pub expires_at_epoch_ms: u64,
}

impl std::fmt::Debug for StreamCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamCredential")
            .field("stream_token", &"[REDACTED]")
            .field("audience", &self.audience)
            .field("expires_at_epoch_ms", &self.expires_at_epoch_ms)
            .finish()
    }
}

impl StreamCredential {
    pub fn is_expired(&self, now_epoch_ms: u64) -> bool {
        now_epoch_ms >= self.expires_at_epoch_ms
    }

    pub fn should_refresh(&self, now_epoch_ms: u64, refresh_before_ms: u64) -> bool {
        now_epoch_ms.saturating_add(refresh_before_ms) >= self.expires_at_epoch_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcClientConfig {
    pub endpoint: String,
    pub tls: TlsConfig,
    pub proxy: ProxyConfig,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub keepalive: KeepaliveConfig,
    pub compression: CompressionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub enabled: bool,
    pub domain_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub use_environment: bool,
    pub required: bool,
    pub explicit_proxy_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepaliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub while_idle: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CompressionConfig {
    Disabled,
    Gzip,
}

impl Default for GrpcClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://api.loomex.app".to_string(),
            tls: TlsConfig {
                enabled: true,
                domain_name: Some("api.loomex.app".to_string()),
            },
            proxy: ProxyConfig {
                use_environment: true,
                required: false,
                explicit_proxy_url: None,
            },
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            keepalive: KeepaliveConfig {
                interval: Duration::from_secs(20),
                timeout: Duration::from_secs(10),
                while_idle: true,
            },
            compression: CompressionConfig::Gzip,
        }
    }
}

impl ProxyConfig {
    pub fn resolve_for_endpoint<F>(&self, endpoint: &str, read_env: F) -> CoreResult<Option<String>>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(proxy_url) = &self.explicit_proxy_url {
            if proxy_url.trim().is_empty() {
                return Err(CoreError::new(
                    "GRPC_PROXY_CONFIG_INVALID",
                    "explicit proxy url cannot be empty",
                ));
            }
            return Ok(Some(proxy_url.clone()));
        }

        if self.use_environment {
            let endpoint_is_https = endpoint.starts_with("https://");
            let keys = if endpoint_is_https {
                ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
            } else {
                ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
            };
            for key in keys {
                if let Some(value) = read_env(key) {
                    if !value.trim().is_empty() {
                        return Ok(Some(value));
                    }
                }
            }
        }

        if self.required {
            return Err(CoreError::new(
                "GRPC_PROXY_REQUIRED",
                "proxy is required but no proxy URL was configured",
            ));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TonicRunnerClient {
    config: GrpcClientConfig,
    credential: StreamCredential,
    identity: StreamIdentity,
}

impl TonicRunnerClient {
    pub fn new(
        config: GrpcClientConfig,
        credential: StreamCredential,
        identity: StreamIdentity,
    ) -> CoreResult<Self> {
        validate_stream_credential(&credential)?;
        validate_stream_identity(&identity)?;

        Ok(Self {
            config,
            credential,
            identity,
        })
    }

    pub async fn connect_channel(&self) -> CoreResult<Channel> {
        connect_channel(&self.config).await
    }

    pub async fn open_stream<R>(
        &self,
        outbound: R,
    ) -> CoreResult<Response<Streaming<pb::ServerToRunner>>>
    where
        R: IntoStreamingRequest<Message = pb::RunnerToServer>,
    {
        let channel = self.connect_channel().await?;
        self.open_stream_on_channel(channel, outbound).await
    }

    pub async fn open_stream_on_channel<R>(
        &self,
        channel: Channel,
        outbound: R,
    ) -> CoreResult<Response<Streaming<pb::ServerToRunner>>>
    where
        R: IntoStreamingRequest<Message = pb::RunnerToServer>,
    {
        let mut client = pb::runner_data_plane_client::RunnerDataPlaneClient::new(channel);
        if self.config.compression == CompressionConfig::Gzip {
            client = client
                .send_compressed(CompressionEncoding::Gzip)
                .accept_compressed(CompressionEncoding::Gzip);
        }
        let mut request = outbound.into_streaming_request();
        attach_required_metadata(&mut request, &self.credential, &self.identity)?;

        client.open(request).await.map_err(map_tonic_status)
    }
}

pub async fn connect_channel(config: &GrpcClientConfig) -> CoreResult<Channel> {
    validate_proxy_transport(config, |key| std::env::var(key).ok())?;

    let mut endpoint = Endpoint::from_shared(config.endpoint.clone())
        .map_err(|err| CoreError::new("GRPC_ENDPOINT_INVALID", err.to_string()))?
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .http2_keep_alive_interval(config.keepalive.interval)
        .keep_alive_timeout(config.keepalive.timeout)
        .keep_alive_while_idle(config.keepalive.while_idle);

    if config.tls.enabled {
        let mut tls = ClientTlsConfig::new();
        if let Some(domain_name) = &config.tls.domain_name {
            tls = tls.domain_name(domain_name.clone());
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|err| CoreError::new("GRPC_TLS_CONFIG_INVALID", err.to_string()))?;
    }

    endpoint
        .connect()
        .await
        .map_err(|err| CoreError::new("GRPC_CONNECT_FAILED", err.to_string()))
}

pub fn validate_proxy_transport<F>(config: &GrpcClientConfig, read_env: F) -> CoreResult<()>
where
    F: Fn(&str) -> Option<String>,
{
    let proxy_url = config
        .proxy
        .resolve_for_endpoint(&config.endpoint, read_env)?;
    if proxy_url.is_some() {
        return Err(CoreError::new(
            "GRPC_PROXY_UNSUPPORTED",
            "tonic transport proxy is not wired; unset proxy config or use a direct endpoint",
        ));
    }
    Ok(())
}

pub fn attach_required_metadata<T>(
    request: &mut Request<T>,
    credential: &StreamCredential,
    identity: &StreamIdentity,
) -> CoreResult<()> {
    request.metadata_mut().insert(
        "authorization",
        ascii_metadata_value(format!("Bearer {}", credential.stream_token))?,
    );
    request.metadata_mut().insert(
        "x-loomex-org-id",
        ascii_metadata_value(identity.organization_id.clone())?,
    );
    request.metadata_mut().insert(
        "x-loomex-project-id",
        ascii_metadata_value(identity.project_id.clone())?,
    );
    request.metadata_mut().insert(
        "x-loomex-runner-device-id",
        ascii_metadata_value(identity.runner_device_id.clone())?,
    );
    request.metadata_mut().insert(
        "x-loomex-runner-session-id",
        ascii_metadata_value(identity.runner_session_id.clone())?,
    );
    request.metadata_mut().insert(
        "x-loomex-protocol-version",
        ascii_metadata_value(identity.protocol_version.clone())?,
    );
    request.metadata_mut().insert(
        "x-loomex-runner-version",
        ascii_metadata_value(identity.runner_version.clone())?,
    );
    Ok(())
}

pub fn validate_stream_credential(credential: &StreamCredential) -> CoreResult<()> {
    if credential.stream_token.trim().is_empty() {
        return Err(CoreError::new(
            "STREAM_AUTH_MISSING_TOKEN",
            "stream token is required",
        ));
    }
    if credential.audience.trim().is_empty() {
        return Err(CoreError::new(
            "STREAM_AUTH_MISSING_AUDIENCE",
            "stream credential audience is required",
        ));
    }
    if credential.audience != STREAM_TOKEN_AUDIENCE {
        return Err(CoreError::new(
            "STREAM_TOKEN_AUDIENCE_INVALID",
            "stream credential audience must be runner_stream",
        ));
    }
    if credential.expires_at_epoch_ms == 0 {
        return Err(CoreError::new(
            "STREAM_AUTH_MISSING_EXPIRY",
            "stream credential expiry is required",
        ));
    }
    Ok(())
}

pub fn validate_stream_identity(identity: &StreamIdentity) -> CoreResult<()> {
    for (field, value) in [
        ("organization_id", &identity.organization_id),
        ("project_id", &identity.project_id),
        ("runner_device_id", &identity.runner_device_id),
        ("runner_session_id", &identity.runner_session_id),
        ("protocol_version", &identity.protocol_version),
        ("runner_version", &identity.runner_version),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("STREAM_IDENTITY_MISSING_FIELD", field));
        }
    }
    Ok(())
}

fn ascii_metadata_value(value: String) -> CoreResult<MetadataValue<tonic::metadata::Ascii>> {
    value
        .parse()
        .map_err(|err: tonic::metadata::errors::InvalidMetadataValue| {
            CoreError::new("GRPC_METADATA_INVALID", err.to_string())
        })
}

fn map_tonic_status(status: tonic::Status) -> CoreError {
    let code = match status.code() {
        tonic::Code::Unauthenticated => "GRPC_AUTH_FAILED",
        tonic::Code::PermissionDenied => "GRPC_PERMISSION_DENIED",
        tonic::Code::DeadlineExceeded => "GRPC_TIMEOUT",
        tonic::Code::Unavailable => "GRPC_UNAVAILABLE",
        tonic::Code::InvalidArgument => "GRPC_VALIDATION_FAILED",
        _ => "GRPC_STREAM_FAILED",
    };
    CoreError::new(code, status.message().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_VERSION;

    fn identity() -> StreamIdentity {
        StreamIdentity {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            runner_device_id: "device_123".to_string(),
            runner_session_id: "session_123".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_version: "0.1.0".to_string(),
        }
    }

    #[test]
    fn auth_failure_is_structured_before_connect() {
        let credential = StreamCredential {
            stream_token: String::new(),
            audience: STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: 1,
        };

        assert_eq!(
            "STREAM_AUTH_MISSING_TOKEN",
            TonicRunnerClient::new(GrpcClientConfig::default(), credential, identity())
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn required_metadata_matches_contract() {
        let credential = StreamCredential {
            stream_token: "stream_token_123".to_string(),
            audience: STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: 1,
        };
        let identity = identity();
        let mut request = Request::new(());

        attach_required_metadata(&mut request, &credential, &identity).unwrap();

        for key in [
            "authorization",
            "x-loomex-org-id",
            "x-loomex-project-id",
            "x-loomex-runner-device-id",
            "x-loomex-runner-session-id",
            "x-loomex-protocol-version",
            "x-loomex-runner-version",
        ] {
            assert!(request.metadata().contains_key(key), "missing {key}");
        }
    }

    #[test]
    fn proxy_required_without_env_is_structured() {
        let proxy = ProxyConfig {
            use_environment: true,
            required: true,
            explicit_proxy_url: None,
        };

        assert_eq!(
            "GRPC_PROXY_REQUIRED",
            proxy
                .resolve_for_endpoint("https://api.loomex.app", |_| None)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn proxy_env_can_be_resolved_for_https_endpoint() {
        let proxy = ProxyConfig {
            use_environment: true,
            required: true,
            explicit_proxy_url: None,
        };

        let resolved = proxy
            .resolve_for_endpoint("https://api.loomex.app", |key| {
                (key == "HTTPS_PROXY").then(|| "http://proxy.local:8080".to_string())
            })
            .unwrap();

        assert_eq!(Some("http://proxy.local:8080".to_string()), resolved);
    }

    #[test]
    fn resolved_proxy_fails_fast_until_transport_support_is_wired() {
        let config = GrpcClientConfig {
            proxy: ProxyConfig {
                use_environment: true,
                required: true,
                explicit_proxy_url: None,
            },
            ..GrpcClientConfig::default()
        };

        assert_eq!(
            "GRPC_PROXY_UNSUPPORTED",
            validate_proxy_transport(&config, |key| {
                (key == "HTTPS_PROXY").then(|| "http://proxy.local:8080".to_string())
            })
            .unwrap_err()
            .code
        );
    }

    #[test]
    fn stream_credential_rejects_non_canonical_audience() {
        let credential = StreamCredential {
            stream_token: "stream_token_123".to_string(),
            audience: "runner-stream".to_string(),
            expires_at_epoch_ms: 1,
        };

        assert_eq!(
            "STREAM_TOKEN_AUDIENCE_INVALID",
            validate_stream_credential(&credential).unwrap_err().code
        );
    }

    #[test]
    fn stream_credential_reports_refresh_window() {
        let credential = StreamCredential {
            stream_token: "stream_token_123".to_string(),
            audience: STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: 10_000,
        };

        assert!(credential.should_refresh(9_500, 1_000));
    }

    #[test]
    fn stream_credential_debug_does_not_print_secret() {
        let credential = StreamCredential {
            stream_token: "stream_token_123".to_string(),
            audience: STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: 10_000,
        };

        assert!(!format!("{credential:?}").contains("stream_token_123"));
    }
}
