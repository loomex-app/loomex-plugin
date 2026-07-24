use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message;
use prost_types::Timestamp;
#[cfg(test)]
use std::collections::VecDeque;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::grpc::{
    pb, validate_stream_credential, validate_stream_identity, GrpcClientConfig, StreamCredential,
    TonicRunnerClient,
};
use crate::protocol::StreamIdentity;
use crate::stream::{ServerEvent, StreamSupervisor};
use crate::{CoreError, CoreResult};

const WS_RUNNER_TO_SERVER_TAG: u8 = 1;
const WS_SERVER_TO_RUNNER_TAG: u8 = 2;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerTransport {
    Grpc,
    WebSocket,
}

impl RunnerTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::WebSocket => "websocket",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportNegotiationPolicy {
    GrpcPreferred,
    WebSocketPreferred,
    ForceGrpc,
    ForceWebSocket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketClientConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_frame_bytes: usize,
    pub proxy: WebSocketProxyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketProxyConfig {
    pub use_environment: bool,
    pub required: bool,
    pub explicit_proxy_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportClientConfig {
    pub grpc: GrpcClientConfig,
    pub websocket: Option<WebSocketClientConfig>,
    pub negotiation: TransportNegotiationPolicy,
}

pub enum RunnerTransportSession {
    Grpc(tonic::transport::Channel),
    WebSocket {
        client: WebSocketRunnerClient,
        stream: RunnerWebSocketStream,
    },
    #[cfg(test)]
    Test(RunnerTransport),
}

pub struct TransportConnector {
    config: TransportClientConfig,
    credential: StreamCredential,
    identity: StreamIdentity,
    metrics: TransportMetrics,
}

pub struct RunnerTransportRuntime {
    connector: TransportConnector,
    supervisor: StreamSupervisor,
    session: Option<ActiveTransportSession>,
    selection: Option<TransportSelection>,
}

pub struct RuntimeStep {
    pub selection: TransportSelection,
    pub event: ServerEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportProbe {
    pub transport: RunnerTransport,
    pub available: bool,
    pub retryable: bool,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportSelection {
    pub transport: RunnerTransport,
    pub reason: String,
    pub fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMetrics {
    pub reconnect_count: u64,
    pub transport_fallback_count: u64,
    pub stream_latency_ms: Option<u64>,
    pub message_lag_ms: Option<u64>,
    pub dropped_events: u64,
    pub duplicate_events: u64,
    pub accepted_events: u64,
    last_server_sequence: u64,
}

#[derive(Debug, Clone)]
pub struct FlowControlWindow {
    inner: Arc<Mutex<FlowControlState>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowControlState {
    max_inflight_bytes: usize,
    inflight_bytes: usize,
}

#[derive(Debug)]
pub struct FlowControlPermit {
    window: FlowControlWindow,
    bytes: usize,
    released: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebSocketFrame {
    RunnerToServer(pb::RunnerToServer),
    ServerToRunner(pb::ServerToRunner),
}

pub type RunnerWebSocketStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone)]
pub struct WebSocketRunnerClient {
    config: WebSocketClientConfig,
    credential: StreamCredential,
    identity: StreamIdentity,
}

impl Default for WebSocketClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "wss://api.loomex.app/runner-stream".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            max_frame_bytes: 1_048_576,
            proxy: WebSocketProxyConfig {
                use_environment: true,
                required: false,
                explicit_proxy_url: None,
            },
        }
    }
}

impl WebSocketClientConfig {
    pub fn validate<F>(&self, read_env: F) -> CoreResult<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        if !(self.endpoint.starts_with("wss://") || self.endpoint.starts_with("ws://")) {
            return Err(CoreError::new(
                "WEBSOCKET_ENDPOINT_INVALID",
                "websocket endpoint must use ws:// or wss://",
            ));
        }
        if self.max_frame_bytes == 0 {
            return Err(CoreError::new(
                "WEBSOCKET_FRAME_LIMIT_INVALID",
                "max websocket frame bytes must be greater than zero",
            ));
        }
        if self
            .proxy
            .resolve_for_endpoint(&self.endpoint, read_env)?
            .is_some()
        {
            return Err(CoreError::new(
                "WEBSOCKET_PROXY_UNSUPPORTED",
                "websocket proxy transport is not wired; unset proxy config or use a direct endpoint",
            ));
        }
        Ok(())
    }
}

impl TransportConnector {
    pub fn new(
        config: TransportClientConfig,
        credential: StreamCredential,
        identity: StreamIdentity,
    ) -> CoreResult<Self> {
        validate_stream_credential(&credential)?;
        validate_stream_identity(&identity)?;
        Ok(Self {
            config,
            credential,
            identity,
            metrics: TransportMetrics::new(),
        })
    }

    pub fn metrics(&self) -> &TransportMetrics {
        &self.metrics
    }

    pub async fn connect(&mut self) -> CoreResult<(TransportSelection, RunnerTransportSession)> {
        let grpc_client = TonicRunnerClient::new(
            self.config.grpc.clone(),
            self.credential.clone(),
            self.identity.clone(),
        )?;
        let grpc_result = grpc_client
            .connect_channel()
            .await
            .map(RunnerTransportSession::Grpc);

        self.connect_after_grpc_result(grpc_result, |config, credential, identity| async move {
            let websocket_client = WebSocketRunnerClient::new(config, credential, identity)?;
            let stream = websocket_client.connect().await?;
            Ok(RunnerTransportSession::WebSocket {
                client: websocket_client,
                stream,
            })
        })
        .await
    }

    async fn connect_after_grpc_result<F, Fut>(
        &mut self,
        grpc_result: CoreResult<RunnerTransportSession>,
        websocket_open: F,
    ) -> CoreResult<(TransportSelection, RunnerTransportSession)>
    where
        F: FnOnce(WebSocketClientConfig, StreamCredential, StreamIdentity) -> Fut,
        Fut: std::future::Future<Output = CoreResult<RunnerTransportSession>>,
    {
        match self.config.negotiation {
            TransportNegotiationPolicy::ForceGrpc => {
                let session = grpc_result?;
                Ok((
                    selection(RunnerTransport::Grpc, "grpc forced and connected", false),
                    session,
                ))
            }
            TransportNegotiationPolicy::GrpcPreferred => match grpc_result {
                Ok(session) => Ok((
                    selection(RunnerTransport::Grpc, "grpc connected", false),
                    session,
                )),
                Err(err) if grpc_error_allows_websocket_fallback(err.code) => {
                    let websocket_config = self.config.websocket.clone().ok_or_else(|| {
                        CoreError::new(
                            "WEBSOCKET_FALLBACK_NOT_CONFIGURED",
                            "websocket fallback endpoint is not configured",
                        )
                    })?;
                    let session = websocket_open(
                        websocket_config,
                        self.credential.clone(),
                        self.identity.clone(),
                    )
                    .await?;
                    self.metrics.record_fallback();
                    Ok((
                        selection(
                            RunnerTransport::WebSocket,
                            format!("grpc failed with {}; websocket connected", err.code),
                            true,
                        ),
                        session,
                    ))
                }
                Err(err) => Err(err),
            },
            TransportNegotiationPolicy::ForceWebSocket
            | TransportNegotiationPolicy::WebSocketPreferred => {
                let websocket_config = self.config.websocket.clone().ok_or_else(|| {
                    CoreError::new(
                        "WEBSOCKET_FALLBACK_NOT_CONFIGURED",
                        "websocket endpoint is not configured",
                    )
                })?;
                let session = websocket_open(
                    websocket_config,
                    self.credential.clone(),
                    self.identity.clone(),
                )
                .await?;
                let fallback = matches!(
                    self.config.negotiation,
                    TransportNegotiationPolicy::WebSocketPreferred
                );
                if fallback {
                    self.metrics.record_fallback();
                }
                Ok((
                    selection(RunnerTransport::WebSocket, "websocket connected", fallback),
                    session,
                ))
            }
        }
    }

    #[cfg(test)]
    async fn connect_with_test_results(
        &mut self,
        grpc_result: CoreResult<()>,
        websocket_result: CoreResult<()>,
    ) -> CoreResult<TransportSelection> {
        let (_, session) = self
            .connect_with_test_session(grpc_result, websocket_result)
            .await?;
        Ok(selection(
            session.transport(),
            format!("{} test session connected", session.transport().as_str()),
            self.metrics.transport_fallback_count > 0,
        ))
    }

    #[cfg(test)]
    async fn connect_with_test_session(
        &mut self,
        grpc_result: CoreResult<()>,
        websocket_result: CoreResult<()>,
    ) -> CoreResult<(TransportSelection, RunnerTransportSession)> {
        self.connect_after_grpc_result(grpc_result.map(|_| RunnerTransportSession::test_grpc()), {
            move |_config, _credential, _identity| async move {
                websocket_result.map(|_| RunnerTransportSession::test_websocket())
            }
        })
        .await
    }
}

impl RunnerTransportRuntime {
    pub fn new(connector: TransportConnector, supervisor: StreamSupervisor) -> Self {
        Self {
            connector,
            supervisor,
            session: None,
            selection: None,
        }
    }

    pub fn supervisor(&self) -> &StreamSupervisor {
        &self.supervisor
    }

    pub fn supervisor_mut(&mut self) -> &mut StreamSupervisor {
        &mut self.supervisor
    }

    pub fn selection(&self) -> Option<&TransportSelection> {
        self.selection.as_ref()
    }

    pub async fn connect_and_register(&mut self, now_epoch_ms: u64) -> CoreResult<RuntimeStep> {
        let (selection, session) = self.connector.connect().await?;
        self.open_selected_session(selection, session, now_epoch_ms)
            .await
    }

    async fn open_selected_session(
        &mut self,
        selection: TransportSelection,
        session: RunnerTransportSession,
        now_epoch_ms: u64,
    ) -> CoreResult<RuntimeStep> {
        if selection.fallback {
            self.supervisor.record_transport_fallback();
        }
        let hello = self.supervisor.runner_hello(now_epoch_ms);
        let mut active = self.open_runtime_session(session, hello).await?;
        let server_message = active.receive_server_to_runner().await?;
        let event = self
            .supervisor
            .accept_server_message(server_message, now_epoch_ms)?;
        self.selection = Some(selection.clone());
        self.session = Some(active);
        Ok(RuntimeStep { selection, event })
    }

    async fn open_runtime_session(
        &self,
        session: RunnerTransportSession,
        hello: pb::RunnerToServer,
    ) -> CoreResult<ActiveTransportSession> {
        match session {
            RunnerTransportSession::Grpc(channel) => {
                let (outbound, inbound) =
                    mpsc::channel::<pb::RunnerToServer>(self.grpc_outbound_buffer());
                outbound
                    .send(hello)
                    .await
                    .map_err(|_| CoreError::new("GRPC_STREAM_SEND_FAILED", "grpc stream closed"))?;
                let client = TonicRunnerClient::new(
                    self.connector.config.grpc.clone(),
                    self.connector.credential.clone(),
                    self.connector.identity.clone(),
                )?;
                let response = client
                    .open_stream_on_channel(channel, ReceiverStream::new(inbound))
                    .await?;
                Ok(ActiveTransportSession::Grpc {
                    outbound,
                    inbound: response.into_inner(),
                    request_timeout: self.connector.config.grpc.request_timeout,
                })
            }
            RunnerTransportSession::WebSocket { client, mut stream } => {
                client.send_runner_to_server(&mut stream, hello).await?;
                Ok(ActiveTransportSession::WebSocket { client, stream })
            }
            #[cfg(test)]
            RunnerTransportSession::Test(transport) => {
                let mut active = ActiveTransportSession::test(transport, Vec::new());
                active.send_runner_to_server(hello).await?;
                Ok(active)
            }
        }
    }

    pub async fn receive_next(&mut self, now_epoch_ms: u64) -> CoreResult<ServerEvent> {
        let session = self.session_mut()?;
        let message = session.receive_server_to_runner().await?;
        self.supervisor.accept_server_message(message, now_epoch_ms)
    }

    pub async fn send_runner_message(&mut self, message: pb::RunnerToServer) -> CoreResult<()> {
        self.session_mut()?.send_runner_to_server(message).await
    }

    pub async fn send_output_messages(
        &mut self,
        messages: Vec<pb::RunnerToServer>,
    ) -> CoreResult<()> {
        let output_bytes = output_payload_bytes(&messages);
        let _permit = self.supervisor.reserve_output_flow_control(output_bytes)?;
        for message in messages {
            self.session_mut()?.send_runner_to_server(message).await?;
        }
        Ok(())
    }

    fn session_mut(&mut self) -> CoreResult<&mut ActiveTransportSession> {
        self.session.as_mut().ok_or_else(|| {
            CoreError::new(
                "RUNNER_TRANSPORT_NOT_CONNECTED",
                "runner transport session has not been opened",
            )
        })
    }

    fn grpc_outbound_buffer(&self) -> usize {
        32
    }

    #[cfg(test)]
    async fn connect_and_register_with_test_results(
        &mut self,
        grpc_result: CoreResult<()>,
        websocket_result: CoreResult<()>,
        server_messages: Vec<pb::ServerToRunner>,
        now_epoch_ms: u64,
    ) -> CoreResult<RuntimeStep> {
        let (selection, session) = self
            .connector
            .connect_with_test_session(grpc_result, websocket_result)
            .await?;
        let mut active = match session {
            RunnerTransportSession::Test(transport) => {
                ActiveTransportSession::test(transport, server_messages)
            }
            _ => unreachable!("test connector only returns test sessions"),
        };
        if selection.fallback {
            self.supervisor.record_transport_fallback();
        }
        let hello = self.supervisor.runner_hello(now_epoch_ms);
        active.send_runner_to_server(hello).await?;
        let server_message = active.receive_server_to_runner().await?;
        let event = self
            .supervisor
            .accept_server_message(server_message, now_epoch_ms)?;
        self.selection = Some(selection.clone());
        self.session = Some(active);
        Ok(RuntimeStep { selection, event })
    }

    #[cfg(test)]
    fn install_test_session(&mut self, session: ActiveTransportSession) {
        self.session = Some(session);
    }
}

enum ActiveTransportSession {
    Grpc {
        outbound: mpsc::Sender<pb::RunnerToServer>,
        inbound: tonic::Streaming<pb::ServerToRunner>,
        request_timeout: Duration,
    },
    WebSocket {
        client: WebSocketRunnerClient,
        stream: RunnerWebSocketStream,
    },
    #[cfg(test)]
    Test {
        transport: RunnerTransport,
        inbound: VecDeque<pb::ServerToRunner>,
        sent: Vec<pb::RunnerToServer>,
        send_error: Option<CoreError>,
        send_delay: Duration,
        request_timeout: Duration,
    },
}

impl ActiveTransportSession {
    async fn send_runner_to_server(&mut self, message: pb::RunnerToServer) -> CoreResult<()> {
        match self {
            Self::Grpc {
                outbound,
                request_timeout,
                ..
            } => with_transport_timeout(
                *request_timeout,
                "GRPC_STREAM_SEND_TIMEOUT",
                "grpc stream send",
                outbound.send(message),
            )
            .await?
            .map_err(|_| CoreError::new("GRPC_STREAM_SEND_FAILED", "grpc stream closed")),
            Self::WebSocket { client, stream } => {
                client.send_runner_to_server(stream, message).await
            }
            #[cfg(test)]
            Self::Test {
                sent,
                send_error,
                send_delay,
                request_timeout,
                ..
            } => {
                let send_result = with_transport_timeout(
                    *request_timeout,
                    "TRANSPORT_TEST_SEND_TIMEOUT",
                    "test transport send",
                    async {
                        if !send_delay.is_zero() {
                            tokio::time::sleep(*send_delay).await;
                        }
                        if let Some(err) = send_error.clone() {
                            Err(err)
                        } else {
                            sent.push(message);
                            Ok(())
                        }
                    },
                )
                .await?;
                send_result
            }
        }
    }

    async fn receive_server_to_runner(&mut self) -> CoreResult<pb::ServerToRunner> {
        match self {
            Self::Grpc {
                inbound,
                request_timeout,
                ..
            } => {
                let next = with_transport_timeout(
                    *request_timeout,
                    "GRPC_STREAM_RECEIVE_TIMEOUT",
                    "grpc stream receive",
                    inbound.message(),
                )
                .await?
                .map_err(map_grpc_stream_status)?;
                next.ok_or_else(|| CoreError::new("GRPC_STREAM_CLOSED", "grpc stream closed"))
            }
            Self::WebSocket { client, stream } => client.receive_server_to_runner(stream).await,
            #[cfg(test)]
            Self::Test { inbound, .. } => inbound.pop_front().ok_or_else(|| {
                CoreError::new(
                    "TRANSPORT_TEST_STREAM_CLOSED",
                    "test transport has no server messages",
                )
            }),
        }
    }

    #[cfg(test)]
    fn test(transport: RunnerTransport, server_messages: Vec<pb::ServerToRunner>) -> Self {
        Self::Test {
            transport,
            inbound: server_messages.into(),
            sent: Vec::new(),
            send_error: None,
            send_delay: Duration::ZERO,
            request_timeout: Duration::from_secs(60),
        }
    }

    #[cfg(test)]
    fn test_send_error(transport: RunnerTransport, err: CoreError) -> Self {
        Self::Test {
            transport,
            inbound: VecDeque::new(),
            sent: Vec::new(),
            send_error: Some(err),
            send_delay: Duration::ZERO,
            request_timeout: Duration::from_secs(60),
        }
    }

    #[cfg(test)]
    fn test_send_timeout(transport: RunnerTransport) -> Self {
        Self::Test {
            transport,
            inbound: VecDeque::new(),
            sent: Vec::new(),
            send_error: None,
            send_delay: Duration::from_millis(50),
            request_timeout: Duration::from_millis(1),
        }
    }

    #[cfg(test)]
    fn test_sent_messages(&self) -> &[pb::RunnerToServer] {
        match self {
            Self::Test { sent, .. } => sent,
            _ => &[],
        }
    }

    #[cfg(test)]
    fn test_transport(&self) -> Option<RunnerTransport> {
        match self {
            Self::Test { transport, .. } => Some(*transport),
            _ => None,
        }
    }
}

impl WebSocketRunnerClient {
    pub fn new(
        config: WebSocketClientConfig,
        credential: StreamCredential,
        identity: StreamIdentity,
    ) -> CoreResult<Self> {
        config.validate(|key| std::env::var(key).ok())?;
        validate_stream_credential(&credential)?;
        validate_stream_identity(&identity)?;
        Ok(Self {
            config,
            credential,
            identity,
        })
    }

    pub fn build_request(&self) -> CoreResult<Request> {
        websocket_request(&self.config.endpoint, &self.credential, &self.identity)
    }

    pub async fn connect(&self) -> CoreResult<RunnerWebSocketStream> {
        let request = self.build_request()?;
        let connected = with_transport_timeout(
            self.config.connect_timeout,
            "WEBSOCKET_CONNECT_TIMEOUT",
            "websocket connect",
            connect_async(request),
        )
        .await?;
        let (stream, _response) =
            connected.map_err(|err| CoreError::new("WEBSOCKET_CONNECT_FAILED", err.to_string()))?;
        Ok(stream)
    }

    pub async fn send_runner_to_server(
        &self,
        stream: &mut RunnerWebSocketStream,
        message: pb::RunnerToServer,
    ) -> CoreResult<()> {
        let frame = encode_websocket_frame(&WebSocketFrame::RunnerToServer(message))?;
        if frame.len() > self.config.max_frame_bytes {
            return Err(CoreError::new(
                "WEBSOCKET_FRAME_TOO_LARGE",
                "websocket runner frame exceeded configured maximum",
            ));
        }
        with_transport_timeout(
            self.config.request_timeout,
            "WEBSOCKET_SEND_TIMEOUT",
            "websocket send",
            stream.send(WebSocketMessage::Binary(frame.into())),
        )
        .await?
        .map_err(|err| CoreError::new("WEBSOCKET_SEND_FAILED", err.to_string()))
    }

    pub async fn receive_server_to_runner(
        &self,
        stream: &mut RunnerWebSocketStream,
    ) -> CoreResult<pb::ServerToRunner> {
        let next = with_transport_timeout(
            self.config.request_timeout,
            "WEBSOCKET_RECEIVE_TIMEOUT",
            "websocket receive",
            stream.next(),
        )
        .await?;
        let Some(message) = next else {
            return Err(CoreError::new(
                "WEBSOCKET_STREAM_CLOSED",
                "websocket stream closed before server message",
            ));
        };
        match message.map_err(|err| CoreError::new("WEBSOCKET_RECEIVE_FAILED", err.to_string()))? {
            WebSocketMessage::Binary(data) => {
                match decode_websocket_frame(&data, self.config.max_frame_bytes)? {
                    WebSocketFrame::ServerToRunner(message) => Ok(message),
                    WebSocketFrame::RunnerToServer(_) => Err(CoreError::new(
                        "WEBSOCKET_FRAME_DIRECTION_INVALID",
                        "runner received a runner-to-server frame",
                    )),
                }
            }
            WebSocketMessage::Close(_) => Err(CoreError::new(
                "WEBSOCKET_STREAM_CLOSED",
                "websocket stream closed by server",
            )),
            _ => Err(CoreError::new(
                "WEBSOCKET_FRAME_TYPE_INVALID",
                "websocket runner stream requires binary protobuf frames",
            )),
        }
    }
}

impl WebSocketProxyConfig {
    pub fn resolve_for_endpoint<F>(&self, endpoint: &str, read_env: F) -> CoreResult<Option<String>>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(proxy_url) = &self.explicit_proxy_url {
            if proxy_url.trim().is_empty() {
                return Err(CoreError::new(
                    "WEBSOCKET_PROXY_CONFIG_INVALID",
                    "explicit proxy url cannot be empty",
                ));
            }
            return Ok(Some(proxy_url.clone()));
        }

        if self.use_environment {
            let endpoint_is_secure = endpoint.starts_with("wss://");
            let keys = if endpoint_is_secure {
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
                "WEBSOCKET_PROXY_REQUIRED",
                "websocket proxy is required but no proxy URL was configured",
            ));
        }

        Ok(None)
    }
}

impl TransportProbe {
    pub fn available(transport: RunnerTransport) -> Self {
        Self {
            transport,
            available: true,
            retryable: false,
            code: "OK",
            message: "available".to_string(),
        }
    }

    pub fn unavailable(
        transport: RunnerTransport,
        retryable: bool,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            available: false,
            retryable,
            code,
            message: message.into(),
        }
    }
}

impl TransportMetrics {
    pub fn new() -> Self {
        Self {
            reconnect_count: 0,
            transport_fallback_count: 0,
            stream_latency_ms: None,
            message_lag_ms: None,
            dropped_events: 0,
            duplicate_events: 0,
            accepted_events: 0,
            last_server_sequence: 0,
        }
    }

    pub fn record_reconnect(&mut self) {
        self.reconnect_count += 1;
    }

    pub fn record_fallback(&mut self) {
        self.transport_fallback_count += 1;
    }

    pub fn observe_stream_latency(&mut self, latency: Duration) {
        self.stream_latency_ms = Some(latency.as_millis().min(u128::from(u64::MAX)) as u64);
    }

    pub fn observe_server_message(&mut self, message: &pb::ServerToRunner, now_epoch_ms: u64) {
        if message.sequence == 0 || message.sequence > self.last_server_sequence + 1 {
            self.dropped_events += 1;
        } else if message.sequence <= self.last_server_sequence {
            self.duplicate_events += 1;
            return;
        } else {
            self.accepted_events += 1;
            self.last_server_sequence = message.sequence;
        }
        self.message_lag_ms = timestamp_lag_ms(message.sent_at.as_ref(), now_epoch_ms);
    }

    pub fn observe_rejected_server_message(
        &mut self,
        message: &pb::ServerToRunner,
        now_epoch_ms: u64,
    ) {
        if message.sequence <= self.last_server_sequence {
            self.duplicate_events += 1;
        } else {
            self.dropped_events += 1;
        }
        self.message_lag_ms = timestamp_lag_ms(message.sent_at.as_ref(), now_epoch_ms);
    }
}

impl Default for TransportMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowControlWindow {
    pub fn new(max_inflight_bytes: usize) -> CoreResult<Self> {
        if max_inflight_bytes == 0 {
            return Err(CoreError::new(
                "TRANSPORT_FLOW_CONTROL_INVALID",
                "max inflight bytes must be greater than zero",
            ));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(FlowControlState {
                max_inflight_bytes,
                inflight_bytes: 0,
            })),
        })
    }

    pub fn reserve(&self, bytes: usize) -> CoreResult<FlowControlPermit> {
        let mut inner = self.lock();
        if inner.inflight_bytes.saturating_add(bytes) > inner.max_inflight_bytes {
            return Err(CoreError::new(
                "TRANSPORT_BACKPRESSURE",
                "transport flow-control window is full",
            ));
        }
        inner.inflight_bytes += bytes;
        drop(inner);
        Ok(FlowControlPermit {
            window: self.clone(),
            bytes,
            released: false,
        })
    }

    pub fn release(&self, bytes: usize) {
        let mut inner = self.lock();
        inner.inflight_bytes = inner.inflight_bytes.saturating_sub(bytes);
    }

    pub fn inflight_bytes(&self) -> usize {
        self.lock().inflight_bytes
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FlowControlState> {
        self.inner
            .lock()
            .expect("transport flow-control window lock poisoned")
    }
}

impl PartialEq for FlowControlWindow {
    fn eq(&self, other: &Self) -> bool {
        *self.lock() == *other.lock()
    }
}

impl Eq for FlowControlWindow {}

impl FlowControlPermit {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn release(mut self) {
        if !self.released {
            self.window.release(self.bytes);
            self.released = true;
        }
    }
}

impl Drop for FlowControlPermit {
    fn drop(&mut self) {
        if !self.released {
            self.window.release(self.bytes);
            self.released = true;
        }
    }
}

pub fn negotiate_transport(
    policy: TransportNegotiationPolicy,
    grpc: &TransportProbe,
    websocket: Option<&TransportProbe>,
) -> CoreResult<TransportSelection> {
    match policy {
        TransportNegotiationPolicy::ForceGrpc => require_available(grpc, false),
        TransportNegotiationPolicy::ForceWebSocket => {
            require_available(required_websocket_probe(websocket)?, false)
        }
        TransportNegotiationPolicy::GrpcPreferred => {
            if grpc.available {
                return Ok(selection(RunnerTransport::Grpc, "grpc available", false));
            }
            let ws = required_websocket_probe(websocket)?;
            if grpc.retryable && ws.available {
                return Ok(selection(
                    RunnerTransport::WebSocket,
                    format!("grpc unavailable with {}; websocket available", grpc.code),
                    true,
                ));
            }
            Err(CoreError::new(
                "TRANSPORT_NEGOTIATION_FAILED",
                format!(
                    "grpc failed with {}; websocket fallback unavailable",
                    grpc.code
                ),
            ))
        }
        TransportNegotiationPolicy::WebSocketPreferred => {
            if let Some(ws) = websocket {
                if ws.available {
                    return Ok(selection(
                        RunnerTransport::WebSocket,
                        "websocket available",
                        false,
                    ));
                }
            }
            if grpc.available {
                return Ok(selection(
                    RunnerTransport::Grpc,
                    "websocket unavailable; grpc available",
                    true,
                ));
            }
            Err(CoreError::new(
                "TRANSPORT_NEGOTIATION_FAILED",
                "neither websocket nor grpc transport is available",
            ))
        }
    }
}

pub fn encode_websocket_frame(frame: &WebSocketFrame) -> CoreResult<Vec<u8>> {
    let (tag, mut payload) = match frame {
        WebSocketFrame::RunnerToServer(message) => {
            (WS_RUNNER_TO_SERVER_TAG, message.encode_to_vec())
        }
        WebSocketFrame::ServerToRunner(message) => {
            (WS_SERVER_TO_RUNNER_TAG, message.encode_to_vec())
        }
    };
    let mut output = Vec::with_capacity(payload.len() + 1);
    output.push(tag);
    output.append(&mut payload);
    Ok(output)
}

pub fn decode_websocket_frame(data: &[u8], max_frame_bytes: usize) -> CoreResult<WebSocketFrame> {
    if data.len() > max_frame_bytes {
        return Err(CoreError::new(
            "WEBSOCKET_FRAME_TOO_LARGE",
            "websocket frame exceeded configured maximum",
        ));
    }
    let Some((&tag, payload)) = data.split_first() else {
        return Err(CoreError::new(
            "WEBSOCKET_FRAME_EMPTY",
            "websocket frame cannot be empty",
        ));
    };
    match tag {
        WS_RUNNER_TO_SERVER_TAG => pb::RunnerToServer::decode(payload)
            .map(WebSocketFrame::RunnerToServer)
            .map_err(|err| CoreError::new("WEBSOCKET_PROTO_DECODE_FAILED", err.to_string())),
        WS_SERVER_TO_RUNNER_TAG => pb::ServerToRunner::decode(payload)
            .map(WebSocketFrame::ServerToRunner)
            .map_err(|err| CoreError::new("WEBSOCKET_PROTO_DECODE_FAILED", err.to_string())),
        _ => Err(CoreError::new(
            "WEBSOCKET_FRAME_DIRECTION_INVALID",
            "unknown websocket frame direction tag",
        )),
    }
}

pub fn websocket_request(
    endpoint: &str,
    credential: &StreamCredential,
    identity: &StreamIdentity,
) -> CoreResult<Request> {
    validate_stream_credential(credential)?;
    validate_stream_identity(identity)?;
    Request::builder()
        .uri(endpoint)
        .header(
            "authorization",
            format!("Bearer {}", credential.stream_token),
        )
        .header("x-loomex-org-id", identity.organization_id.clone())
        .header("x-loomex-project-id", identity.project_id.clone())
        .header(
            "x-loomex-runner-device-id",
            identity.runner_device_id.clone(),
        )
        .header(
            "x-loomex-runner-session-id",
            identity.runner_session_id.clone(),
        )
        .header(
            "x-loomex-protocol-version",
            identity.protocol_version.clone(),
        )
        .header("x-loomex-runner-version", identity.runner_version.clone())
        .body(())
        .map_err(|err| CoreError::new("WEBSOCKET_REQUEST_INVALID", err.to_string()))
}

fn require_available(probe: &TransportProbe, fallback: bool) -> CoreResult<TransportSelection> {
    if probe.available {
        Ok(selection(
            probe.transport,
            format!("{} forced and available", probe.transport.as_str()),
            fallback,
        ))
    } else {
        Err(CoreError::new(
            "TRANSPORT_UNAVAILABLE",
            format!("{} unavailable: {}", probe.transport.as_str(), probe.code),
        ))
    }
}

fn required_websocket_probe(probe: Option<&TransportProbe>) -> CoreResult<&TransportProbe> {
    probe.ok_or_else(|| {
        CoreError::new(
            "WEBSOCKET_FALLBACK_NOT_CONFIGURED",
            "websocket fallback endpoint is not configured",
        )
    })
}

fn selection(
    transport: RunnerTransport,
    reason: impl Into<String>,
    fallback: bool,
) -> TransportSelection {
    TransportSelection {
        transport,
        reason: reason.into(),
        fallback,
    }
}

fn timestamp_lag_ms(timestamp: Option<&Timestamp>, now_epoch_ms: u64) -> Option<u64> {
    let timestamp = timestamp?;
    if timestamp.seconds < 0 || timestamp.nanos < 0 {
        return None;
    }
    let sent = timestamp.seconds as u64 * 1000 + timestamp.nanos as u64 / 1_000_000;
    Some(now_epoch_ms.saturating_sub(sent))
}

fn grpc_error_allows_websocket_fallback(code: &str) -> bool {
    matches!(
        code,
        "GRPC_PROXY_UNSUPPORTED"
            | "GRPC_PROXY_REQUIRED"
            | "GRPC_CONNECT_FAILED"
            | "GRPC_CONNECT_TIMEOUT"
            | "GRPC_TLS_CONFIG_INVALID"
            | "GRPC_NETWORK_TIMEOUT"
            | "RUNNER_STREAM_UNAVAILABLE"
    )
}

fn map_grpc_stream_status(status: tonic::Status) -> CoreError {
    CoreError::new("GRPC_STREAM_RECEIVE_FAILED", status.to_string())
}

fn output_payload_bytes(messages: &[pb::RunnerToServer]) -> usize {
    messages
        .iter()
        .filter_map(|message| match message.payload.as_ref()? {
            pb::runner_to_server::Payload::ToolCallOutput(output) => Some(output.data.len()),
            _ => None,
        })
        .sum()
}

impl RunnerTransportSession {
    pub fn transport(&self) -> RunnerTransport {
        match self {
            Self::Grpc(_) => RunnerTransport::Grpc,
            Self::WebSocket { .. } => RunnerTransport::WebSocket,
            #[cfg(test)]
            Self::Test(transport) => *transport,
        }
    }

    #[cfg(test)]
    fn test_grpc() -> Self {
        Self::Test(RunnerTransport::Grpc)
    }

    #[cfg(test)]
    fn test_websocket() -> Self {
        Self::Test(RunnerTransport::WebSocket)
    }
}

async fn with_transport_timeout<T, F>(
    duration: Duration,
    code: &'static str,
    operation: &'static str,
    future: F,
) -> CoreResult<T>
where
    F: std::future::Future<Output = T>,
{
    timeout(duration, future).await.map_err(|_| {
        CoreError::new(
            code,
            format!("{operation} timed out after {}ms", duration.as_millis()),
        )
    })
}

#[cfg(test)]
mod tests {
    use prost_types::{Duration as ProtoDuration, Timestamp};

    use super::*;
    use crate::protocol::PROTOCOL_VERSION;

    fn runner_hello() -> pb::RunnerToServer {
        pb::RunnerToServer {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            runner_device_id: "device_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 1,
            idempotency_key: "runner-hello".to_string(),
            sent_at: Some(timestamp(1000)),
            payload: Some(pb::runner_to_server::Payload::Hello(pb::RunnerHello {
                runner_version: "0.1.0".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                minimum_supported_version: PROTOCOL_VERSION.to_string(),
                capabilities: vec!["shell.exec".to_string()],
                nonce: "nonce_123".to_string(),
                runner_device_id: "device_123".to_string(),
                runner_session_id: "session_123".to_string(),
                resume_after_server_sequence: 7,
                ..Default::default()
            })),
        }
    }

    fn server_hello(sequence: u64) -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence,
            idempotency_key: format!("server-{sequence}"),
            sent_at: Some(timestamp(1000 + sequence)),
            payload: Some(pb::server_to_runner::Payload::Hello(pb::ServerHello {
                protocol_version: PROTOCOL_VERSION.to_string(),
                minimum_supported_version: PROTOCOL_VERSION.to_string(),
                minimum_supported_runner_version: "0.1.0".to_string(),
                heartbeat: Some(pb::HeartbeatConfig {
                    interval: Some(ProtoDuration {
                        seconds: 10,
                        nanos: 0,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    fn tool_call_output(data: Vec<u8>) -> pb::RunnerToServer {
        pb::RunnerToServer {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            runner_device_id: "device_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 2,
            idempotency_key: "output-1".to_string(),
            sent_at: Some(timestamp(2000)),
            payload: Some(pb::runner_to_server::Payload::ToolCallOutput(
                pb::ToolCallOutput {
                    tool_call_id: "tool_123".to_string(),
                    workflow_run_id: "run_123".to_string(),
                    attempt: 1,
                    chunk_sequence: 1,
                    stream: 1,
                    data,
                    text_encoding: "utf-8".to_string(),
                    final_chunk: true,
                    emitted_at: Some(timestamp(2000)),
                    ..Default::default()
                },
            )),
        }
    }

    fn timestamp(epoch_ms: u64) -> Timestamp {
        Timestamp {
            seconds: (epoch_ms / 1000) as i64,
            nanos: ((epoch_ms % 1000) * 1_000_000) as i32,
        }
    }

    fn stream_credential() -> StreamCredential {
        StreamCredential {
            stream_token: "stream_secret".to_string(),
            audience: crate::device::STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: 10_000,
        }
    }

    fn stream_identity() -> StreamIdentity {
        StreamIdentity {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            runner_device_id: "device_123".to_string(),
            runner_session_id: "session_123".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_version: "0.1.0".to_string(),
        }
    }

    fn transport_config(policy: TransportNegotiationPolicy) -> TransportClientConfig {
        TransportClientConfig {
            grpc: GrpcClientConfig::default(),
            websocket: Some(WebSocketClientConfig {
                endpoint: "wss://loomex.app/runner-stream".to_string(),
                proxy: WebSocketProxyConfig {
                    use_environment: false,
                    required: false,
                    explicit_proxy_url: None,
                },
                ..WebSocketClientConfig::default()
            }),
            negotiation: policy,
        }
    }

    fn websocket_config_without_env_proxy() -> WebSocketClientConfig {
        WebSocketClientConfig {
            proxy: WebSocketProxyConfig {
                use_environment: false,
                required: false,
                explicit_proxy_url: None,
            },
            ..WebSocketClientConfig::default()
        }
    }

    fn connector(policy: TransportNegotiationPolicy) -> TransportConnector {
        TransportConnector::new(
            transport_config(policy),
            stream_credential(),
            stream_identity(),
        )
        .unwrap()
    }

    fn stream_supervisor(max_inflight_output_bytes: usize) -> StreamSupervisor {
        let mut supervisor = StreamSupervisor::new(crate::stream::StreamSupervisorConfig {
            identity: stream_identity(),
            project_runner_binding_id: "binding_123".to_string(),
            local_root_path: "/tmp/project".to_string(),
            capabilities: vec!["shell.exec".to_string()],
            default_heartbeat_interval: Duration::from_secs(10),
            default_max_output_chunk_bytes: 64,
            transport_max_inflight_output_bytes: max_inflight_output_bytes,
        })
        .unwrap();
        supervisor.authenticate().unwrap();
        supervisor.bind_project().unwrap();
        supervisor
    }

    fn runtime(
        policy: TransportNegotiationPolicy,
        max_inflight_output_bytes: usize,
    ) -> RunnerTransportRuntime {
        RunnerTransportRuntime::new(
            connector(policy),
            stream_supervisor(max_inflight_output_bytes),
        )
    }

    #[test]
    fn grpc_is_preferred_when_available() {
        let selected = negotiate_transport(
            TransportNegotiationPolicy::GrpcPreferred,
            &TransportProbe::available(RunnerTransport::Grpc),
            Some(&TransportProbe::available(RunnerTransport::WebSocket)),
        )
        .unwrap();

        assert_eq!(RunnerTransport::Grpc, selected.transport);
        assert!(!selected.fallback);
    }

    #[test]
    fn websocket_fallback_is_selected_when_grpc_is_retryably_blocked() {
        let selected = negotiate_transport(
            TransportNegotiationPolicy::GrpcPreferred,
            &TransportProbe::unavailable(
                RunnerTransport::Grpc,
                true,
                "GRPC_PROXY_UNSUPPORTED",
                "proxy blocks grpc",
            ),
            Some(&TransportProbe::available(RunnerTransport::WebSocket)),
        )
        .unwrap();

        assert_eq!(RunnerTransport::WebSocket, selected.transport);
        assert!(selected.fallback);
    }

    #[tokio::test]
    async fn connector_uses_grpc_when_grpc_connects() {
        let mut connector = connector(TransportNegotiationPolicy::GrpcPreferred);

        let selected = connector
            .connect_with_test_results(Ok(()), Ok(()))
            .await
            .unwrap();

        assert_eq!(RunnerTransport::Grpc, selected.transport);
        assert!(!selected.fallback);
        assert_eq!(0, connector.metrics().transport_fallback_count);
    }

    #[tokio::test]
    async fn connector_falls_back_to_websocket_for_retryable_grpc_failure() {
        let mut connector = connector(TransportNegotiationPolicy::GrpcPreferred);

        let selected = connector
            .connect_with_test_results(
                Err(CoreError::new(
                    "GRPC_PROXY_UNSUPPORTED",
                    "proxy blocks grpc",
                )),
                Ok(()),
            )
            .await
            .unwrap();

        assert_eq!(RunnerTransport::WebSocket, selected.transport);
        assert!(selected.fallback);
        assert_eq!(1, connector.metrics().transport_fallback_count);
    }

    #[tokio::test]
    async fn connector_does_not_fallback_for_permanent_grpc_failure() {
        let mut connector = connector(TransportNegotiationPolicy::GrpcPreferred);

        let err = connector
            .connect_with_test_results(
                Err(CoreError::new("STREAM_AUTH_FAILED", "bad stream token")),
                Ok(()),
            )
            .await
            .unwrap_err();

        assert_eq!("STREAM_AUTH_FAILED", err.code);
        assert_eq!(0, connector.metrics().transport_fallback_count);
    }

    #[tokio::test]
    async fn runtime_connects_with_fallback_sends_hello_and_accepts_server_hello() {
        let mut runtime = runtime(TransportNegotiationPolicy::GrpcPreferred, 64);

        let step = runtime
            .connect_and_register_with_test_results(
                Err(CoreError::new("GRPC_CONNECT_FAILED", "network unavailable")),
                Ok(()),
                vec![server_hello(1)],
                1000,
            )
            .await
            .unwrap();

        assert_eq!(RunnerTransport::WebSocket, step.selection.transport);
        assert!(step.selection.fallback);
        assert_eq!(ServerEvent::Registered, step.event);
        assert_eq!(
            1,
            runtime
                .supervisor()
                .transport_metrics()
                .transport_fallback_count
        );
        assert_eq!(1, runtime.supervisor().transport_metrics().accepted_events);
        let session = runtime.session.as_ref().unwrap();
        assert_eq!(Some(RunnerTransport::WebSocket), session.test_transport());
        assert_eq!(1, session.test_sent_messages().len());
        assert!(matches!(
            session.test_sent_messages()[0].payload,
            Some(pb::runner_to_server::Payload::Hello(_))
        ));
    }

    #[tokio::test]
    async fn runtime_output_send_failure_releases_flow_control_permit() {
        let mut runtime = runtime(TransportNegotiationPolicy::ForceWebSocket, 8);
        runtime.install_test_session(ActiveTransportSession::test_send_error(
            RunnerTransport::WebSocket,
            CoreError::new("WEBSOCKET_SEND_FAILED", "send failed"),
        ));

        let err = runtime
            .send_output_messages(vec![tool_call_output(vec![b'x'; 6])])
            .await
            .unwrap_err();

        assert_eq!("WEBSOCKET_SEND_FAILED", err.code);
        assert_eq!(0, runtime.supervisor().output_flow_control_inflight_bytes());
    }

    #[tokio::test]
    async fn runtime_output_send_timeout_releases_flow_control_permit() {
        let mut runtime = runtime(TransportNegotiationPolicy::ForceWebSocket, 8);
        runtime.install_test_session(ActiveTransportSession::test_send_timeout(
            RunnerTransport::WebSocket,
        ));

        let err = runtime
            .send_output_messages(vec![tool_call_output(vec![b'x'; 6])])
            .await
            .unwrap_err();

        assert_eq!("TRANSPORT_TEST_SEND_TIMEOUT", err.code);
        assert_eq!(0, runtime.supervisor().output_flow_control_inflight_bytes());
    }

    #[test]
    fn permanent_grpc_failure_does_not_silently_fallback() {
        let err = negotiate_transport(
            TransportNegotiationPolicy::GrpcPreferred,
            &TransportProbe::unavailable(
                RunnerTransport::Grpc,
                false,
                "STREAM_AUTH_FAILED",
                "bad stream credential",
            ),
            Some(&TransportProbe::available(RunnerTransport::WebSocket)),
        )
        .unwrap_err();

        assert_eq!("TRANSPORT_NEGOTIATION_FAILED", err.code);
    }

    #[test]
    fn websocket_frame_roundtrip_uses_generated_protobuf_contract() {
        let hello = runner_hello();
        let encoded = encode_websocket_frame(&WebSocketFrame::RunnerToServer(hello.clone()))
            .expect("frame encodes");
        let decoded = decode_websocket_frame(&encoded, 16_384).expect("frame decodes");

        assert_eq!(WebSocketFrame::RunnerToServer(hello), decoded);
    }

    #[test]
    fn websocket_connect_request_uses_stream_auth_and_identity_headers() {
        let client = WebSocketRunnerClient::new(
            websocket_config_without_env_proxy(),
            stream_credential(),
            stream_identity(),
        )
        .unwrap();
        let request = client.build_request().unwrap();
        let headers = request.headers();

        assert_eq!("wss://api.loomex.app/runner-stream", request.uri());
        assert_eq!("Bearer stream_secret", headers["authorization"]);
        assert_eq!("org_123", headers["x-loomex-org-id"]);
        assert_eq!("prj_123", headers["x-loomex-project-id"]);
        assert_eq!("device_123", headers["x-loomex-runner-device-id"]);
        assert_eq!("session_123", headers["x-loomex-runner-session-id"]);
        assert_eq!(PROTOCOL_VERSION, headers["x-loomex-protocol-version"]);
        assert_eq!("0.1.0", headers["x-loomex-runner-version"]);
    }

    #[test]
    fn websocket_server_frame_roundtrip_preserves_resume_cursor() {
        let hello = server_hello(8);
        let encoded = encode_websocket_frame(&WebSocketFrame::ServerToRunner(hello.clone()))
            .expect("frame encodes");
        let decoded = decode_websocket_frame(&encoded, 16_384).expect("frame decodes");

        assert_eq!(WebSocketFrame::ServerToRunner(hello), decoded);
    }

    #[test]
    fn websocket_frame_limit_enforces_backpressure_boundary() {
        let encoded =
            encode_websocket_frame(&WebSocketFrame::RunnerToServer(tool_call_output(vec![
                b'x';
                64
            ])))
            .unwrap();

        assert_eq!(
            "WEBSOCKET_FRAME_TOO_LARGE",
            decode_websocket_frame(&encoded, 8).unwrap_err().code
        );
    }

    #[test]
    fn flow_control_rejects_large_output_until_window_is_released() {
        let window = FlowControlWindow::new(8).unwrap();
        let permit = window.reserve(6).unwrap();

        assert_eq!(
            "TRANSPORT_BACKPRESSURE",
            window.reserve(3).unwrap_err().code
        );

        permit.release();
        let _second = window.reserve(3).unwrap();
        assert_eq!(3, window.inflight_bytes());
    }

    #[test]
    fn metrics_track_reconnect_lag_duplicate_and_dropped_events() {
        let mut metrics = TransportMetrics::new();
        metrics.record_reconnect();
        metrics.record_fallback();
        metrics.observe_stream_latency(Duration::from_millis(42));
        metrics.observe_server_message(&server_hello(1), 1_100);
        metrics.observe_server_message(&server_hello(1), 1_110);
        metrics.observe_server_message(&server_hello(3), 1_120);

        assert_eq!(1, metrics.reconnect_count);
        assert_eq!(1, metrics.transport_fallback_count);
        assert_eq!(Some(42), metrics.stream_latency_ms);
        assert_eq!(Some(117), metrics.message_lag_ms);
        assert_eq!(1, metrics.accepted_events);
        assert_eq!(1, metrics.duplicate_events);
        assert_eq!(1, metrics.dropped_events);
    }

    #[test]
    fn websocket_config_validates_endpoint_and_proxy() {
        let mut config = WebSocketClientConfig {
            endpoint: "https://loomex.app/ws".to_string(),
            ..WebSocketClientConfig::default()
        };
        assert_eq!(
            "WEBSOCKET_ENDPOINT_INVALID",
            config.validate(|_| None).unwrap_err().code
        );

        config.endpoint = "wss://loomex.app/runner-stream".to_string();
        config.proxy.required = true;
        assert_eq!(
            "WEBSOCKET_PROXY_REQUIRED",
            config.validate(|_| None).unwrap_err().code
        );
        assert_eq!(
            "WEBSOCKET_PROXY_UNSUPPORTED",
            config
                .validate(|key| {
                    if key == "HTTPS_PROXY" {
                        Some("http://proxy.local:8080".to_string())
                    } else {
                        None
                    }
                })
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn websocket_client_rejects_explicit_proxy_before_connect() {
        let config = WebSocketClientConfig {
            endpoint: "wss://loomex.app/runner-stream".to_string(),
            proxy: WebSocketProxyConfig {
                use_environment: false,
                required: false,
                explicit_proxy_url: Some("http://proxy.local:8080".to_string()),
            },
            ..WebSocketClientConfig::default()
        };

        let err =
            WebSocketRunnerClient::new(config, stream_credential(), stream_identity()).unwrap_err();

        assert_eq!("WEBSOCKET_PROXY_UNSUPPORTED", err.code);
    }

    #[tokio::test]
    async fn websocket_timeout_helper_returns_stable_error() {
        let err = with_transport_timeout(
            Duration::from_millis(1),
            "WEBSOCKET_RECEIVE_TIMEOUT",
            "websocket receive",
            tokio::time::sleep(Duration::from_millis(50)),
        )
        .await
        .unwrap_err();

        assert_eq!("WEBSOCKET_RECEIVE_TIMEOUT", err.code);
        assert!(err.message.contains("websocket receive timed out"));
    }
}
