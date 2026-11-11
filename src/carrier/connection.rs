//! The mailbox-transport WebSocket client.
//!
//! One connection carries the whole mailbox contract: CHALLENGE → HELLO →
//! READY at open, multiplexed SEND/RESULT lanes (at most 16 outstanding),
//! DELIVER/ACK pull, DRAINED, and the keepalive Ping cadence. All protocol
//! framing is the SDK's `licoarc::transport` codec; the socket only moves
//! bounded binary frames.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

use licoarc::provider::{SignatureProvider, fixed_provider};
use licoarc::transport::{
    ClientFrame, FailureClass, MAX_OUTSTANDING_SENDS, MAX_PACKET_BYTES, StationFrame,
};

use super::credentials::Credentials;
use super::token::HandleToken;

/// The required WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "licoarc.mailbox.v1";
const HELLO_CONTEXT: &[u8] = b"licoarc-mailbox-hello-v1";
const KEEPALIVE_MS: u64 = 30_000;

/// Why a station exchange failed.
#[derive(Debug)]
pub enum StationError {
    /// The Station rejected the send durably.
    Rejected { failure: FailureClass },
    /// The Station reported a transient failure.
    Transient {
        failure: FailureClass,
        retry_after: Option<u32>,
    },
    /// The connection was lost before RESULT; the send may or may not have
    /// been stored.
    Ambiguous,
    /// Another connection owns the mailbox (close 4000).
    Superseded,
    /// The mailbox was revoked (close 4001).
    Revoked,
    /// The device key differs from the bound key (close 4003).
    DeviceMismatch,
    /// The upgrade was refused (401/403 or another non-101 response).
    Refused,
    /// A frame, close, or response violated the mailbox contract.
    Protocol,
    /// Underlying transport failure.
    Io(std::io::Error),
}

impl std::fmt::Display for StationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { failure } => write!(formatter, "station rejected: {failure:?}"),
            Self::Transient { failure, .. } => write!(formatter, "station transient: {failure:?}"),
            Self::Ambiguous => write!(formatter, "send outcome ambiguous"),
            Self::Superseded => write!(formatter, "mailbox owned by another connection"),
            Self::Revoked => write!(formatter, "mailbox revoked"),
            Self::DeviceMismatch => write!(formatter, "device key differs from bound key"),
            Self::Refused => write!(formatter, "station refused the upgrade"),
            Self::Protocol => write!(formatter, "station violated the mailbox contract"),
            Self::Io(cause) => write!(formatter, "transport I/O: {cause}"),
        }
    }
}

impl std::error::Error for StationError {}

impl Clone for StationError {
    fn clone(&self) -> Self {
        match self {
            Self::Rejected { failure } => Self::Rejected { failure: *failure },
            Self::Transient {
                failure,
                retry_after,
            } => Self::Transient {
                failure: *failure,
                retry_after: *retry_after,
            },
            Self::Ambiguous => Self::Ambiguous,
            Self::Superseded => Self::Superseded,
            Self::Revoked => Self::Revoked,
            Self::DeviceMismatch => Self::DeviceMismatch,
            Self::Refused => Self::Refused,
            Self::Protocol => Self::Protocol,
            Self::Io(cause) => Self::Io(std::io::Error::new(cause.kind(), cause.to_string())),
        }
    }
}

/// One inbound station event beyond RESULT.
#[derive(Debug)]
pub enum Event {
    /// A stored packet delivery.
    Deliver {
        sequence: u64,
        handle: HandleToken,
        packet: Vec<u8>,
    },
    /// The mailbox reports every packet delivered.
    Drained,
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// One live mailbox connection.
pub struct MailboxClient {
    outbound: mpsc::UnboundedSender<Message>,
    events: mpsc::UnboundedReceiver<Result<Event, StationError>>,
    pending: Arc<PendingTable>,
    slots: Arc<Semaphore>,
    next_request: std::sync::atomic::AtomicU32,
    mailbox_id: [u8; 16],
    runtime_flavor: tokio::runtime::RuntimeFlavor,
}

type PendingTable = std::sync::Mutex<HashMap<u32, oneshot::Sender<Result<(), StationError>>>>;

impl MailboxClient {
    /// Opens the TLS 1.3 WebSocket, completes CHALLENGE → HELLO → READY,
    /// and returns the live client. The mailbox id is exposed through
    /// [`Self::mailbox_id`]; the caller persists it (the CLI's `enroll`
    /// writes it back to the credentials file). The keepalive cadence is
    /// the protocol's 30 seconds.
    ///
    /// The connection's I/O task is spawned on the calling runtime, which
    /// must be multi-threaded and outlive the client: on a current-thread
    /// runtime the task only advances while `block_on` runs, so blocking
    /// adapters such as [`crate::SubmitCarrier`] (whose private runtime
    /// awaits RESULTs) would deadlock. [`Self::runtime_flavor`] reports
    /// the flavor recorded here.
    pub async fn connect(
        credentials: &Credentials,
        extra_roots: &[PathBuf],
    ) -> Result<Self, StationError> {
        Self::connect_with(
            credentials,
            extra_roots,
            Duration::from_millis(KEEPALIVE_MS),
        )
        .await
    }

    /// [`Self::connect`] with a caller-chosen keepalive cadence. The 30 s
    /// default is the protocol cadence; a different value is a caller
    /// (test) concern, never a Station negotiation. The same
    /// multi-threaded runtime requirement as [`Self::connect`] applies.
    pub async fn connect_with(
        credentials: &Credentials,
        extra_roots: &[PathBuf],
        keepalive: Duration,
    ) -> Result<Self, StationError> {
        let url = url::Url::parse(credentials.station()).map_err(|_| StationError::Protocol)?;
        match url.scheme() {
            "https" | "wss" => {}
            _ => return Err(StationError::Protocol),
        }
        let host = url.host_str().ok_or(StationError::Protocol)?.to_string();
        let port = url.port_or_known_default().ok_or(StationError::Protocol)?;
        let connector = tls_connector(extra_roots)?;
        let socket = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(StationError::Io)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| StationError::Protocol)?;
        let tls = connector
            .connect(server_name, socket)
            .await
            .map_err(StationError::Io)?;

        let request = upgrade_request(&url, credentials.token())?;
        let (mut ws, response) = tokio_tungstenite::client_async(request, tls)
            .await
            .map_err(|error| match error {
                tokio_tungstenite::tungstenite::Error::Http(response) => {
                    match response.status().as_u16() {
                        401 | 403 => StationError::Refused,
                        _ => StationError::Io(std::io::Error::other(format!(
                            "http {}",
                            response.status()
                        ))),
                    }
                }
                tokio_tungstenite::tungstenite::Error::Protocol(_) => StationError::Protocol,
                _ => StationError::Io(std::io::Error::other(format!("{error}"))),
            })?;
        let protocol = response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok());
        if protocol != Some(SUBPROTOCOL) {
            return Err(StationError::Protocol);
        }

        let challenge = match read_frame(&mut ws).await? {
            StationFrame::Challenge { nonce } => nonce,
            _ => return Err(StationError::Protocol),
        };
        let public = fixed_provider().ed25519_public(credentials.device_secret());
        let mut message = Vec::with_capacity(HELLO_CONTEXT.len() + challenge.len());
        message.extend_from_slice(HELLO_CONTEXT);
        message.extend_from_slice(&challenge);
        let signature = fixed_provider().ed25519_sign(credentials.device_secret(), &message);
        ws.send(Message::Binary(
            ClientFrame::Hello {
                device_key: public,
                signature,
            }
            .encode()
            .map_err(|_| StationError::Protocol)?
            .into(),
        ))
        .await
        .map_err(|error| StationError::Io(std::io::Error::other(format!("{error}"))))?;
        let mailbox_id = match read_frame(&mut ws).await? {
            StationFrame::Ready { mailbox_id } => mailbox_id,
            _ => return Err(StationError::Protocol),
        };
        if let Some(bound) = credentials.mailbox_id()
            && bound != mailbox_id
        {
            return Err(StationError::Protocol);
        }

        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::unbounded_channel();
        let pending: Arc<PendingTable> = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let io_pending = pending.clone();
        tokio::spawn(io_loop(ws, outbound_rx, events, io_pending, keepalive));

        Ok(Self {
            outbound,
            events: events_rx,
            pending,
            slots: Arc::new(Semaphore::new(MAX_OUTSTANDING_SENDS as usize)),
            next_request: std::sync::atomic::AtomicU32::new(1),
            mailbox_id,
            runtime_flavor: tokio::runtime::Handle::current().runtime_flavor(),
        })
    }

    /// One SEND, resolved by its RESULT. At most 16 outstanding; the caller
    /// awaits a slot, never an error. Connection loss before RESULT is
    /// `Ambiguous`.
    pub async fn send(&self, handle: HandleToken, packet: &[u8]) -> Result<(), StationError> {
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(StationError::Protocol);
        }
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| StationError::Ambiguous)?;
        let request_id = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % u32::MAX;
        let request_id = if request_id == 0 { 1 } else { request_id };
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| StationError::Protocol)?
            .insert(request_id, tx);
        let frame = ClientFrame::Send {
            request_id,
            handle: *handle.as_bytes(),
            packet: packet.to_vec(),
        }
        .encode()
        .map_err(|_| StationError::Protocol)?;
        let sent = self.outbound.send(Message::Binary(frame.into()));
        if sent.is_err() {
            self.pending
                .lock()
                .map_err(|_| StationError::Protocol)?
                .remove(&request_id);
            return Err(StationError::Ambiguous);
        }
        let outcome = rx.await;
        drop(permit);
        match outcome {
            Err(_) => Err(StationError::Ambiguous),
            Ok(result) => result,
        }
    }

    /// The mailbox identity learned at READY. Callers persist it through
    /// their own storage (`Credentials::bind_mailbox` for the CLI).
    #[must_use]
    pub const fn mailbox_id(&self) -> [u8; 16] {
        self.mailbox_id
    }

    /// Whether the connection's I/O task was spawned on a current-thread
    /// runtime. [`crate::SubmitCarrier`] refuses such clients; see
    /// [`Self::connect`].
    #[must_use]
    pub fn is_current_thread_runtime(&self) -> bool {
        matches!(
            self.runtime_flavor,
            tokio::runtime::RuntimeFlavor::CurrentThread
        )
    }

    /// The next station event: a delivery or DRAINED.
    pub async fn next(&mut self) -> Result<Event, StationError> {
        match self.events.recv().await {
            Some(Ok(event)) => Ok(event),
            Some(Err(error)) => Err(error),
            None => Err(StationError::Ambiguous),
        }
    }

    /// Acknowledges one delivery sequence.
    pub async fn ack(&self, sequence: u64) -> Result<(), StationError> {
        let frame = ClientFrame::Ack {
            delivery_sequence: sequence,
        }
        .encode()
        .map_err(|_| StationError::Protocol)?;
        self.outbound
            .send(Message::Binary(frame.into()))
            .map_err(|_| StationError::Ambiguous)
    }
}

async fn read_frame(ws: &mut Ws) -> Result<StationFrame, StationError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                return StationFrame::decode(&bytes).map_err(|_| StationError::Protocol);
            }
            Some(Ok(Message::Close(frame))) => return Err(close_error(frame)),
            Some(Ok(_)) => continue,
            _ => return Err(StationError::Ambiguous),
        }
    }
}

fn close_error(frame: Option<CloseFrame>) -> StationError {
    match frame.map(|frame| u16::from(frame.code)) {
        Some(4000) => StationError::Superseded,
        Some(4001) => StationError::Revoked,
        Some(4003) => StationError::DeviceMismatch,
        _ => StationError::Ambiguous,
    }
}

/// The single I/O owner: inbound frames to pending/events, outbound channel
/// to the socket, Ping cadence.
async fn io_loop(
    mut ws: Ws,
    mut outbound: mpsc::UnboundedReceiver<Message>,
    events: mpsc::UnboundedSender<Result<Event, StationError>>,
    pending: Arc<PendingTable>,
    keepalive: Duration,
) {
    let mut keepalive = tokio::time::interval(keepalive);
    let mut awaiting_pong = false;
    let fatal = loop {
        tokio::select! {
            message = ws.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => match StationFrame::decode(&bytes) {
                        Ok(StationFrame::Result { request_id, outcome, failure_class, retry_after_ms }) => {
                            let slot = pending.lock().ok().and_then(|mut table| table.remove(&request_id));
                            let result = match outcome {
                                licoarc::transport::TransportOutcome::Accepted => Ok(()),
                                licoarc::transport::TransportOutcome::Rejected => Err(StationError::Rejected {
                                    failure: failure_class.unwrap_or(FailureClass::InvalidRequest),
                                }),
                                _ => Err(StationError::Transient {
                                    failure: failure_class.unwrap_or(FailureClass::InternalUnavailable),
                                    retry_after: retry_after_ms,
                                }),
                            };
                            if let Some(slot) = slot {
                                let _ = slot.send(result);
                            }
                        }
                        Ok(StationFrame::Deliver { delivery_sequence, handle, packet }) => {
                            let _ = events.send(Ok(Event::Deliver {
                                sequence: delivery_sequence,
                                handle: HandleToken::from_bytes(handle),
                                packet,
                            }));
                        }
                        Ok(StationFrame::Drained) => {
                            let _ = events.send(Ok(Event::Drained));
                        }
                        _ => break StationError::Protocol,
                    },
                    Some(Ok(Message::Close(frame))) => break close_error(frame),
                    Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                    Some(Ok(_)) => continue,
                    _ => break StationError::Ambiguous,
                }
            }
            outbound_message = outbound.recv() => {
                match outbound_message {
                    Some(message) => {
                        if ws.send(message).await.is_err() {
                            break StationError::Ambiguous;
                        }
                    }
                    None => {
                        // The last outbound sender went away: the client is
                        // dropped. Send a graceful Close (1000) and flush so
                        // the station drops the socket now instead of
                        // holding a stale hibernated one.
                        let _ = ws.close(None).await;
                        break StationError::Ambiguous;
                    }
                }
            }
            _ = keepalive.tick() => {
                if awaiting_pong {
                    break StationError::Ambiguous;
                }
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break StationError::Ambiguous;
                }
                awaiting_pong = true;
            }
        }
    };
    if let Ok(mut table) = pending.lock() {
        for (_, slot) in table.drain() {
            let _ = slot.send(Err(fatal.clone()));
        }
    }
    let _ = events.send(Err(fatal));
}

fn upgrade_request(
    url: &url::Url,
    token: &str,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, StationError> {
    let host = url.host_str().ok_or(StationError::Protocol)?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => match url.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        },
    };
    let mut ws_url = url.clone();
    // The caller already refused every scheme except https/wss, so the
    // upgrade always rides TLS — there is no plaintext-Bearer form to emit.
    ws_url
        .set_scheme("wss")
        .map_err(|_| StationError::Protocol)?;
    ws_url.set_path("/v1/mailbox");
    tokio_tungstenite::tungstenite::http::Request::builder()
        .method("GET")
        .uri(ws_url.as_str())
        .header("host", authority)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", generate_key())
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", SUBPROTOCOL)
        .header("authorization", format!("Bearer {token}"))
        .body(())
        .map_err(|_| StationError::Protocol)
}

/// TLS 1.3 only: system roots plus extra PEM roots when configured.
fn tls_connector(extra_roots: &[PathBuf]) -> Result<TlsConnector, StationError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_roots {
        let pem = std::fs::read(path).map_err(StationError::Io)?;
        let mut added = 0_u32;
        for cert in CertificateDer::pem_slice_iter(&pem[..]).flatten() {
            roots.add(cert).map_err(|_| StationError::Protocol)?;
            added += 1;
        }
        if added == 0 {
            return Err(StationError::Io(std::io::Error::other(format!(
                "{}: no certificates",
                path.display()
            ))));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| StationError::Protocol)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
