//! Mailbox-transport integration tests against an in-process Station.
//!
//! The fake Station speaks the real wire: TLS-terminated WebSocket, the
//! `licoarc.mailbox.v1` subprotocol, and the SDK's own CBOR codecs, so every
//! frame the client sees is exactly what a conforming Station produces.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use licoarc::transport::{ClientFrame, StationFrame};
use licoarc_client::{
    Credentials, Event, HandleToken, LoopExit, MailboxClient, PacketSink, ReconnectPolicy, Spool,
    StationError, SubmitCarrier, Verdict, receive_loop,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::Request;

// ---------------------------------------------------------------------------
// Fixture: a private temp dir + a self-signed Station certificate
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

fn temp_dir() -> TempDir {
    let path = std::env::temp_dir()
        .join(format!("licoarc-mailbox-test-{}", std::process::id()))
        .join(format!("{}", rand_u64()));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rand_u64() -> u64 {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    u64::from_be_bytes(bytes)
}

struct Station {
    origin: String,
    ca_pem: PathBuf,
    sent_acks: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    _control: mpsc::UnboundedSender<Behaviour>,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
enum Behaviour {
    Normal,
    Reject,
    Transient,
    DropOnSend,
    Dead,      // stops polling after READY — Pings never get Pongs
    Push(u64), // deliver N packets then DRAINED
    SupersededOnOpen,
    RevokedOnOpen,
}

fn make_ca() -> (rustls::ServerConfig, String) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            key.serialize_der().try_into().unwrap(),
        )
        .expect("server config");
    (config, cert.pem())
}

async fn serve(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    echoes_protocol: bool,
    mut behaviour: Behaviour,
    mut rx: mpsc::UnboundedReceiver<Behaviour>,
    acks: Arc<AtomicU64>,
    conns: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let Ok((socket, _)) = accept else { continue };
                let config = config.clone();
                let acks = acks.clone();
                conns.fetch_add(1, Ordering::SeqCst);
                let b = behaviour.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(socket, config, echoes_protocol, b, acks).await;
                });
            }
            next = rx.recv() => {
                match next {
                    Some(b) => behaviour = b,
                    None => break,
                }
            }
        }
    }
}

#[allow(clippy::result_large_err)]
async fn handle_conn(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    echoes_protocol: bool,
    behaviour: Behaviour,
    acks: Arc<AtomicU64>,
) -> Result<(), ()> {
    let tls = tokio_rustls::TlsAcceptor::from(config)
        .accept(socket)
        .await
        .map_err(|_| ())?;
    let mut ws = tokio_tungstenite::accept_hdr_async(
        tls,
        |_req: &Request,
         mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if echoes_protocol {
                response.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    "licoarc.mailbox.v1".parse().unwrap(),
                );
            }
            Ok(response)
        },
    )
    .await
    .map_err(|_| ())?;

    // CHALLENGE → HELLO → READY
    ws.send(Message::Binary(
        StationFrame::Challenge { nonce: [7_u8; 32] }
            .encode()
            .unwrap()
            .into(),
    ))
    .await
    .map_err(|_| ())?;
    let hello = match ws.next().await {
        Some(Ok(Message::Binary(bytes))) => ClientFrame::decode(&bytes).map_err(|_| ())?,
        _ => return Err(()),
    };
    let ClientFrame::Hello { device_key, .. } = hello else {
        return Err(());
    };
    let mut mailbox = [0_u8; 16];
    mailbox.copy_from_slice(&device_key[..16]);
    match behaviour {
        Behaviour::SupersededOnOpen => {
            ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(
                    4000_u16,
                ),
                reason: "superseded".into(),
            }))
            .await
            .map_err(|_| ())?;
            return Ok(());
        }
        Behaviour::Dead => {
            ws.send(Message::Binary(
                StationFrame::Ready {
                    mailbox_id: mailbox,
                }
                .encode()
                .unwrap()
                .into(),
            ))
            .await
            .map_err(|_| ())?;
            std::future::pending::<()>().await;
        }
        Behaviour::RevokedOnOpen => {
            ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(
                    4001_u16,
                ),
                reason: "revoked".into(),
            }))
            .await
            .map_err(|_| ())?;
            return Ok(());
        }
        _ => {}
    }
    ws.send(Message::Binary(
        StationFrame::Ready {
            mailbox_id: mailbox,
        }
        .encode()
        .unwrap()
        .into(),
    ))
    .await
    .map_err(|_| ())?;

    if let Behaviour::Push(count) = behaviour {
        let mut handle = [0_u8; 32];
        handle[..16].copy_from_slice(&mailbox);
        handle[16] = 0xab;
        for sequence in 1..=count {
            let frame = StationFrame::Deliver {
                delivery_sequence: sequence,
                handle,
                packet: format!("delivered-{sequence}").into_bytes(),
            };
            ws.send(Message::Binary(frame.encode().unwrap().into()))
                .await
                .map_err(|_| ())?;
        }
        ws.send(Message::Binary(
            StationFrame::Drained.encode().unwrap().into(),
        ))
        .await
        .map_err(|_| ())?;
    }

    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                match ClientFrame::decode(&bytes).map_err(|_| ())? {
                    ClientFrame::Send {
                        request_id, packet, ..
                    } => {
                        let frame = match behaviour {
                            Behaviour::Reject => StationFrame::Result {
                                request_id,
                                outcome: licoarc::transport::TransportOutcome::Rejected,
                                failure_class: Some(licoarc::transport::FailureClass::MailboxFull),
                                retry_after_ms: None,
                            },
                            Behaviour::Transient => StationFrame::Result {
                                request_id,
                                outcome: licoarc::transport::TransportOutcome::Transient,
                                failure_class: Some(
                                    licoarc::transport::FailureClass::InternalUnavailable,
                                ),
                                retry_after_ms: Some(1_000),
                            },
                            Behaviour::DropOnSend => return Ok(()),
                            _ => StationFrame::Result {
                                request_id,
                                outcome: licoarc::transport::TransportOutcome::Accepted,
                                failure_class: None,
                                retry_after_ms: None,
                            },
                        };
                        let _ = packet;
                        ws.send(Message::Binary(frame.encode().unwrap().into()))
                            .await
                            .map_err(|_| ())?;
                    }
                    ClientFrame::Ack { .. } => {
                        acks.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => return Err(()),
                }
            }
            Some(Ok(Message::Ping(data))) => {
                ws.send(Message::Pong(data)).await.map_err(|_| ())?;
            }
            Some(Ok(Message::Close(_))) | None => return Ok(()),
            Some(Ok(_)) => return Err(()),
            Some(Err(_)) => return Err(()),
        }
    }
}

async fn start_station(behaviour: Behaviour, echoes_protocol: bool) -> (Station, TempDir) {
    let (config, pem) = make_ca();
    let dir = temp_dir();
    let ca_path = dir.0.join("ca.pem");
    std::fs::write(&ca_path, pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (control, rx) = mpsc::unbounded_channel();
    let acks = Arc::new(AtomicU64::new(0));
    let conns = Arc::new(AtomicU64::new(0));
    let task = tokio::spawn(serve(
        listener,
        Arc::new(config),
        echoes_protocol,
        behaviour,
        rx,
        acks.clone(),
        conns.clone(),
    ));
    (
        Station {
            origin: format!("wss://localhost:{}", addr.port()),
            ca_pem: ca_path,
            sent_acks: acks,
            connections: conns,
            _control: control,
            _task: task,
        },
        dir,
    )
}

fn mint_credentials(station: &Station, dir: &TempDir) -> Credentials {
    let path = dir.0.join("credentials.json");
    Credentials::mint(station.origin.clone(), "btm1.test".to_owned(), path).unwrap()
}

fn roots(station: &Station) -> Vec<PathBuf> {
    vec![station.ca_pem.clone()]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_binds_and_persists_the_mailbox_id() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let mut credentials = mint_credentials(&station, &dir);
    let client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .expect("connect");
    let mailbox = client.mailbox_id();
    credentials.bind_mailbox(mailbox).unwrap();
    drop(client);
    // The file persisted it: a fresh load sees the same id.
    let reloaded = Credentials::load(&dir.0.join("credentials.json")).unwrap();
    assert_eq!(reloaded.mailbox_id(), Some(mailbox));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_accepted_rejected_and_transient_map_to_their_outcomes() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let credentials = mint_credentials(&station, &dir);
    let client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    let handle = HandleToken::mint(client.mailbox_id()).unwrap();
    client.send(handle, b"ok").await.expect("accepted");

    let (station2, dir2) = start_station(Behaviour::Reject, true).await;
    let credentials2 = mint_credentials(&station2, &dir2);
    let client2 = MailboxClient::connect(&credentials2, &roots(&station2))
        .await
        .unwrap();
    let handle2 = HandleToken::mint(client2.mailbox_id()).unwrap();
    match client2.send(handle2, b"x").await {
        Err(StationError::Rejected { .. }) => {}
        other => panic!("expected rejected, got {other:?}"),
    }
    let (station3, dir3) = start_station(Behaviour::Transient, true).await;
    let credentials3 = mint_credentials(&station3, &dir3);
    let client3 = MailboxClient::connect(&credentials3, &roots(&station3))
        .await
        .unwrap();
    let handle3 = HandleToken::mint(client3.mailbox_id()).unwrap();
    match client3.send(handle3, b"x").await {
        Err(StationError::Transient { retry_after, .. }) => assert_eq!(retry_after, Some(1_000)),
        other => panic!("expected transient, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_loss_before_result_is_ambiguous() {
    let (station, dir) = start_station(Behaviour::DropOnSend, true).await;
    let credentials = mint_credentials(&station, &dir);
    let client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    let handle = HandleToken::mint(client.mailbox_id()).unwrap();
    match client.send(handle, b"x").await {
        Err(StationError::Ambiguous) => {}
        other => panic!("expected ambiguous, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixteen_outstanding_sends_share_one_connection() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let credentials = mint_credentials(&station, &dir);
    let client = Arc::new(
        MailboxClient::connect(&credentials, &roots(&station))
            .await
            .unwrap(),
    );
    let handle = HandleToken::mint(client.mailbox_id()).unwrap();
    let mut tasks = Vec::new();
    for index in 0..40_u32 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            client
                .send(handle, format!("packet-{index}").as_bytes())
                .await
        }));
    }
    for task in tasks {
        task.await.unwrap().expect("every send resolves");
    }
    assert_eq!(station.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deliveries_reach_the_sink_and_ack_in_order() {
    let (station, dir) = start_station(Behaviour::Push(3), true).await;
    let credentials = mint_credentials(&station, &dir);
    let mut client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    let mut seen = Vec::new();
    while let Event::Deliver {
        sequence, packet, ..
    } = client.next().await.expect("event")
    {
        seen.push((sequence, packet.clone()));
        client.ack(sequence).await.expect("ack");
    }
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, 1);
    assert_eq!(seen[1].0, 2);
    assert_eq!(seen[2].0, 3);
    for _ in 0..50 {
        if station.sent_acks.load(Ordering::SeqCst) == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(station.sent_acks.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spool_stores_then_the_file_exists_before_ack() {
    let (station, dir) = start_station(Behaviour::Push(2), true).await;
    let credentials = mint_credentials(&station, &dir);
    let mut client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    let mut spool = Spool::open(&dir.0.join("spool")).unwrap();
    let mut stored = 0_u64;
    while let Event::Deliver {
        sequence,
        handle,
        packet,
    } = client.next().await.expect("event")
    {
        assert_eq!(spool.accept(sequence, handle, &packet), Verdict::Done);
        let found = spool.stored(handle).unwrap();
        assert!(
            found.len() == (stored + 1) as usize,
            "expected {} files, found {found:?}",
            stored + 1
        );
        stored += 1;
        client.ack(sequence).await.expect("ack");
    }
    assert_eq!(stored, 2);
    for _ in 0..50 {
        if station.sent_acks.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(station.sent_acks.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_pong_kills_the_lane() {
    // A shrunken cadence exercises the same missing-Pong path.
    let (station, dir) = start_station(Behaviour::Dead, true).await;
    let credentials = mint_credentials(&station, &dir);
    let mut client =
        MailboxClient::connect_with(&credentials, &roots(&station), Duration::from_millis(100))
            .await
            .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), client.next()).await;
    match outcome {
        Ok(Err(StationError::Ambiguous)) => {}
        other => panic!("expected ambiguous from missing-pong loss, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_handshake_failure_is_retryable_io() {
    // A plaintext listener: the ClientHello gets bytes back it cannot parse
    // as TLS, so the handshake fails — retryable transport failure, not a
    // terminal refusal. (TLS 1.2-only servers refuse the handshake the same
    // way at the protocol layer.)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = socket.write_all(b"not tls").await;
        }
    });
    let station = Station {
        origin: format!("wss://127.0.0.1:{}", addr.port()),
        ca_pem: dir_path_buf(),
        sent_acks: Arc::new(AtomicU64::new(0)),
        connections: Arc::new(AtomicU64::new(0)),
        _control: mpsc::unbounded_channel().0,
        _task: tokio::spawn(async {}),
    };
    let dir = temp_dir();
    let credentials = mint_credentials(&station, &dir);
    match MailboxClient::connect(&credentials, &roots(&station)).await {
        Err(StationError::Io(_)) => {}
        Err(error) => panic!("expected Io on a TLS handshake failure, got {error}"),
        Ok(_) => panic!("expected Io on a TLS handshake failure, got connected"),
    }
}

fn dir_path_buf() -> PathBuf {
    std::env::temp_dir().join("licoarc-mailbox-test-noca.pem")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_subprotocol_is_refused() {
    let (station, dir) = start_station(Behaviour::Normal, false).await;
    let credentials = mint_credentials(&station, &dir);
    match MailboxClient::connect(&credentials, &roots(&station)).await {
        Err(StationError::Protocol) => {}
        Err(error) => panic!("expected Protocol without subprotocol echo, got {error}"),
        Ok(_) => panic!("expected Protocol without subprotocol echo, got connected"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_and_revoked_are_terminal() {
    for (behaviour, expected) in [
        (Behaviour::SupersededOnOpen, "superseded"),
        (Behaviour::RevokedOnOpen, "revoked"),
    ] {
        let (station, dir) = start_station(behaviour, true).await;
        let credentials = mint_credentials(&station, &dir);
        let outcome = MailboxClient::connect(&credentials, &roots(&station)).await;
        match (expected, outcome) {
            ("superseded", Err(StationError::Superseded)) => {}
            ("revoked", Err(StationError::Revoked)) => {}
            (_, Err(error)) => panic!("expected {expected}, got {error}"),
            (_, Ok(_)) => panic!("expected {expected}, got connected"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unacked_delivery_is_redelivered_on_reconnect() {
    let (station, dir) = start_station(Behaviour::Push(1), true).await;
    let credentials = mint_credentials(&station, &dir);
    // First connection sees the delivery and dies without acking.
    {
        let mut client = MailboxClient::connect(&credentials, &roots(&station))
            .await
            .unwrap();
        match client.next().await.expect("event") {
            Event::Deliver { packet, .. } => assert_eq!(packet, b"delivered-1"),
            other => panic!("expected deliver, got {other:?}"),
        }
    }
    // The Station never saw an ACK, so the packet is redelivered.
    let mut client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    match client.next().await.expect("event") {
        Event::Deliver {
            sequence, packet, ..
        } => {
            assert_eq!(packet, b"delivered-1");
            client.ack(sequence).await.expect("ack");
        }
        other => panic!("expected deliver, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_loop_stops_on_terminal_errors_without_reconnecting() {
    use licoarc_client::runtime::LoopExit;
    use licoarc_client::runtime::receive_loop;
    struct Never;
    impl PacketSink for Never {
        fn accept(&mut self, _sequence: u64, _handle: HandleToken, _packet: &[u8]) -> Verdict {
            Verdict::Done
        }
    }
    for (behaviour, expect) in [
        (Behaviour::SupersededOnOpen, "superseded"),
        (Behaviour::RevokedOnOpen, "revoked"),
    ] {
        let (station, dir) = start_station(behaviour, true).await;
        let credentials = mint_credentials(&station, &dir);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let exit = receive_loop(
            &credentials,
            &roots(&station),
            &mut Never,
            rx,
            ReconnectPolicy::default(),
        )
        .await;
        match (expect, exit) {
            ("superseded", LoopExit::Failed(StationError::Superseded)) => {}
            ("revoked", LoopExit::Failed(StationError::Revoked)) => {}
            (want, other) => panic!("expected {want} terminal, got {other:?}"),
        }
        // Exactly one connection attempt: the terminal error never retries.
        assert_eq!(station.connections.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redelivery_overwrites_its_spool_file() {
    let (_station, dir) = start_station(Behaviour::Normal, true).await;
    let mut spool = Spool::open(&dir.0.join("spool")).unwrap();
    let handle = HandleToken::mint([7_u8; 16]).unwrap();
    for _ in 0..2 {
        assert_eq!(spool.accept(5, handle, b"same"), Verdict::Done);
    }
    let files = spool.stored(handle).unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].1.ends_with("0000000000000005.packet"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_503_upgrade_is_retried_by_receive_loop() {
    let dir = temp_dir();
    struct Never;
    impl PacketSink for Never {
        fn accept(&mut self, _sequence: u64, _handle: HandleToken, _packet: &[u8]) -> Verdict {
            Verdict::Done
        }
    }
    // A raw responder that always answers the upgrade with HTTP 503.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let hits2 = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            hits2.fetch_add(1, Ordering::SeqCst);
            let mut request = vec![0_u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = socket.read(&mut request).await;
            use tokio::io::AsyncWriteExt;
            let _ = socket
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let credentials = Credentials::mint(
        format!("wss://127.0.0.1:{port}"),
        "btm1.test".to_owned(),
        dir.0.join("creds2.json"),
    )
    .unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let mut never = Never;
    let probe = tokio::spawn(async move {
        receive_loop(
            &credentials,
            &[],
            &mut never,
            rx,
            ReconnectPolicy::default(),
        )
        .await
    });
    // The loop retries indefinitely; several attempts should accumulate.
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert!(
        hits.load(Ordering::SeqCst) > 1,
        "expected retries, got {}",
        hits.load(Ordering::SeqCst)
    );
    assert!(!probe.is_finished());
    probe.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_observed_while_connected_and_idle() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let credentials = mint_credentials(&station, &dir);
    let (tx, rx) = tokio::sync::watch::channel(false);
    struct Never;
    impl PacketSink for Never {
        fn accept(&mut self, _sequence: u64, _handle: HandleToken, _packet: &[u8]) -> Verdict {
            Verdict::Done
        }
    }
    let mut never = Never;
    let roots = roots(&station);
    let task = tokio::spawn(async move {
        receive_loop(
            &credentials,
            &roots,
            &mut never,
            rx,
            ReconnectPolicy::default(),
        )
        .await
    });
    // Let the connection establish and go idle, then stop.
    tokio::time::sleep(Duration::from_millis(500)).await;
    tx.send(true).unwrap();
    match tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
    {
        Ok(LoopExit::Stopped) => {}
        other => panic!("expected prompt Stopped, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn submit_carrier_refuses_a_current_thread_runtime() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let credentials = mint_credentials(&station, &dir);
    let client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    assert!(client.is_current_thread_runtime());
    match SubmitCarrier::new(Arc::new(client), HandleToken::mint([0_u8; 16]).unwrap()) {
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::Unsupported),
        Ok(_) => panic!("expected Unsupported on a current-thread runtime"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_carrier_accepts_a_multi_thread_runtime() {
    let (station, dir) = start_station(Behaviour::Normal, true).await;
    let credentials = mint_credentials(&station, &dir);
    let client = MailboxClient::connect(&credentials, &roots(&station))
        .await
        .unwrap();
    assert!(!client.is_current_thread_runtime());
    SubmitCarrier::new(Arc::new(client), HandleToken::mint([0_u8; 16]).unwrap()).unwrap();
}
