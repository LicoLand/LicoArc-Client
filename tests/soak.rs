//! Soak validation: reconnect, Station restart and backlog catch-up over a
//! stateful local Station that speaks the real wire.
//!
//! The fixture Station is not a canned script: it owns a durable mailbox —
//! TLS-terminated WebSocket, the `licoarc.mailbox.v1` subprotocol, the SDK's
//! own CBOR codecs, stored rows kept until ACK, replay of every unacknowledged
//! row on reconnect, and the 16-unACKed-DELIVER window the spec fixes
//! (`docs/protocols/mailbox-transport-v1.md` in LicoArc). What it injects is
//! the environment around that contract: mid-backlog connection loss, a
//! Station restart with real listener downtime, and a large pre-stored
//! backlog.
//!
//! The assertions are the durable properties the contract owes: nothing
//! stored is ever lost, nothing delivered takes effect twice, and the
//! reconnect cadence stays inside the configured backoff.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use licoarc::transport::{ClientFrame, StationFrame};
use licoarc_client::{
    Credentials, HandleToken, LoopExit, PacketSink, ReconnectPolicy, Spool, Verdict, receive_loop,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

/// The spec's window: at most 16 un-ACKed DELIVERs per connection.
const DELIVERY_WINDOW: usize = 16;

// ---------------------------------------------------------------------------
// Fixture: a private temp dir + a self-signed Station certificate
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

fn temp_dir() -> TempDir {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    let path = std::env::temp_dir()
        .join(format!("licoarc-soak-test-{}", std::process::id()))
        .join(format!("{}", u64::from_be_bytes(bytes)));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

// ---------------------------------------------------------------------------
// The stateful Station: one durable mailbox, spec-ordered replay
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Row {
    handle: [u8; 32],
    packet: Vec<u8>,
}

/// What one accepted connection does before it reaches the mailbox lane.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    /// The full mailbox contract.
    Serve,
    /// TCP is accepted and dropped immediately — a Station that is up but
    /// never useful, so every attempt is timestamped and fails fast.
    Drop,
}

/// The mailbox the Station owns across connections and restarts.
struct Store {
    /// Stored rows by delivery sequence. A row leaves only on ACK, so an
    /// unacknowledged reconnect replays it with the same sequence.
    rows: Mutex<BTreeMap<u64, Row>>,
    next_sequence: AtomicU64,
    /// Rows actually deleted by an ACK — every row that ever left storage.
    acked: AtomicU64,
    /// Every DELIVER frame ever sent, including replays. A value above the
    /// stored total proves at least one row was delivered twice.
    delivered: AtomicU64,
    /// Every accepted TCP connection, for the backoff measurement.
    accepts: Mutex<Vec<Instant>>,
    /// Connections accepted and dropped under [`Mode::Drop`]. A mode change
    /// must wait for the drop itself, not the accept record.
    dropped: AtomicU64,
    /// Live connections over the run, so reconnects are observable.
    conns: AtomicU64,
    /// Wakes the active delivery lane when new rows arrive.
    changed: Notify,
    /// Holds ACK processing at a chosen row until the driver cuts the lane.
    pause_after_ack: AtomicU64,
    paused: Notify,
    /// When nonzero, the next client ACK is recorded in `held` and left
    /// unapplied: the row stays stored, so a reconnect replays a packet the
    /// client had already written to its spool.
    hold_next: AtomicU64,
    /// Delivery sequences whose first ACK was left unapplied.
    held: Mutex<BTreeSet<u64>>,
    /// Every delivery sequence the client ever ACKed — proof the packet was
    /// durably accepted before the row left storage.
    client_acked: Mutex<BTreeSet<u64>>,
    /// Sequences delivered again after the client had already ACKed them:
    /// replays that exercise the spool's same-sequence overwrite.
    replayed: Mutex<BTreeSet<u64>>,
    /// Bumped to kill every live connection; a lane dies when the epoch
    /// advances past the one it was spawned under.
    kill_epoch: watch::Sender<u64>,
}

impl Store {
    fn enqueue(&self, tag: &str, count: usize, handle: [u8; 32]) -> Vec<Vec<u8>> {
        let mut expected = Vec::with_capacity(count);
        let mut rows = self.rows.lock().unwrap();
        for index in 0..count {
            let packet = format!("{tag}-{index:05}").into_bytes();
            let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst) + 1;
            rows.insert(
                sequence,
                Row {
                    handle,
                    packet: packet.clone(),
                },
            );
            expected.push(packet);
        }
        drop(rows);
        self.changed.notify_one();
        expected
    }

    fn stored_count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}

enum Control {
    KillConnections,
    Restart { downtime: Duration },
}

struct Station {
    origin: String,
    ca_pem: PathBuf,
    store: Arc<Store>,
    mode: watch::Sender<Mode>,
    control: mpsc::UnboundedSender<Control>,
    _task: tokio::task::JoinHandle<()>,
}

/// Runs the accept loop, taking the listener down for `Restart` while the
/// mailbox state carries over — exactly like a Station process restart that
/// keeps its storage.
async fn serve(
    mut listener: TcpListener,
    addr: SocketAddr,
    config: Arc<rustls::ServerConfig>,
    store: Arc<Store>,
    mode: watch::Receiver<Mode>,
    mut control: mpsc::UnboundedReceiver<Control>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let Ok((socket, _)) = accept else { continue };
                store.accepts.lock().unwrap().push(Instant::now());
                store.conns.fetch_add(1, Ordering::SeqCst);
                if *mode.borrow() == Mode::Drop {
                    drop(socket);
                    store.dropped.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let config = config.clone();
                let store = store.clone();
                let kill = store.kill_epoch.subscribe();
                let epoch = *store.kill_epoch.borrow();
                tokio::spawn(async move {
                    let _ = connection(socket, config, store, kill, epoch).await;
                });
            }
            ctl = control.recv() => {
                match ctl {
                    Some(Control::KillConnections) => {
                        let next = *store.kill_epoch.borrow() + 1;
                        let _ = store.kill_epoch.send(next);
                    }
                    Some(Control::Restart { downtime }) => {
                        // A restart kills every lane first, then the listener.
                        let next = *store.kill_epoch.borrow() + 1;
                        let _ = store.kill_epoch.send(next);
                        drop(listener);
                        tokio::time::sleep(downtime).await;
                        // The port may briefly still be held; a real restart
                        // waits for it too.
                        let mut rebound = None;
                        for _ in 0..50 {
                            match TcpListener::bind(addr).await {
                                Ok(back) => {
                                    rebound = Some(back);
                                    break;
                                }
                                Err(_) => {
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                }
                            }
                        }
                        listener = rebound.expect("listener port did not come back");
                    }
                    None => break,
                }
            }
        }
    }
}

/// One connection's delivery lane: replay every stored row in sequence order
/// under the DELIVER window, delete a row only on ACK, and send DRAINED once
/// the mailbox is empty and nothing is in flight.
#[allow(clippy::result_large_err)]
async fn connection(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    store: Arc<Store>,
    mut kill: watch::Receiver<u64>,
    epoch: u64,
) -> Result<(), ()> {
    let tls = tokio_rustls::TlsAcceptor::from(config)
        .accept(socket)
        .await
        .map_err(|_| ())?;
    let mut ws =
        tokio_tungstenite::accept_hdr_async(tls, |_req: &Request, mut response: Response| {
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                "licoarc.mailbox.v1".parse().unwrap(),
            );
            Ok(response)
        })
        .await
        .map_err(|_| ())?;
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

    let mut inflight: BTreeSet<u64> = BTreeSet::new();
    let mut drained_sent = false;
    loop {
        // Fill the DELIVER window with the oldest rows not yet in flight on
        // this connection.
        while inflight.len() < DELIVERY_WINDOW {
            let next = {
                let rows = store.rows.lock().unwrap();
                rows.iter()
                    .find(|(sequence, _)| !inflight.contains(sequence))
                    .map(|(sequence, row)| (*sequence, row.clone()))
            };
            let Some((sequence, row)) = next else { break };
            let frame = StationFrame::Deliver {
                delivery_sequence: sequence,
                handle: row.handle,
                packet: row.packet,
            };
            ws.send(Message::Binary(frame.encode().unwrap().into()))
                .await
                .map_err(|_| ())?;
            inflight.insert(sequence);
            store.delivered.fetch_add(1, Ordering::SeqCst);
            if store.client_acked.lock().unwrap().contains(&sequence) {
                store.replayed.lock().unwrap().insert(sequence);
            }
            drained_sent = false;
        }
        let pause_after_ack = store.pause_after_ack.load(Ordering::SeqCst);
        if store.acked.load(Ordering::SeqCst) == pause_after_ack {
            assert!(!inflight.is_empty(), "pause must hold unacknowledged rows");
            store.pause_after_ack.store(u64::MAX, Ordering::SeqCst);
            store.paused.notify_one();
            let _ = kill.changed().await;
            return Ok(());
        }

        if !drained_sent && inflight.is_empty() && store.rows.lock().unwrap().is_empty() {
            ws.send(Message::Binary(
                StationFrame::Drained.encode().unwrap().into(),
            ))
            .await
            .map_err(|_| ())?;
            drained_sent = true;
        }
        tokio::select! {
            frame = ws.next() => {
                match frame {
                    Some(Ok(Message::Binary(bytes))) => {
                        match ClientFrame::decode(&bytes).map_err(|_| ())? {
                            ClientFrame::Ack { delivery_sequence } => {
                                store
                                    .client_acked
                                    .lock()
                                    .unwrap()
                                    .insert(delivery_sequence);
                                let already_held = store
                                    .held
                                    .lock()
                                    .unwrap()
                                    .contains(&delivery_sequence);
                                if already_held {
                                    // The replay's re-ACK: apply it now and
                                    // let the held row settle like any other.
                                    if store
                                        .rows
                                        .lock()
                                        .unwrap()
                                        .remove(&delivery_sequence)
                                        .is_some()
                                    {
                                        store.acked.fetch_add(1, Ordering::SeqCst);
                                    }
                                    inflight.remove(&delivery_sequence);
                                } else if store.hold_next.swap(0, Ordering::SeqCst) == 1 {
                                    // Leave this ACK unapplied: the client
                                    // already wrote the row, and keeping it
                                    // stored forces the reconnect to replay
                                    // it into the same spool entry.
                                    store
                                        .held
                                        .lock()
                                        .unwrap()
                                        .insert(delivery_sequence);
                                } else {
                                    // ACK deletes the row; an ACK for a row
                                    // already gone is a no-op, never a loss.
                                    if store
                                        .rows
                                        .lock()
                                        .unwrap()
                                        .remove(&delivery_sequence)
                                        .is_some()
                                    {
                                        store.acked.fetch_add(1, Ordering::SeqCst);
                                    }
                                    inflight.remove(&delivery_sequence);
                                }
                            }
                            ClientFrame::Send { request_id, .. } => {
                                let result = StationFrame::Result {
                                    request_id,
                                    outcome: licoarc::transport::TransportOutcome::Accepted,
                                    failure_class: None,
                                    retry_after_ms: None,
                                };
                                ws.send(Message::Binary(result.encode().unwrap().into()))
                                    .await
                                    .map_err(|_| ())?;
                            }
                            _ => return Err(()),
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        ws.send(Message::Pong(data)).await.map_err(|_| ())?;
                    }
                    _ => return Ok(()),
                }
            }
            _ = store.changed.notified() => {}
            _ = kill.changed() => {
                if *kill.borrow() > epoch {
                    return Ok(());
                }
            }
        }
    }
}

async fn start_station() -> (Station, TempDir) {
    let (config, pem) = make_ca();
    let dir = temp_dir();
    let ca_path = dir.0.join("ca.pem");
    std::fs::write(&ca_path, pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (control, rx) = mpsc::unbounded_channel();
    let (mode, mode_rx) = watch::channel(Mode::Serve);
    let (kill, _) = watch::channel(0_u64);
    let store = Arc::new(Store {
        rows: Mutex::new(BTreeMap::new()),
        next_sequence: AtomicU64::new(0),
        acked: AtomicU64::new(0),
        delivered: AtomicU64::new(0),
        accepts: Mutex::new(Vec::new()),
        dropped: AtomicU64::new(0),
        conns: AtomicU64::new(0),
        changed: Notify::new(),
        pause_after_ack: AtomicU64::new(u64::MAX),
        paused: Notify::new(),
        hold_next: AtomicU64::new(0),
        held: Mutex::new(BTreeSet::new()),
        client_acked: Mutex::new(BTreeSet::new()),
        replayed: Mutex::new(BTreeSet::new()),
        kill_epoch: kill,
    });
    let task = tokio::spawn(serve(
        listener,
        addr,
        Arc::new(config),
        store.clone(),
        mode_rx,
        rx,
    ));
    (
        Station {
            origin: format!("wss://localhost:{}", addr.port()),
            ca_pem: ca_path,
            store,
            mode,
            control,
            _task: task,
        },
        dir,
    )
}

/// A [`PacketSink`] that counts every sink decision on top of the durable
/// spool, so a redelivery is visible as an extra call whose effect — the same
/// sequence-named file — still lands exactly once.
struct Counted<S> {
    inner: S,
    accepts: u64,
    by_sequence: BTreeMap<u64, u64>,
}

impl<S: PacketSink> PacketSink for Counted<S> {
    fn accept(&mut self, sequence: u64, handle: HandleToken, packet: &[u8]) -> Verdict {
        self.accepts += 1;
        *self.by_sequence.entry(sequence).or_insert(0) += 1;
        self.inner.accept(sequence, handle, packet)
    }
}

/// Polls a counter until it reaches `target`, panicking after `budget`.
async fn wait_acked(store: &Store, target: u64, budget: Duration) {
    let deadline = Instant::now() + budget;
    while store.acked.load(Ordering::SeqCst) < target {
        assert!(
            Instant::now() < deadline,
            "acknowledgements stopped at {} below {target}",
            store.acked.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Polls until at least `count` TCP accepts have been observed.
async fn wait_accepts(store: &Store, count: usize, budget: Duration) {
    let deadline = Instant::now() + budget;
    while store.accepts.lock().unwrap().len() < count {
        assert!(Instant::now() < deadline, "attempts stalled below {count}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Polls until at least `count` accepts have been dropped by the fixture,
/// so a mode change cannot race a recorded-but-not-yet-dropped accept.
async fn wait_dropped(store: &Store, count: u64, budget: Duration) {
    let deadline = Instant::now() + budget;
    while store.dropped.load(Ordering::SeqCst) < count {
        assert!(
            Instant::now() < deadline,
            "dropped attempts stalled below {count}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// The soak
// ---------------------------------------------------------------------------

/// The full soak: a large pre-stored backlog, a mid-backlog disconnect with
/// unacknowledged rows in flight, and a Station restart during delivery.
/// The client's durable inbox must hold every packet exactly once at the
/// end, and the Station's storage must be empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backlog_survives_disconnect_restart_and_reconnect() {
    let (station, dir) = start_station().await;
    let handle = HandleToken::mint([0x5A; 16]).unwrap();
    let handle_bytes = *handle.as_bytes();

    // The backlog is stored before the client ever connects.
    let mut expected = station.store.enqueue("backlog", 200, handle_bytes);

    let credentials = Credentials::mint(
        station.origin.clone(),
        "btm1.test".to_owned(),
        dir.0.join("credentials.json"),
    )
    .unwrap();
    let roots = vec![station.ca_pem.clone()];
    let mut sink = Counted {
        inner: Spool::open(&dir.0.join("spool")).unwrap(),
        accepts: 0,
        by_sequence: BTreeMap::new(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let policy = ReconnectPolicy {
        initial: Duration::from_millis(30),
        multiplier: 2,
        cap: Duration::from_millis(200),
    };
    let budget = Duration::from_secs(30);

    let scenario = async {
        let store = &station.store;

        // Phase 1 — the pre-stored backlog drains under the DELIVER window.
        wait_acked(store, 200, budget).await;

        // Phase 2 — a large second backlog arrives; the lane is cut while
        // rows are unacknowledged in flight. They must be replayed with the
        // same sequences on reconnect. One identified ACK is held unapplied:
        // the client had already written that row, so its replay must land
        // in the same spool entry instead of being a first write.
        store.hold_next.store(1, Ordering::SeqCst);
        store.pause_after_ack.store(300, Ordering::SeqCst);
        expected.extend(store.enqueue("aftercut", 400, handle_bytes));
        tokio::time::timeout(budget, store.paused.notified())
            .await
            .expect("no rows in flight to cut");
        assert_eq!(
            store.held.lock().unwrap().len(),
            1,
            "one ACK must be held unapplied before the cut"
        );
        station.control.send(Control::KillConnections).unwrap();
        wait_acked(store, 600, budget).await;

        // Phase 3 — a Station restart during delivery: every lane dies, the
        // listener goes down for a real downtime, and the surviving rows are
        // replayed once it is back. A second ACK is held unapplied here too.
        store.hold_next.store(1, Ordering::SeqCst);
        store.pause_after_ack.store(620, Ordering::SeqCst);
        expected.extend(store.enqueue("restart", 100, handle_bytes));
        tokio::time::timeout(budget, store.paused.notified())
            .await
            .expect("no rows in flight before restart");
        assert_eq!(
            store.held.lock().unwrap().len(),
            2,
            "one more ACK must be held unapplied before the restart"
        );
        station
            .control
            .send(Control::Restart {
                downtime: Duration::from_millis(150),
            })
            .unwrap();
        wait_acked(store, 700, budget).await;

        // The Station's storage is empty only when every row was ACKed.
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.stored_count() != 0 {
            assert!(Instant::now() < deadline, "stored rows never settled");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        stop.send(true).unwrap();
    };

    let (exit, ()) = tokio::join!(
        receive_loop(&credentials, &roots, &mut sink, stop_rx, policy),
        scenario,
    );

    match exit {
        LoopExit::Stopped => {}
        LoopExit::Failed(error) => panic!("the lane failed: {error}"),
    }

    // Reconnects and replays really happened: at least three connections
    // (initial, post-disconnect, post-restart), and the Station re-sent rows
    // that were in flight when the cut landed.
    assert!(
        station.store.conns.load(Ordering::SeqCst) >= 3,
        "disconnect and restart must have forced new connections"
    );
    assert!(
        station.store.delivered.load(Ordering::SeqCst) > expected.len() as u64,
        "the cut rows must have been replayed, not only reconnected"
    );
    assert!(
        sink.accepts >= expected.len() as u64,
        "every delivery reached the sink at least once"
    );
    assert_eq!(
        station.store.acked.load(Ordering::SeqCst),
        expected.len() as u64,
        "each stored row was ACKed and deleted exactly once"
    );

    // Each interruption held one ACK unapplied, and each of those rows was
    // really redelivered after the client had durably written it: the sink
    // saw the same sequence again while the spool kept one file per
    // sequence — the replay landed in the same spool entry.
    let held = station.store.held.lock().unwrap().clone();
    assert_eq!(held.len(), 2, "each interruption must hold one ACK");
    let replayed = station.store.replayed.lock().unwrap().clone();
    for sequence in &held {
        assert!(
            replayed.contains(sequence),
            "held row {sequence} was never replayed"
        );
        assert!(
            sink.by_sequence.get(sequence).copied().unwrap_or(0) >= 2,
            "sequence {sequence} must reach the sink again after the replay"
        );
    }

    // No loss, no duplicate effect: the spool holds exactly one file per
    // delivery sequence — redeliveries overwrote their own sequence file —
    // and every packet landed with its own bytes.
    let stored = sink.inner.stored(handle).unwrap();
    assert_eq!(
        stored.len(),
        expected.len(),
        "one spool file per delivered packet"
    );
    let sequences = stored
        .iter()
        .map(|(sequence, _)| *sequence)
        .collect::<Vec<_>>();
    let continuity = 1..=expected.len() as u64;
    assert!(
        sequences.iter().copied().eq(continuity),
        "delivery sequences are contiguous with no gaps or duplicates"
    );
    // Each sequence must hold its own packet: compare sequence and bytes
    // together, so a payload stored under a wrong sequence cannot pass.
    for (sequence, path) in &stored {
        let expected_packet = &expected[(*sequence - 1) as usize];
        assert_eq!(
            &std::fs::read(path).unwrap(),
            expected_packet,
            "sequence {sequence} holds the wrong packet"
        );
    }
}

/// The reconnect cadence stays inside the configured backoff: the wait before
/// attempt `n` is `initial * multiplier^(n-1)`, capped, plus up to +50 %
/// uniform jitter on top.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_backoff_stays_within_the_policy() {
    let (station, dir) = start_station().await;
    // Every attempt is accepted then dropped, so each retry is timestamped.
    station.mode.send(Mode::Drop).unwrap();

    let credentials = Credentials::mint(
        station.origin.clone(),
        "btm1.test".to_owned(),
        dir.0.join("credentials.json"),
    )
    .unwrap();
    let roots = vec![station.ca_pem.clone()];
    let mut sink = Counted {
        inner: Spool::open(&dir.0.join("spool")).unwrap(),
        accepts: 0,
        by_sequence: BTreeMap::new(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let policy = ReconnectPolicy {
        initial: Duration::from_millis(100),
        multiplier: 4,
        cap: Duration::from_millis(200),
    };

    let driver = async {
        // Five attempts produce four measured backoff waits: 100 then the
        // 200 cap held three times. With the cap missing the third wait
        // would be 1600 ms — far outside the capped assertion window.
        wait_accepts(&station.store, 5, Duration::from_secs(15)).await;
        stop.send(true).unwrap();
    };
    let (exit, ()) = tokio::join!(
        receive_loop(&credentials, &roots, &mut sink, stop_rx, policy),
        driver,
    );
    match exit {
        LoopExit::Stopped => {}
        LoopExit::Failed(error) => panic!("the lane failed: {error}"),
    }

    let accepts = station.store.accepts.lock().unwrap().clone();
    assert!(accepts.len() >= 5, "expected several failed attempts");
    let gaps = accepts
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect::<Vec<_>>();
    // The wait after failure k is base_k = min(initial*mult^(k-1), cap), then
    // up to +50 % jitter. The measured gap also includes the failing
    // attempt's own latency and scheduler noise under a parallel suite, so
    // the upper slack is generous — yet stays far below the 1600 ms wait an
    // uncapped cadence would show at index 2.
    for (index, gap) in gaps.iter().enumerate().take(4) {
        let base = Duration::from_millis([100_u64, 200, 200, 200][index]);
        assert!(
            *gap >= base.mul_f64(0.8),
            "gap {index} {gap:?} below the {base:?} backoff wait"
        );
        assert!(
            *gap <= base.mul_f64(1.5) + Duration::from_millis(500),
            "gap {index} {gap:?} above the jittered {base:?} backoff wait"
        );
    }
}

/// A successful connection resets the cadence: the wait after the next loss
/// is `initial` again, not the grown value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successful_connect_resets_the_backoff() {
    let (station, dir) = start_station().await;
    station.mode.send(Mode::Drop).unwrap();

    let credentials = Credentials::mint(
        station.origin.clone(),
        "btm1.test".to_owned(),
        dir.0.join("credentials.json"),
    )
    .unwrap();
    let roots = vec![station.ca_pem.clone()];
    let mut sink = Counted {
        inner: Spool::open(&dir.0.join("spool")).unwrap(),
        accepts: 0,
        by_sequence: BTreeMap::new(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let policy = ReconnectPolicy {
        initial: Duration::from_millis(40),
        multiplier: 4,
        cap: Duration::from_millis(500),
    };

    let driver = async {
        // Three failed attempts grow the wait: 40, then 160, then the
        // 500 cap — the next wait is the grown value. Wait for the third
        // socket to be dropped, not merely accepted, before enabling
        // service so the mode flip cannot race the fixture's mode read.
        wait_dropped(&station.store, 3, Duration::from_secs(15)).await;
        station.mode.send(Mode::Serve).unwrap();
        // An ACK proves the next attempt reached the mailbox receive loop.
        station.store.enqueue(
            "reset",
            1,
            *HandleToken::mint([0x5A; 16]).unwrap().as_bytes(),
        );
        wait_acked(&station.store, 1, Duration::from_secs(15)).await;
        station.control.send(Control::KillConnections).unwrap();
        // The retry after the killed-but-successful connection arrives after
        // the reset wait — `initial` again, not the grown backoff.
        wait_accepts(&station.store, 5, Duration::from_secs(15)).await;
        stop.send(true).unwrap();
    };
    let (exit, ()) = tokio::join!(
        receive_loop(&credentials, &roots, &mut sink, stop_rx, policy),
        driver,
    );
    match exit {
        LoopExit::Stopped => {}
        LoopExit::Failed(error) => panic!("the lane failed: {error}"),
    }

    let accepts = station.store.accepts.lock().unwrap().clone();
    assert!(
        accepts.len() >= 5,
        "expected failing attempts plus the successful one, got {}",
        accepts.len()
    );
    // accepts[2] → accepts[3] spans the grown wait after three failures:
    // jitter(500) ≥ 500 ms. accepts[3] is the successful connect and
    // accepts[4] the first attempt after it was killed — their gap is the
    // reset wait, jitter(40) ≤ 60 ms plus a small margin, far below the
    // grown value an un-reset cadence would show.
    let grown_gap = accepts[3] - accepts[2];
    assert!(
        grown_gap >= Duration::from_millis(400),
        "the grown backoff {grown_gap:?} should dwarf the reset wait"
    );
    let reset_gap = accepts[4] - accepts[3];
    assert!(
        reset_gap <= Duration::from_millis(40).mul_f64(1.5) + Duration::from_millis(200),
        "reset gap {reset_gap:?} shows the grown backoff was not reset"
    );
}
