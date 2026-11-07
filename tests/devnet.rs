//! Devnet acceptance: the full pairing handshake over a real Station.
//!
//! One test process plays both endpoints. The responder's bootstrap handle,
//! the initiator's reply handle, and the shared session handle are real
//! leases reserved under one live affiliation; every envelope and every
//! session record crosses the Station through the production carrier.
//!
//! The test is gated on its environment, exactly like the SDK's own
//! authority-gated tests. Required:
//!
//! - `LICOARC_AUTHORITY_BUNDLE` — one authority bundle artifact;
//! - `LICOARC_DEVNET_STATION` — the Station origin, e.g.
//!   `https://127.0.0.1:8443`;
//! - `LICOARC_DEVNET_DESCRIPTOR` — the Station descriptor digest, 64 hex;
//! - `LICOARC_DEVNET_CA` — optional PEM file added to the trust roots for a
//!   self-signed development certificate.
//! - `LICOARC_DEVNET_ACCESS` — optional BadTower.js access credentials file.
//!   When set the Station is the capability-gated profile: affiliation is
//!   skipped (the preview fails it closed by design) and every lease is
//!   first-contact, which fits this flow's one submission per handle.
//!
//! The affiliation commitment is minted fresh per run so repeated runs never
//! collide under the idempotent affiliate operation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use licoarc::provider::RustCryptoProvider;
use licoarc::state::{ApplicationEffects, PlaintextReceiver};

use licoarc_client::adapters::PacketCarrierAdapter;
use licoarc_client::carrier::{
    AffiliateRequest, CarrierConfig, HandleClass, ReserveRequest, StationClient,
    TRANSPORT_PROFILE_DIGEST,
};
use licoarc_client::ports::Clock;
use licoarc_client::providers::FileCustody;
use licoarc_client::{
    AuthorityInput, ConsumeVerdict, EndpointConsumer, Error, HandleCarrier, InitiatorDrive,
    LocalIdentity, Mailbox, PacketSink, PairingOffer, ResponderDrive, StaticTrust, SubmitCarrier,
    SystemClock,
};

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if text.len() != 64 {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

struct Config {
    origin: String,
    descriptor: [u8; 32],
    authority: PathBuf,
    ca: Option<PathBuf>,
    access: Option<PathBuf>,
}

fn env_config() -> Option<Config> {
    std::env::var_os("LICOARC_DEVNET")?;
    Some(Config {
        origin: std::env::var("LICOARC_DEVNET_STATION").ok()?,
        descriptor: hex32(&std::env::var("LICOARC_DEVNET_DESCRIPTOR").ok()?)?,
        authority: PathBuf::from(std::env::var_os("LICOARC_AUTHORITY_BUNDLE")?),
        ca: std::env::var_os("LICOARC_DEVNET_CA").map(PathBuf::from),
        access: std::env::var_os("LICOARC_DEVNET_ACCESS").map(PathBuf::from),
    })
}

fn station_client(config: &Config) -> StationClient {
    let mut carrier = CarrierConfig {
        origin: config.origin.clone(),
        request_timeout: Duration::from_secs(30),
        ..CarrierConfig::default()
    };
    if let Some(ca) = &config.ca {
        let pem = std::fs::read(ca).expect("devnet CA file readable");
        carrier
            .extra_root_certificates
            .push(reqwest::Certificate::from_pem(&pem).expect("devnet CA is PEM"));
    }
    carrier.access_credentials = config.access.clone();
    StationClient::new(carrier).expect("station client constructs")
}

/// A fresh commitment per run: nanoseconds since epoch spread across the
/// array keeps repeated devnet runs from replaying an earlier affiliation.
fn fresh_commitment() -> [u8; 32] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut commitment = [0u8; 32];
    for (i, byte) in commitment.iter_mut().enumerate() {
        *byte = (nanos >> ((i % 16) * 8)) as u8 ^ (i as u8).wrapping_mul(31);
    }
    commitment
}

/// A unique empty directory per endpoint, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp() -> TempDir {
    let path = std::env::temp_dir().join(format!(
        "licoarc-client-devnet-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

/// Claims land here; every item completes so the queue drains for the next
/// leg.
#[derive(Default)]
struct Collect {
    packets: Vec<Vec<u8>>,
}

impl PacketSink for Collect {
    fn accept(&mut self, packet: &[u8]) -> ConsumeVerdict {
        self.packets.push(packet.to_vec());
        ConsumeVerdict::Complete
    }
}

struct NullEffects;

impl ApplicationEffects for NullEffects {
    fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

struct CapturePlaintext {
    plaintexts: Vec<Vec<u8>>,
}

impl PlaintextReceiver for CapturePlaintext {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.plaintexts.push(plaintext.to_vec());
        Ok(())
    }
}

#[test]
fn pairing_over_a_real_station_moves_a_record() {
    let Some(config) = env_config() else {
        eprintln!("LICOARC_DEVNET unset: skipping devnet acceptance");
        return;
    };
    let bundle = std::fs::read(&config.authority).expect("authority bundle readable");
    let line = AuthorityInput::new(&bundle)
        .admit()
        .expect("authority bundle admits");
    let client = Arc::new(station_client(&config));
    let runtime = tokio::runtime::Runtime::new().expect("devnet runtime builds");
    let commitment = fresh_commitment();

    // One affiliation, three leases: responder bootstrap, initiator reply,
    // shared session. The capability-gated profile skips affiliation — the
    // preview fails it closed — and every lease is first-contact, matching
    // this flow's one submission per handle.
    if config.access.is_none() {
        runtime.block_on(async {
            client
                .affiliate(&AffiliateRequest {
                    station_descriptor_digest: config.descriptor,
                    affiliation_commitment: commitment,
                })
                .await
                .expect("affiliate succeeds");
        });
    }
    let class = if config.access.is_some() {
        HandleClass::FirstContact
    } else {
        HandleClass::Async
    };
    let reserve = || {
        runtime
            .block_on(client.reserve(&ReserveRequest {
                station_descriptor_digest: config.descriptor,
                affiliation_commitment: commitment,
                transport_profile_digest: TRANSPORT_PROFILE_DIGEST,
                handle_class: class,
            }))
            .expect("reserve succeeds")
            .handle
    };
    let bootstrap = reserve();
    let reply_handle = reserve();
    let session_handle = reserve();

    // Both endpoints mint identities; only wire forms travel.
    let consumer = EndpointConsumer::new();
    let clock = SystemClock;
    let responder_authority = [81; 32];
    let initiator_authority = [82; 32];
    let responder_dir = temp();
    let initiator_dir = temp();
    let mut responder_custody =
        FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap();
    let mut initiator_custody =
        FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap();
    let responder_identity = LocalIdentity::mint(&mut responder_custody).unwrap();
    let initiator_identity = LocalIdentity::mint(&mut initiator_custody).unwrap();

    // The responder issues its offer, then crosses a process boundary: the
    // drive is dropped and reopened from the sealed checkpoint, so the prekey
    // the offer published is exactly the prekey the restored endpoint holds.
    let offer = {
        let mut responder = ResponderDrive::open(
            responder_dir.path(),
            line.clone(),
            responder_custody.clone(),
            RustCryptoProvider,
        )
        .unwrap();
        let now = clock.now_unix_seconds().unwrap();
        responder
            .issue_offer(
                &responder_identity,
                responder_authority,
                bootstrap,
                1,
                now - 60,
                now + 3_600,
            )
            .unwrap()
    };
    let offer = PairingOffer::decode(&offer.encode().unwrap()).unwrap();

    // Same boundary for the initiator between begin and finish.
    let submission = {
        let mut initiator = InitiatorDrive::open(
            initiator_dir.path(),
            line.clone(),
            initiator_custody.clone(),
            RustCryptoProvider,
        )
        .unwrap();
        initiator
            .begin(
                &consumer,
                &initiator_identity,
                initiator_authority,
                &offer,
                reply_handle,
                &StaticTrust::for_identity(&offer.identity),
                &clock,
            )
            .unwrap()
    };

    // The submission crosses the Station to the responder's bootstrap handle.
    runtime
        .block_on(client.submit(bootstrap, &submission))
        .expect("submission lands");
    let bootstrap_mailbox = Mailbox::new(HandleCarrier::new(client.clone(), bootstrap), 16);
    let mut inbound = Collect::default();
    let report = runtime
        .block_on(bootstrap_mailbox.pump(&mut inbound))
        .expect("bootstrap claim succeeds");
    assert_eq!(report.claimed, 1);
    assert_eq!(inbound.packets.len(), 1);

    // The responder authenticates and produces the reply for the session
    // handle it reserved.
    let mut responder_trust = StaticTrust::new();
    responder_trust.register(initiator_identity.public().clone());
    let mut responder = ResponderDrive::open(
        responder_dir.path(),
        line.clone(),
        FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap(),
        RustCryptoProvider,
    )
    .unwrap();
    let (reply, session, facts) = responder
        .accept(
            &consumer,
            initiator_identity.public().clone(),
            &responder_identity,
            responder_authority,
            &responder_trust,
            session_handle,
            &inbound.packets[0],
            &clock,
        )
        .unwrap();
    assert_eq!(
        facts.author().user_authority_state_digest,
        initiator_authority
    );

    // The reply crosses back over the initiator's reply handle.
    runtime
        .block_on(client.submit(reply_handle, &reply.encode().unwrap()))
        .expect("reply lands");
    let reply_mailbox = Mailbox::new(HandleCarrier::new(client.clone(), reply_handle), 16);
    let mut replies = Collect::default();
    runtime
        .block_on(reply_mailbox.pump(&mut replies))
        .expect("reply claim succeeds");
    assert_eq!(replies.packets.len(), 1);
    let mut initiator = InitiatorDrive::open(
        initiator_dir.path(),
        line.clone(),
        FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap(),
        RustCryptoProvider,
    )
    .unwrap();
    let (_accept, learned) = initiator.finish(&replies.packets[0]).unwrap();
    assert_eq!(learned, session_handle);

    // One protected record travels initiator → responder over the session
    // handle, dispatched by the SDK through the blocking submit lane.
    let pending = initiator
        .endpoint()
        .unwrap()
        .send_record(b"devnet-proof", None)
        .unwrap();
    initiator.persist().unwrap();
    let submit_lane = SubmitCarrier::new(client.clone(), session_handle).unwrap();
    let mut carrier = PacketCarrierAdapter::new(submit_lane);
    let mut effects = NullEffects;
    initiator
        .endpoint()
        .unwrap()
        .dispatch_pending(pending, &mut carrier, &mut effects)
        .unwrap();
    initiator.persist().unwrap();

    // The responder crosses one more boundary after the handshake: the
    // session is dropped and the endpoint resumes established, so the record
    // lands on a restarted process.
    drop(session);
    drop(responder);
    let mut responder = ResponderDrive::open(
        responder_dir.path(),
        line.clone(),
        FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap(),
        RustCryptoProvider,
    )
    .unwrap();

    let session_mailbox = Mailbox::new(HandleCarrier::new(client.clone(), session_handle), 16);
    let mut inbound_session = Collect::default();
    let report = runtime
        .block_on(session_mailbox.pump(&mut inbound_session))
        .expect("session claim succeeds");
    assert_eq!(report.claimed, 1);
    let inbound_pending = responder
        .endpoint()
        .unwrap()
        .receive_record(&inbound_session.packets[0], None)
        .unwrap();
    responder.persist().unwrap();
    let mut receiver = CapturePlaintext {
        plaintexts: Vec::new(),
    };
    responder
        .endpoint()
        .unwrap()
        .release_pending_plaintext(inbound_pending, &mut receiver)
        .unwrap();
    assert_eq!(receiver.plaintexts, vec![b"devnet-proof".to_vec()]);
    responder.persist().unwrap();
}
