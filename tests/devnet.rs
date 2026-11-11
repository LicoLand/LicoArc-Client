//! Devnet acceptance: the full pairing handshake over a real Station.
//!
//! One test process plays both endpoints. Each endpoint owns one mailbox:
//! enrollment is a `btm1` invitation plus a device key, the first READY
//! binds the mailbox id, and every envelope and session record crosses the
//! Station through the production mailbox carrier.
//!
//! The test is gated on its environment:
//!
//! - `LICOARC_AUTHORITY_BUNDLE` — one authority bundle artifact;
//! - `LICOARC_DEVNET_STATION` — the Station origin, e.g.
//!   `https://localhost:8443`;
//! - `LICOARC_DEVNET_CA` — PEM file added to the trust roots for the
//!   development certificate;
//! - `LICOARC_DEVNET_INVITATIONS` — directory containing
//!   `responder.invitation` and `initiator.invitation` token files.
//!
//! The flow: both endpoints enroll and bind; the responder offers on its own
//! mailbox handle, the initiator begins against its own handle, the reply
//! returns over the initiator's handle, and one session record travels each
//! way.

use std::path::PathBuf;

use licoarc::provider::RustCryptoProvider;
use licoarc::state::{ApplicationEffects, PlaintextReceiver};
use licoarc_client::{
    AuthorityInput, Clock, Credentials, EndpointConsumer, EndpointSink, Error, Event, FileCustody,
    HandleToken, InitiatorDrive, LocalIdentity, MailboxClient, PacketCarrierAdapter, PacketSink,
    PairingOffer, PortFailure, ResponderDrive, StaticTrust, SystemClock, Transport,
    TransportOutcome,
};

struct Config {
    origin: String,
    authority: PathBuf,
    ca: PathBuf,
    invitations: PathBuf,
}

fn env_config() -> Option<Config> {
    let invitations = std::env::var_os("LICOARC_DEVNET_INVITATIONS")?;
    Some(Config {
        origin: std::env::var("LICOARC_DEVNET_STATION").ok()?,
        ca: PathBuf::from(std::env::var_os("LICOARC_DEVNET_CA")?),
        authority: PathBuf::from(std::env::var_os("LICOARC_AUTHORITY_BUNDLE")?),
        invitations: PathBuf::from(invitations),
    })
}

/// Enrolls one endpoint: fresh credentials from its invitation file, a
/// handshake that binds the mailbox id, and a live mailbox client.
async fn enroll(config: &Config, invitation: &str) -> MailboxClient {
    let token = std::fs::read_to_string(config.invitations.join(invitation))
        .expect("invitation file readable")
        .trim()
        .to_owned();
    let credentials = Credentials::mint(config.origin.clone(), token, PathBuf::from("/dev/null"))
        .expect("credentials mint");
    let roots = vec![config.ca.clone()];
    MailboxClient::connect(&credentials, &roots)
        .await
        .expect("enrollment connects")
}

/// Receives deliveries for one connection until `expected` packets are
/// ACKed. DRAINED is transient (the station sends it at bind time when the
/// mailbox is empty): we keep reading until the expected deliveries arrive —
/// the DRAINED that follows an ACK ends the wait.
async fn drain(client: &mut MailboxClient, expected: usize) -> Vec<(u64, HandleToken, Vec<u8>)> {
    let mut packets = vec![];
    loop {
        match client.next().await.expect("mailbox event") {
            Event::Deliver {
                sequence,
                handle,
                packet,
            } => {
                packets.push((sequence, handle, packet));
                client.ack(sequence).await.expect("ack lands");
            }
            Event::Drained => {
                if packets.len() >= expected {
                    return packets;
                }
            }
        }
    }
}

/// A unique empty directory per endpoint, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

fn temp() -> TempDir {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    let path = std::env::temp_dir().join(format!(
        "licoarc-devnet-{}-{}",
        std::process::id(),
        u64::from_be_bytes(bytes)
    ));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Default)]
struct Collect(std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>);

impl PlaintextReceiver for Collect {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.0.borrow_mut().push(plaintext.to_vec());
        Ok(())
    }
}

struct NullEffects;

impl ApplicationEffects for NullEffects {
    fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// A synchronous `Transport` adapter over a borrowed mailbox client — the
/// same `block_on` shape `SubmitCarrier` uses, scoped to this test.
struct RuntimeCarrier<'a> {
    client: &'a mut MailboxClient,
    handle: HandleToken,
    runtime: &'a tokio::runtime::Runtime,
}

impl Transport for RuntimeCarrier<'_> {
    fn submit(&mut self, packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
        self.runtime
            .block_on(self.client.send(self.handle, packet))
            .map_err(|_| PortFailure::Unavailable)?;
        Ok(TransportOutcome::Accepted)
    }
}

#[test]
fn pairing_over_a_real_station_moves_a_record() {
    let Some(config) = env_config() else {
        eprintln!("LICOARC_DEVNET_* unset: skipping devnet acceptance");
        return;
    };
    let bundle = std::fs::read(&config.authority).expect("authority bundle readable");
    let line = AuthorityInput::new(&bundle)
        .admit()
        .expect("authority bundle admits");
    let runtime = tokio::runtime::Runtime::new().expect("devnet runtime builds");

    let responder_dir = temp();
    let initiator_dir = temp();
    let mut responder_client = runtime.block_on(enroll(&config, "responder.invitation"));
    let mut initiator_client = runtime.block_on(enroll(&config, "initiator.invitation"));
    let responder_handle = HandleToken::mint(responder_client.mailbox_id()).expect("mint");
    let initiator_handle = HandleToken::mint(initiator_client.mailbox_id()).expect("mint");

    let consumer = EndpointConsumer::new();
    let clock = SystemClock;
    let responder_authority = [81; 32];
    let initiator_authority = [82; 32];
    let mut responder_custody =
        FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap();
    let mut initiator_custody =
        FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap();
    let responder_identity = LocalIdentity::mint(&mut responder_custody).unwrap();
    let initiator_identity = LocalIdentity::mint(&mut initiator_custody).unwrap();

    // The responder offers on its own mailbox handle, then crosses a process
    // boundary so the published offer matches the restored prekey.
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
                responder_handle,
                1,
                now - 60,
                now + 3_600,
            )
            .unwrap()
    };
    let offer = PairingOffer::decode(&offer.encode().unwrap()).unwrap();

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
                initiator_handle,
                &StaticTrust::for_identity(&offer.identity),
                &clock,
            )
            .unwrap()
    };

    // The submission crosses the Station into the responder's mailbox.
    runtime
        .block_on(initiator_client.send(responder_handle, &submission))
        .expect("submission lands");
    let inbound = runtime.block_on(drain(&mut responder_client, 1));
    assert_eq!(inbound.len(), 1);

    // The responder authenticates and produces the reply; its session
    // handle is its own mailbox (initiator sends session records there).
    let mut responder_trust = StaticTrust::new();
    responder_trust.register(initiator_identity.public().clone());
    let mut responder_custody_drive =
        FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap();
    let mut responder = ResponderDrive::open(
        responder_dir.path(),
        line.clone(),
        responder_custody_drive.clone(),
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
            responder_handle,
            &inbound[0].2,
            &clock,
        )
        .unwrap();
    assert_eq!(
        facts.author().user_authority_state_digest,
        initiator_authority
    );

    // The reply crosses back into the initiator's mailbox.
    runtime
        .block_on(responder_client.send(initiator_handle, &reply.encode().unwrap()))
        .expect("reply lands");
    let replies = runtime.block_on(drain(&mut initiator_client, 1));
    assert_eq!(replies.len(), 1);
    let mut initiator_custody_drive =
        FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap();
    let mut initiator = InitiatorDrive::open(
        initiator_dir.path(),
        line.clone(),
        initiator_custody_drive.clone(),
        RustCryptoProvider,
    )
    .unwrap();
    let (_accept, learned) = initiator.finish(&replies[0].2).unwrap();
    assert_eq!(learned, responder_handle);

    // One protected record travels initiator → responder through the SDK's
    // synchronous dispatch boundary over the mailbox carrier.
    let pending = initiator
        .endpoint()
        .unwrap()
        .send_record(b"devnet-proof", None)
        .unwrap();
    initiator.persist().unwrap();
    {
        let mut carrier = PacketCarrierAdapter::new(RuntimeCarrier {
            client: &mut initiator_client,
            handle: responder_handle,
            runtime: &runtime,
        });
        initiator
            .endpoint()
            .unwrap()
            .dispatch_pending(pending, &mut carrier, &mut NullEffects)
            .unwrap();
    }
    initiator.persist().unwrap();

    // The responder crosses a process boundary and consumes the record.
    drop(session);
    drop(responder);
    let mut responder = ResponderDrive::open(
        responder_dir.path(),
        line.clone(),
        responder_custody_drive.clone(),
        RustCryptoProvider,
    )
    .unwrap();
    let records = runtime.block_on(drain(&mut responder_client, 1));
    assert_eq!(records.len(), 1);
    {
        let received = Collect::default();
        let mut sink = EndpointSink::new(responder.endpoint().unwrap(), received.clone());
        sink.accept(0, HandleToken::from_bytes([0_u8; 32]), &records[0].2);
        assert_eq!(sink.refused().len(), 0);
        assert_eq!(received.0.borrow().len(), 1);
        assert_eq!(received.0.borrow()[0], b"devnet-proof");
    }
    responder.persist().unwrap();

    // And one record travels back responder → initiator.
    // The responder's first send needs a fresh X25519 for the DH ratchet
    // step (`bootstrap_private`) — its sending chain starts empty.
    let staged = responder_custody_drive
        .stage(licoarc_client::CustodyPurpose::X25519Private)
        .unwrap();
    let pending = responder
        .endpoint()
        .unwrap()
        .send_record(
            b"devnet-reply",
            Some(licoarc_client::state::StagedSecretHandle::<
                licoarc_client::state::X25519Private,
            >::from_custody_token(staged.custody_token())),
        )
        .unwrap();
    responder.persist().unwrap();
    {
        let mut carrier = PacketCarrierAdapter::new(RuntimeCarrier {
            client: &mut responder_client,
            handle: initiator_handle,
            runtime: &runtime,
        });
        responder
            .endpoint()
            .unwrap()
            .dispatch_pending(pending, &mut carrier, &mut NullEffects)
            .unwrap();
    }
    responder.persist().unwrap();
    let replies = runtime.block_on(drain(&mut initiator_client, 1));
    assert_eq!(replies.len(), 1);
    // The responder's first record rotated the DH: the initiator needs a
    // fresh staged X25519 to complete the ratchet step.
    {
        let received = Collect::default();
        let mut sink =
            EndpointSink::with_fresh(initiator.endpoint().unwrap(), received.clone(), move || {
                initiator_custody_drive
                    .stage(licoarc_client::CustodyPurpose::X25519Private)
                    .ok()
                    .map(|handle| {
                        licoarc_client::state::StagedSecretHandle::<
                            licoarc_client::state::X25519Private,
                        >::from_custody_token(handle.custody_token())
                    })
            });
        sink.accept(0, HandleToken::from_bytes([0_u8; 32]), &replies[0].2);
        assert_eq!(sink.refused().len(), 0);
        assert_eq!(received.0.borrow().len(), 1);
        assert_eq!(received.0.borrow()[0], b"devnet-reply");
    }
}
