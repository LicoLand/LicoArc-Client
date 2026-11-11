//! The pairing drives: caller-owned custody and state behind one SDK endpoint
//! per role.
//!
//! The pinned SDK's endpoint is one long-lived object: `Endpoint::initiator`
//! admits only the `InitiatorNew` phase and `Endpoint::responder` only
//! `ResponderReady`, and the same endpoint then walks `Awaiting` and
//! `Established` through its own commits. Each drive therefore constructs its
//! endpoint once and keeps it for the role's lifetime — rebuilding per call
//! would fail the phase check exactly when a session exists to serve.
//!
//! Drives hold the caller-owned assembly — the verified line, the crypto
//! provider, the [`FileCustody`]-backed custody adapter, and the
//! [`FileState`]-backed state adapter — and refuse in [`InboundRefusal`]
//! vocabulary: SDK causes ride through verbatim, envelopes that cannot form
//! one unit refuse as `UnboundUnit`, and custody staging failures surface as a
//! provider failure.
//!
//! Durability: every state-advancing drive call seals the SDK checkpoint to
//! `dir/endpoint.checkpoint` before returning, so a reopened drive resumes
//! from the last committed snapshot. Callers that advance state through
//! `endpoint()` or a returned session do the same through
//! [`FileState::save`]/[`ResponderDrive::persist`].

use std::path::Path;

use licoarc::artifact::VerifiedProtocolLine;
use licoarc::endpoint::{self, Endpoint, IdentityPublic, Initiator, Responder, SessionAccept};
use licoarc::error::{Error, ErrorCode, Stage};
use licoarc::provider::Provider;
use licoarc::state::{
    MlKem768Private, MlKemEncapsulationEntropy, SecretHandle, StagedSecretHandle,
    TrustFacts as TrustFactsPort, X25519Private,
};

use crate::HandleToken;
use crate::adapters::{AtomicStateAdapter, ClockAdapter, KeyCustodyAdapter};
use crate::inbound::{EndpointConsumer, InboundRefusal, InboundSession, TrustFacts};
use crate::ports::{Clock as ClockPort, CustodyPurpose};
use crate::providers::FileCustody;

use super::{FileState, LocalIdentity, PairingOffer, PairingReply, PairingSubmission};

/// The SDK store type one drive hands its endpoint.
pub type DriveStore<P> = AtomicStateAdapter<FileState<P>>;

/// The SDK custody type one drive hands its endpoint.
pub type DriveCustody<P> = KeyCustodyAdapter<FileCustody<P>, FileCustody<P>>;

/// The responder endpoint the drives assemble.
pub type ResponderEndpoint<P> = Endpoint<Responder, P, DriveCustody<P>, DriveStore<P>>;

/// The initiator endpoint the drives assemble.
pub type InitiatorEndpoint<P> = Endpoint<Initiator, P, DriveCustody<P>, DriveStore<P>>;

/// The SDK-authenticated responder session `accept` yields.
pub type ResponderSession<P> = InboundSession<P, DriveCustody<P>, DriveStore<P>>;

/// The caller-owned pieces every operation reassembles around.
struct Shared<P> {
    line: VerifiedProtocolLine,
    provider: P,
    custody: FileCustody<P>,
    state: FileState<P>,
}

impl<P> Shared<P> {
    fn custody_adapter(&self) -> DriveCustody<P> {
        // Both clones share one custody table, so the handle lookup and the
        // operation see the same objects the SDK commits mutations against.
        KeyCustodyAdapter::new(self.custody.clone(), self.custody.clone())
    }

    fn state_adapter(&self) -> DriveStore<P> {
        AtomicStateAdapter::new(self.state.clone())
    }
}

/// Custody staging failures surface as an unavailable port in SDK vocabulary.
fn custody_refusal() -> InboundRefusal {
    InboundRefusal::of(Error::terminal(
        ErrorCode::ProviderFailure,
        Stage::Validation,
    ))
}

/// The responder half of one pairing: stage a prekey, publish an offer,
/// authenticate a submission.
pub struct ResponderDrive<P> {
    shared: Shared<P>,
    endpoint: Option<ResponderEndpoint<P>>,
}

/// The initiator half of one pairing: build a submission, verify the reply.
pub struct InitiatorDrive<P> {
    shared: Shared<P>,
    endpoint: Option<InitiatorEndpoint<P>>,
}

impl<P> ResponderDrive<P>
where
    P: Provider + Clone,
{
    /// Opens the durable responder endpoint at `dir`.
    ///
    /// The state is [`FileState::responder`]: a checkpoint file restores the
    /// last committed snapshot (prekeys and established sessions included),
    /// an absent file starts `ResponderReady`. The endpoint's own phase check
    /// decides on first use whether the state is admissible.
    ///
    /// # Errors
    ///
    /// Returns `InboundRefusal` when the checkpoint cannot be read or refuses
    /// to decode.
    pub fn open(
        dir: &Path,
        line: VerifiedProtocolLine,
        custody: FileCustody<P>,
        provider: P,
    ) -> Result<Self, InboundRefusal> {
        Ok(Self {
            shared: Shared {
                line: line.clone(),
                provider: provider.clone(),
                custody: custody.clone(),
                state: FileState::responder(dir, line, custody, provider)
                    .map_err(|_| custody_refusal())?,
            },
            endpoint: None,
        })
    }

    /// The endpoint, constructed on first use and kept for the role's
    /// lifetime.
    ///
    /// All endpoint operations — pending enumeration, dispatch, plaintext
    /// release, record retry, session delete — are reached through it.
    ///
    /// # Errors
    ///
    /// Returns the SDK refusal when the state is dead or is not in the
    /// `ResponderReady` phase at construction, or `InvalidTransition` when the
    /// endpoint was already consumed by [`ResponderDrive::accept`].
    pub fn endpoint(&mut self) -> Result<&mut ResponderEndpoint<P>, InboundRefusal> {
        if self.endpoint.is_none() {
            // `resume` admits every live responder phase — `ResponderReady`
            // for a fresh directory, `Established` for a restored session —
            // so one constructor covers open and reopen alike.
            self.endpoint = Some(
                Endpoint::<Responder, _, _, _>::resume(
                    self.shared.line.clone(),
                    self.shared.provider.clone(),
                    self.shared.custody_adapter(),
                    self.shared.state_adapter(),
                    self.shared.state.minimum_generation(),
                )
                .map_err(InboundRefusal::of)?,
            );
        }
        self.endpoint.as_mut().ok_or_else(|| {
            InboundRefusal::of(Error::terminal(
                ErrorCode::InvalidTransition,
                Stage::Validation,
            ))
        })
    }

    /// The coupled custody, for callers that stage through the same backend.
    #[must_use]
    pub const fn custody(&self) -> &FileCustody<P> {
        &self.shared.custody
    }

    /// The coupled custody, mutable, for secret insertion outside a drive op.
    pub fn custody_mut(&mut self) -> &mut FileCustody<P> {
        &mut self.shared.custody
    }

    /// The coupled durable state, for checkpoint publication after work the
    /// caller drove through `endpoint()` directly.
    #[must_use]
    pub const fn state(&self) -> &FileState<P> {
        &self.shared.state
    }

    /// Seals the live endpoint's committed snapshot to the checkpoint file.
    ///
    /// Drive operations persist before returning; callers that advanced state
    /// through `endpoint()` — `send_record`, `dispatch_pending`, plaintext
    /// release — call this before reporting the operation complete.
    ///
    /// # Errors
    ///
    /// Returns `InboundRefusal` when the endpoint refuses to checkpoint or the
    /// file write fails.
    pub fn persist(&self) -> Result<(), InboundRefusal> {
        if let Some(endpoint) = &self.endpoint {
            self.shared
                .state
                .save(endpoint)
                .map_err(|_| custody_refusal())?;
        }
        Ok(())
    }

    /// Stages one X25519 + one ML-KEM private inside custody and admits the
    /// resulting [`PrekeyBundle`](licoarc::endpoint::PrekeyBundle), then binds
    /// it to the bootstrap handle.
    ///
    /// The SDK commits the staged-key adoption with the state revision, so a
    /// refused admission leaves no half-adopted secret, and an abandoned staged
    /// key is removed by the custody's abort path.
    ///
    /// # Errors
    ///
    /// Returns `InboundRefusal` when custody refuses to stage, or when the SDK
    /// refuses the bundle's window or shape.
    pub fn issue_offer(
        &mut self,
        identity: &LocalIdentity,
        responder_authority_state_digest: [u8; 32],
        bootstrap_handle: HandleToken,
        pair_sequence: u64,
        valid_from: u64,
        valid_until: u64,
    ) -> Result<PairingOffer, InboundRefusal> {
        let x25519 = self
            .shared
            .custody
            .stage(CustodyPurpose::X25519Private)
            .map_err(|_| custody_refusal())?;
        let ml_kem = self
            .shared
            .custody
            .stage(CustodyPurpose::MlKem768Private)
            .map_err(|_| custody_refusal())?;
        let prekey = self
            .endpoint()?
            .admit_prekey(
                identity.public(),
                &identity.signing_handles(),
                pair_sequence,
                StagedSecretHandle::<X25519Private>::from_custody_token(x25519.custody_token()),
                StagedSecretHandle::<MlKem768Private>::from_custody_token(ml_kem.custody_token()),
                valid_from,
                valid_until,
            )
            .map_err(InboundRefusal::of)?;
        self.persist()?;
        Ok(PairingOffer {
            identity: identity.public().clone(),
            prekey,
            handle: bootstrap_handle,
            responder_authority_state_digest,
        })
    }

    /// Authenticates one [`PairingSubmission`] and produces the reply bound to
    /// `session_handle`.
    ///
    /// The initiator's [`IdentityPublic`] does not travel inside the packet —
    /// the packet carries digests — so the caller supplies the identity it
    /// resolved out-of-band (for example the initiator's published
    /// `identity.json` registered in a [`super::StaticTrust`]). The identity's
    /// digest must equal the packet's, and `TrustedIdentity::resolve` verifies
    /// its key material against `trust`.
    ///
    /// The session takes ownership of the endpoint: the responder's session
    /// traffic runs through it (`receive_record`, `endpoint_mut`), while a
    /// drive's endpoint stays usable for further prekey admissions only until
    /// consumed.
    ///
    /// # Errors
    ///
    /// Returns `UnboundUnit` for a malformed envelope or an identity the
    /// packet does not name, and the SDK's refusal when the handshake does not
    /// authenticate.
    #[allow(clippy::too_many_arguments)]
    pub fn accept<K>(
        &mut self,
        consumer: &EndpointConsumer,
        initiator_identity: IdentityPublic,
        self_identity: &LocalIdentity,
        self_authority_state_digest: [u8; 32],
        trust: &impl TrustFactsPort,
        session_handle: HandleToken,
        submission_bytes: &[u8],
        clock: &K,
    ) -> Result<(PairingReply, ResponderSession<P>, TrustFacts), InboundRefusal>
    where
        K: ClockPort,
    {
        let submission =
            PairingSubmission::decode(submission_bytes).map_err(|_| InboundRefusal::UnboundUnit)?;
        if submission.packet.initiator_identity_state_digest != initiator_identity.state_digest {
            // The caller-resolved identity must be the one the packet names;
            // anything else would verify a different device's handshake.
            return Err(InboundRefusal::UnboundUnit);
        }
        let trusted = consumer.trust_peer(&self.shared.line, trust, &initiator_identity)?;
        let endpoint = match self.endpoint.take() {
            Some(endpoint) => endpoint,
            None => Endpoint::<Responder, _, _, _>::resume(
                self.shared.line.clone(),
                self.shared.provider.clone(),
                self.shared.custody_adapter(),
                self.shared.state_adapter(),
                self.shared.state.minimum_generation(),
            )
            .map_err(InboundRefusal::of)?,
        };
        let (mut session, accept) = consumer.accept_handshake(
            endpoint,
            &trusted,
            self_identity.public(),
            self_authority_state_digest,
            &submission.packet,
            &ClockAdapter::new(clock),
        )?;
        // The accepted endpoint lives inside the session from here on; seal
        // the established snapshot before the caller receives it.
        self.shared
            .state
            .save(session.endpoint_mut())
            .map_err(|_| custody_refusal())?;
        let facts = session.facts().clone();
        let reply = PairingReply {
            accept,
            session_handle,
        };
        Ok((reply, session, facts))
    }
}

impl<P> InitiatorDrive<P>
where
    P: Provider + Clone,
{
    /// Opens the durable initiator endpoint at `dir`; see
    /// [`ResponderDrive::open`]. Without a checkpoint the state starts in the
    /// `InitiatorNew` phase.
    ///
    /// # Errors
    ///
    /// Returns `InboundRefusal` when the checkpoint cannot be read or refuses
    /// to decode.
    pub fn open(
        dir: &Path,
        line: VerifiedProtocolLine,
        custody: FileCustody<P>,
        provider: P,
    ) -> Result<Self, InboundRefusal> {
        Ok(Self {
            shared: Shared {
                line: line.clone(),
                provider: provider.clone(),
                custody: custody.clone(),
                state: FileState::initiator(dir, line, custody, provider)
                    .map_err(|_| custody_refusal())?,
            },
            endpoint: None,
        })
    }

    /// The endpoint, constructed on first use and kept for the role's
    /// lifetime.
    ///
    /// All endpoint operations — pending enumeration, dispatch, plaintext
    /// release, record retry, session delete — are reached through it.
    ///
    /// # Errors
    ///
    /// Returns the SDK refusal when the state is dead or does not name an
    /// initiator phase at construction.
    pub fn endpoint(&mut self) -> Result<&mut InitiatorEndpoint<P>, InboundRefusal> {
        if self.endpoint.is_none() {
            self.endpoint = Some(
                Endpoint::<Initiator, _, _, _>::resume(
                    self.shared.line.clone(),
                    self.shared.provider.clone(),
                    self.shared.custody_adapter(),
                    self.shared.state_adapter(),
                    self.shared.state.minimum_generation(),
                )
                .map_err(InboundRefusal::of)?,
            );
        }
        self.endpoint.as_mut().ok_or_else(|| {
            InboundRefusal::of(Error::terminal(
                ErrorCode::InvalidTransition,
                Stage::Validation,
            ))
        })
    }

    /// The coupled custody.
    #[must_use]
    pub const fn custody(&self) -> &FileCustody<P> {
        &self.shared.custody
    }

    /// The coupled custody, mutable.
    pub fn custody_mut(&mut self) -> &mut FileCustody<P> {
        &mut self.shared.custody
    }

    /// The coupled durable state; see [`ResponderDrive::state`].
    #[must_use]
    pub const fn state(&self) -> &FileState<P> {
        &self.shared.state
    }

    /// Seals the live endpoint's committed snapshot; see
    /// [`ResponderDrive::persist`].
    ///
    /// # Errors
    ///
    /// Returns `InboundRefusal` when the endpoint refuses to checkpoint or the
    /// file write fails.
    pub fn persist(&self) -> Result<(), InboundRefusal> {
        if let Some(endpoint) = &self.endpoint {
            self.shared
                .state
                .save(endpoint)
                .map_err(|_| custody_refusal())?;
        }
        Ok(())
    }

    /// Builds the [`PairingSubmission`] answering `offer`, bound to the
    /// initiator's `reply_handle`.
    ///
    /// The offer's responder identity resolves through `trust` — typically
    /// [`super::StaticTrust::for_identity`] on the published offer, or a richer
    /// caller-owned view — and the SDK signs the packet with this identity's
    /// custody-held keys.
    ///
    /// # Errors
    ///
    /// Returns `UnboundUnit` for a reply encoding failure, and the SDK's
    /// refusal when the prekey is out of window or the packet cannot be
    /// produced.
    #[allow(clippy::too_many_arguments)]
    pub fn begin<K>(
        &mut self,
        consumer: &EndpointConsumer,
        identity: &LocalIdentity,
        self_authority_state_digest: [u8; 32],
        offer: &PairingOffer,
        reply_handle: HandleToken,
        trust: &impl TrustFactsPort,
        clock: &K,
    ) -> Result<Vec<u8>, InboundRefusal>
    where
        K: ClockPort,
    {
        let trusted = consumer.trust_peer(&self.shared.line, trust, &offer.identity)?;
        if offer.prekey.responder_identity_state_digest != offer.identity.state_digest {
            return Err(InboundRefusal::UnboundUnit);
        }
        let x25519 = self
            .shared
            .custody
            .stage(CustodyPurpose::X25519Private)
            .map_err(|_| custody_refusal())?;
        let entropy = self
            .shared
            .custody
            .adopt(CustodyPurpose::MlKemEncapsulationEntropy)
            .map_err(|_| custody_refusal())?;
        let packet = self
            .endpoint()?
            .create_first_packet(
                identity.public(),
                &trusted,
                self_authority_state_digest,
                offer.responder_authority_state_digest,
                &identity.signing_handles(),
                offer.prekey.clone(),
                &ClockAdapter::new(clock),
                StagedSecretHandle::<X25519Private>::from_custody_token(x25519.custody_token()),
                SecretHandle::<MlKemEncapsulationEntropy>::from_custody_token(
                    entropy.custody_token(),
                ),
            )
            .map_err(InboundRefusal::of)?;
        let packet_bytes = endpoint::encode_first_packet(&packet).map_err(InboundRefusal::of)?;
        let encoded = PairingSubmission::from_packet_bytes(&packet_bytes, reply_handle)
            .map_err(|_| InboundRefusal::UnboundUnit)?;
        self.persist()?;
        Ok(encoded)
    }

    /// Verifies the responder's [`PairingReply`]; on success the SDK's session
    /// is established and the reply's `session_handle` is where session
    /// traffic is submitted.
    ///
    /// The returned [`SessionAccept`] is the session's replay identity —
    /// `ReplayIdentity::of_accepted_handshake` names it.
    ///
    /// # Errors
    ///
    /// Returns `UnboundUnit` for a malformed reply and the SDK's refusal when
    /// the `SessionAccept` does not verify against the awaiting state.
    pub fn finish(
        &mut self,
        reply_bytes: &[u8],
    ) -> Result<(SessionAccept, HandleToken), InboundRefusal> {
        let reply = PairingReply::decode(reply_bytes).map_err(|_| InboundRefusal::UnboundUnit)?;
        self.endpoint()?
            .verify_session_accept(&reply.accept)
            .map_err(InboundRefusal::of)?;
        self.persist()?;
        Ok((reply.accept, reply.session_handle))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use licoarc::provider::RustCryptoProvider;
    use licoarc::state::{ApplicationEffects, PacketCarrier, PlaintextReceiver};

    use super::*;
    use crate::AuthorityInput;
    use crate::session::{StaticTrust, SystemClock};

    /// A unique empty directory per test, removed on drop.
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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "licoarc-client-session-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    /// The authority bundle is an explicit caller artifact; the full pairing
    /// tests are `#[ignore]`d on it exactly like the SDK's own admission
    /// tests — `verify.sh` runs them when the variable names a bundle.
    fn authority_line() -> VerifiedProtocolLine {
        let path = std::env::var_os("LICOARC_AUTHORITY_BUNDLE")
            .expect("LICOARC_AUTHORITY_BUNDLE must name the pinned authority bundle");
        let bytes = std::fs::read(path).expect("authority bundle readable");
        AuthorityInput::new(&bytes)
            .admit()
            .expect("authority bundle admits")
    }

    /// A carrier that captures each packet it would send.
    #[derive(Default)]
    struct Capture {
        packets: Vec<Vec<u8>>,
        plaintexts: Vec<Vec<u8>>,
    }

    impl PacketCarrier for Capture {
        fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
            self.packets.push(packet.to_vec());
            Ok(())
        }
    }

    impl ApplicationEffects for Capture {
        fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }

    impl PlaintextReceiver for Capture {
        fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
            self.plaintexts.push(plaintext.to_vec());
            Ok(())
        }
    }

    #[test]
    #[ignore = "needs LICOARC_AUTHORITY_BUNDLE"]
    fn pairing_roundtrip_establishes_a_session_and_moves_one_record() {
        let line = authority_line();
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
        let mut responder = ResponderDrive::open(
            responder_dir.path(),
            line.clone(),
            responder_custody,
            RustCryptoProvider,
        )
        .unwrap();
        let mut initiator = InitiatorDrive::open(
            initiator_dir.path(),
            line.clone(),
            initiator_custody,
            RustCryptoProvider,
        )
        .unwrap();

        // The responder publishes one offer; the wire form is what travels.
        let now = clock.now_unix_seconds().unwrap();
        let offer = responder
            .issue_offer(
                &responder_identity,
                responder_authority,
                HandleToken::from_bytes([0x11; 32]),
                1,
                now - 60,
                now + 3_600,
            )
            .unwrap();
        let offer = PairingOffer::decode(&offer.encode().unwrap()).unwrap();

        // The initiator answers the offer over its own trust view.
        let submission = initiator
            .begin(
                &consumer,
                &initiator_identity,
                initiator_authority,
                &offer,
                HandleToken::from_bytes([0x22; 32]),
                &StaticTrust::for_identity(&offer.identity),
                &clock,
            )
            .unwrap();

        // The responder resolves the initiator's published identity through
        // its own trust and authenticates the submission.
        let mut responder_trust = StaticTrust::new();
        responder_trust.register(initiator_identity.public().clone());
        let session_handle = HandleToken::from_bytes([0x33; 32]);
        let (reply, mut session, facts) = responder
            .accept(
                &consumer,
                initiator_identity.public().clone(),
                &responder_identity,
                responder_authority,
                &responder_trust,
                session_handle,
                &submission,
                &clock,
            )
            .unwrap();
        assert_eq!(
            facts.author().user_authority_state_digest,
            initiator_authority
        );

        // The reply travels; the initiator verifies and learns the session
        // handle.
        let (accept, learned_handle) = initiator.finish(&reply.encode().unwrap()).unwrap();
        assert_eq!(learned_handle, session_handle);
        assert_eq!(accept, reply.accept);

        // One record moves initiator → responder through the SDK session.
        let pending = initiator
            .endpoint()
            .unwrap()
            .send_record(b"pairing-proof", None)
            .unwrap();
        let mut carrier = Capture::default();
        let mut effects = Capture::default();
        initiator
            .endpoint()
            .unwrap()
            .dispatch_pending(pending, &mut carrier, &mut effects)
            .unwrap();
        assert_eq!(carrier.packets.len(), 1);

        let (record_facts, inbound_pending) =
            session.receive_record(&carrier.packets[0], None).unwrap();
        assert_eq!(
            record_facts.author().user_authority_state_digest,
            initiator_authority
        );
        let mut receiver = Capture::default();
        session
            .endpoint_mut()
            .release_pending_plaintext(inbound_pending, &mut receiver)
            .unwrap();
        assert_eq!(receiver.plaintexts, vec![b"pairing-proof".to_vec()]);
    }

    /// A dropped drive reopens at the last sealed checkpoint: the responder's
    /// admitted prekey survives, an awaiting initiator resumes, and an
    /// established session keeps serving records after the boundary.
    #[test]
    #[ignore = "needs LICOARC_AUTHORITY_BUNDLE"]
    fn a_reopened_drive_resumes_from_the_last_checkpoint() {
        let line = authority_line();
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

        // The responder issues an offer, then its process boundary is crossed:
        // the drive is dropped and reopened from the sealed checkpoint.
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
                    HandleToken::from_bytes([0x11; 32]),
                    1,
                    now - 60,
                    now + 3_600,
                )
                .unwrap()
        };

        // The initiator begins, then crosses the same boundary.
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
                    HandleToken::from_bytes([0x22; 32]),
                    &StaticTrust::for_identity(&offer.identity),
                    &clock,
                )
                .unwrap()
        };

        // Reopened on both sides, the handshake completes: the restored
        // responder still holds the prekey the offer published, and the
        // restored initiator still awaits the reply.
        let mut responder = ResponderDrive::open(
            responder_dir.path(),
            line.clone(),
            FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap(),
            RustCryptoProvider,
        )
        .unwrap();
        let mut initiator = InitiatorDrive::open(
            initiator_dir.path(),
            line.clone(),
            FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap(),
            RustCryptoProvider,
        )
        .unwrap();
        let mut responder_trust = StaticTrust::new();
        responder_trust.register(initiator_identity.public().clone());
        let session_handle = HandleToken::from_bytes([0x33; 32]);
        let (reply, session, _facts) = responder
            .accept(
                &consumer,
                initiator_identity.public().clone(),
                &responder_identity,
                responder_authority,
                &responder_trust,
                session_handle,
                &submission,
                &clock,
            )
            .unwrap();
        initiator.finish(&reply.encode().unwrap()).unwrap();

        // One record crosses the boundary again: the initiator persists its
        // established endpoint, drops, and the responder's session is itself
        // dropped and resumed before the record arrives.
        let packet = {
            let pending = initiator
                .endpoint()
                .unwrap()
                .send_record(b"across-restart", None)
                .unwrap();
            initiator.persist().unwrap();
            let mut carrier = Capture::default();
            let mut effects = Capture::default();
            initiator
                .endpoint()
                .unwrap()
                .dispatch_pending(pending, &mut carrier, &mut effects)
                .unwrap();
            initiator.persist().unwrap();
            carrier.packets.remove(0)
        };
        drop(session);
        drop(responder);
        let mut responder = ResponderDrive::open(
            responder_dir.path(),
            line.clone(),
            FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap(),
            RustCryptoProvider,
        )
        .unwrap();
        let inbound_pending = responder
            .endpoint()
            .unwrap()
            .receive_record(&packet, None)
            .unwrap();
        responder.persist().unwrap();
        let mut receiver = Capture::default();
        responder
            .endpoint()
            .unwrap()
            .release_pending_plaintext(inbound_pending, &mut receiver)
            .unwrap();
        assert_eq!(receiver.plaintexts, vec![b"across-restart".to_vec()]);
    }

    #[test]
    #[ignore = "needs LICOARC_AUTHORITY_BUNDLE"]
    fn a_malformed_submission_and_untrusted_identity_are_refused() {
        let line = authority_line();
        let consumer = EndpointConsumer::new();
        let clock = SystemClock;
        let responder_dir = temp();
        let initiator_dir = temp();
        let mut responder_custody =
            FileCustody::open(responder_dir.path(), RustCryptoProvider).unwrap();
        let mut initiator_custody =
            FileCustody::open(initiator_dir.path(), RustCryptoProvider).unwrap();
        let responder_identity = LocalIdentity::mint(&mut responder_custody).unwrap();
        let initiator_identity = LocalIdentity::mint(&mut initiator_custody).unwrap();
        let other_identity = LocalIdentity::mint(&mut responder_custody).unwrap();
        let mut responder = ResponderDrive::open(
            responder_dir.path(),
            line.clone(),
            responder_custody,
            RustCryptoProvider,
        )
        .unwrap();
        let mut initiator = InitiatorDrive::open(
            initiator_dir.path(),
            line.clone(),
            initiator_custody,
            RustCryptoProvider,
        )
        .unwrap();

        let now = clock.now_unix_seconds().unwrap();
        let offer = responder
            .issue_offer(
                &responder_identity,
                [81; 32],
                HandleToken::from_bytes([0x11; 32]),
                1,
                now - 60,
                now + 3_600,
            )
            .unwrap();
        let submission = initiator
            .begin(
                &consumer,
                &initiator_identity,
                [82; 32],
                &offer,
                HandleToken::from_bytes([0x22; 32]),
                &StaticTrust::for_identity(&offer.identity),
                &clock,
            )
            .unwrap();

        // The submission envelope is malformed.
        let mut trust = StaticTrust::new();
        trust.register(initiator_identity.public().clone());
        let refused = responder.accept(
            &consumer,
            initiator_identity.public().clone(),
            &responder_identity,
            [81; 32],
            &trust,
            HandleToken::from_bytes([0x33; 32]),
            b"not an envelope",
            &clock,
        );
        assert_eq!(refused.err().unwrap().code(), "unit_not_bound");

        // The resolved identity must be the one the packet names.
        let refused = responder.accept(
            &consumer,
            other_identity.public().clone(),
            &responder_identity,
            [81; 32],
            &trust,
            HandleToken::from_bytes([0x33; 32]),
            &submission,
            &clock,
        );
        assert_eq!(refused.err().unwrap().code(), "unit_not_bound");

        // A genuine submission still lands.
        let (reply, _session, _facts) = responder
            .accept(
                &consumer,
                initiator_identity.public().clone(),
                &responder_identity,
                [81; 32],
                &trust,
                HandleToken::from_bytes([0x33; 32]),
                &submission,
                &clock,
            )
            .unwrap();
        let (_accept, learned) = initiator.finish(&reply.encode().unwrap()).unwrap();
        assert_eq!(learned, reply.session_handle);
    }
}
