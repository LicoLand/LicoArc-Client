//! Inbound verification through the pinned SDK's own verification entries.
//!
//! This is the client-side consumer of the fixed Candidate. It never decides a
//! protocol outcome: it calls the SDK entry that owns each decision and records
//! what that entry verified. Every fact below names the SDK entry that produced
//! it, read at revision `244ce7186cac1690c18f091dbe02df36a0860ef4`.
//!
//! One inbound unit yields one [`TrustFacts`] binding:
//!
//! | fact | SDK verification entry |
//! | --- | --- |
//! | author | handshake: `FirstPacket::initiator_user_authority_state_digest`, accepted by `Endpoint::accept_first_packet`, `src/endpoint/mod.rs:534-652` |
//! | device | handshake: `FirstPacket::initiator_identity_state_digest` plus the accepted ed25519/ml-dsa key ids, and `TrustedIdentity::resolve` for the identity trust facts, `src/endpoint/mod.rs:69-108` |
//! | permission | per unit: `AuthorizedSession::{authenticated,sender_authorized,sender_endpoint,expected_sender_endpoint}`, refused by `reliable::apply_endpoint_confirmation`, `src/reliable.rs:79-88`; the roster layer above it adds `AuthenticatedAuthoritySession::authenticated` and the active-device check, `src/identity.rs:365-397`, reached through [`EndpointConsumer::admit_authority`] |
//! | protocol version | client: [`crate::version::AcceptedVersion`], plus the SDK's own line binding `src/identity.rs:145-147` |
//! | replay identity | handshake: `SessionAccept::{transcript_digest,session_context_digest}`, `src/endpoint/mod.rs:605-624`; record: the `PendingId` of `Endpoint::receive_record`, `src/endpoint/mod.rs:1009-1041` |
//!
//! Raw wire is not the client's internal schema, and a local event sequence is
//! not network author order. The identities this module exposes are the SDK's
//! own: message and session ids are network identities, and a confirmation's
//! confirmed ids must be strictly increasing (`validate_confirmation_ids`,
//! `src/reliable.rs:225-234`), so a client cannot substitute arrival order.
//!
//! Four facts are reported separately and never collapsed into one "delivered"
//! boolean:
//!
//! * message delivery — [`EndpointConsumer::note_delivery`], the peer endpoint
//!   accepted the logical message (`ConfirmationStage::EndpointAccepted`);
//! * reliable exchange — [`EndpointConsumer::note_exchange`], the intent's own
//!   retry/migration state (`ReliableState`, `src/reliable.rs:172-219`);
//! * user read — [`UserRead`], client-owned: the pinned SDK has no read receipt;
//! * task acceptance — [`EndpointConsumer::note_acceptance`], which the SDK
//!   grants only for `ConfirmationStage::EffectCompleted` with the expected
//!   result digest (`src/reliable.rs:121-150`).
//!
//! A peer message identity is never promoted to authority: the permission facts
//! come from the session the SDK authenticated, and a capability proxy's command
//! must re-enter the Graph admission path exactly like any other command.

use licoarc::artifact::VerifiedProtocolLine;
use licoarc::endpoint::{FirstPacket, IdentityPublic, SessionAccept, TrustedIdentity};
use licoarc::error::{Error, ErrorCode};
use licoarc::reliable::{
    AuthorizedSession, EndpointConfirmation, FinalityState, ReliableState,
    apply_endpoint_confirmation,
};
use licoarc::state::{PendingId, TrustFacts as TrustFactsPort};

use crate::version::{AcceptedVersion, ProtocolVersion, VersionRefusal};

/// Client-owned read state.
///
/// The pinned SDK carries no read receipt, so this fact can only come from the
/// client's own view. It is deliberately a standalone type: nothing in this
/// module derives it from delivery, exchange progress, or acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserRead {
    Unread,
    ReadLocally,
}

/// The verified author of one inbound unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorFact {
    /// The user-authority state digest the accepted handshake bound.
    pub user_authority_state_digest: [u8; 32],
}

impl AuthorFact {
    /// Reads the author fact of a handshake the SDK accepted.
    #[must_use]
    pub const fn of_accepted_handshake(packet: &FirstPacket) -> Self {
        Self {
            user_authority_state_digest: packet.initiator_user_authority_state_digest,
        }
    }
}

/// The verified device of one inbound unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceFact {
    /// The identity state digest the accepted handshake bound.
    pub identity_state_digest: [u8; 32],
    pub ed25519_key_id: [u8; 32],
    pub ml_dsa_65_key_id: [u8; 32],
}

impl DeviceFact {
    /// Reads the device fact of a handshake the SDK accepted.
    #[must_use]
    pub const fn of_accepted_handshake(packet: &FirstPacket) -> Self {
        Self {
            identity_state_digest: packet.initiator_identity_state_digest,
            ed25519_key_id: packet.initiator_ed25519_key_id,
            ml_dsa_65_key_id: packet.initiator_ml_dsa_65_key_id,
        }
    }

    /// Reads the device fact of an identity the SDK accepted for this line.
    ///
    /// [`TrustedIdentity`] keeps its identity private, so the caller records the
    /// [`IdentityPublic`] it handed to `TrustedIdentity::resolve`; the SDK
    /// accepted that exact value or the call failed.
    #[must_use]
    pub const fn of_trusted_identity(identity: &IdentityPublic) -> Self {
        Self {
            identity_state_digest: identity.state_digest,
            ed25519_key_id: identity.ed25519_key_id,
            ml_dsa_65_key_id: identity.ml_dsa_65_key_id,
        }
    }
}

/// What the SDK verified about who may send one inbound unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionFact {
    /// An accepted handshake: the SDK verified the peer's identity signatures
    /// and the client confirmation before it produced the accept.
    HandshakeAuthenticated,
    /// One message unit on an authenticated session. The SDK requires every
    /// field here before it applies a confirmation, so a message's own identity
    /// can never stand in for authority (`src/reliable.rs:79-88`).
    Session {
        authenticated: bool,
        sender_authorized: bool,
        sender_endpoint: [u8; 32],
        expected_sender_endpoint: [u8; 32],
    },
}

impl PermissionFact {
    /// Records the session facts the SDK is about to require.
    #[must_use]
    pub const fn of_session(session: &AuthorizedSession) -> Self {
        Self::Session {
            authenticated: session.authenticated,
            sender_authorized: session.sender_authorized,
            sender_endpoint: session.sender_endpoint,
            expected_sender_endpoint: session.expected_sender_endpoint,
        }
    }
}

/// The SDK's own replay-resistant identity of one inbound unit.
///
/// A byte-identical replay of the same unit carries the same identity, and the
/// SDK refuses reuse: an exact handshake replay returns the same accept while a
/// changed one is refused with `PrekeyConsumed` (`src/endpoint/mod.rs:548-561`),
/// and the record layer refuses a replayed or stale record with `Replay`
/// (`src/protection/mod.rs:488`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayIdentity {
    /// One accepted handshake, identified by the SDK's transcript and session
    /// context digests.
    Handshake {
        transcript_digest: [u8; 32],
        session_context_digest: [u8; 32],
    },
    /// One inbound protected record, identified by the SDK's content-derived
    /// pending id.
    ProtectedRecord { pending: PendingId },
}

impl ReplayIdentity {
    #[must_use]
    pub const fn of_accepted_handshake(accept: &SessionAccept) -> Self {
        Self::Handshake {
            transcript_digest: accept.transcript_digest,
            session_context_digest: accept.session_context_digest,
        }
    }

    #[must_use]
    pub const fn of_record(pending: PendingId) -> Self {
        Self::ProtectedRecord { pending }
    }
}

/// Everything the SDK verified about one inbound unit, in client vocabulary.
///
/// This is the client's own record of a verification result, not
/// [`licoarc::state::TrustFacts`] (the caller-owned key-lookup port the SDK
/// resolves an identity through).
///
/// The fields are private and every constructor is fallible on purpose: a fact
/// value is only ever produced from protocol values that agree with each other
/// the way the SDK's own entries require, so a caller cannot relabel raw inputs
/// as verified facts or edit one afterwards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustFacts {
    protocol_version: ProtocolVersion,
    author: AuthorFact,
    device: DeviceFact,
    permission: PermissionFact,
    replay_identity: ReplayIdentity,
}

impl TrustFacts {
    #[must_use]
    pub const fn protocol_version(&self) -> &ProtocolVersion {
        &self.protocol_version
    }

    #[must_use]
    pub const fn author(&self) -> AuthorFact {
        self.author
    }

    #[must_use]
    pub const fn device(&self) -> DeviceFact {
        self.device
    }

    #[must_use]
    pub const fn permission(&self) -> PermissionFact {
        self.permission
    }

    #[must_use]
    pub const fn replay_identity(&self) -> &ReplayIdentity {
        &self.replay_identity
    }

    /// Facts of one handshake the SDK accepted, read from the packet it accepted
    /// and the accept it produced.
    ///
    /// # Refusals
    ///
    /// [`InboundRefusal::UnboundUnit`] when the two values could not have come
    /// out of one accepted handshake, or when the packet names a line this
    /// client does not accept. The checks repeat the equalities
    /// `Endpoint::accept_first_packet` itself requires before it produces an
    /// accept (`src/endpoint/mod.rs:534-660`): the accept binds the packet's
    /// initiator authority digest, its pair sequence, and the responder identity
    /// the packet addressed, and both the packet and the accept must name the
    /// verified line. They add no protocol policy of their own, and they cannot
    /// authenticate anything — only the SDK verifies signatures.
    fn of_accepted_handshake(
        version: ProtocolVersion,
        packet: &FirstPacket,
        accept: &SessionAccept,
    ) -> Result<Self, InboundRefusal> {
        let bound = accept.initiator_user_authority_state_digest
            == packet.initiator_user_authority_state_digest
            && accept.pair_sequence == packet.prekey.pair_sequence
            && accept.responder_identity_state_digest == packet.responder_identity_state_digest
            && accept.responder_user_authority_state_digest
                == packet.responder_user_authority_state_digest
            && packet.protocol_line_id == version.protocol_line_id()
            && packet.protection_profile_id == version.protection_profile_id();
        if !bound {
            return Err(InboundRefusal::UnboundUnit);
        }
        Ok(Self {
            protocol_version: version,
            author: AuthorFact::of_accepted_handshake(packet),
            device: DeviceFact::of_accepted_handshake(packet),
            permission: PermissionFact::HandshakeAuthenticated,
            replay_identity: ReplayIdentity::of_accepted_handshake(accept),
        })
    }

    /// These established facts carried onto one later inbound record, which has
    /// its own replay identity.
    ///
    /// Only [`InboundSession::receive_record`] uses this, and only after the SDK
    /// decrypted and durably committed that exact record, so the returned facts
    /// still name the one handshake the SDK authenticated and never a caller's
    /// claim about the session.
    fn with_record(&self, pending: PendingId) -> Self {
        Self {
            protocol_version: self.protocol_version.clone(),
            author: self.author,
            device: self.device,
            permission: self.permission,
            replay_identity: ReplayIdentity::of_record(pending),
        }
    }
}

/// One refused inbound verification.
///
/// The SDK's bounded cause is carried verbatim; it never includes input bytes,
/// payloads, secrets, or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundRefusal {
    /// The Protocol Line this unit names is not the one this client accepts.
    /// The refusal is scoped to this call; nothing established is affected.
    Version(VersionRefusal),
    /// `ErrorCode::AuthenticationFailed`: the SDK could not authenticate.
    Authentication(Error),
    /// `ErrorCode::AuthorizationFailed`: the unit is authenticated but not
    /// authorized, which is also how a revoked or displaced device is refused.
    Authorization(Error),
    /// The supplied protocol values do not describe one verified unit, so
    /// recording them would report a verification that never happened.
    ///
    /// This is a coherence precondition only. The client checks that the values
    /// agree with each other exactly as the SDK's own entries require them to;
    /// it never stands in for the SDK's signature verification, which needs the
    /// gated authority artifact.
    UnboundUnit,
    /// Every other SDK refusal, carried unchanged.
    Sdk(Error),
}

impl InboundRefusal {
    #[must_use]
    pub const fn of(cause: Error) -> Self {
        match cause.code {
            ErrorCode::AuthenticationFailed => Self::Authentication(cause),
            ErrorCode::AuthorizationFailed => Self::Authorization(cause),
            _ => Self::Sdk(cause),
        }
    }

    /// Stable class of this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Version(cause) => cause.code(),
            Self::Authentication(_) => "authentication_failed",
            Self::Authorization(_) => "authorization_failed",
            Self::UnboundUnit => "unit_not_bound",
            Self::Sdk(_) => "protocol_refusal",
        }
    }

    /// The bounded SDK cause, when the SDK refused the unit itself.
    #[must_use]
    pub const fn cause(self) -> Option<Error> {
        match self {
            Self::Authentication(cause) | Self::Authorization(cause) | Self::Sdk(cause) => {
                Some(cause)
            }
            Self::UnboundUnit | Self::Version(_) => None,
        }
    }
}

impl core::fmt::Display for InboundRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.cause() {
            Some(cause) => write!(formatter, "{}: {cause}", self.code()),
            None => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for InboundRefusal {}

/// The client's consumer of the pinned LicoArc endpoint SDK.
///
/// It holds exactly one thing: the version this build accepts. Constructing it
/// initializes no custody backend, starts no listener, and touches no network,
/// so a build without the optional pairing package stays inert.
#[derive(Clone, Copy, Debug, Default)]
pub struct EndpointConsumer {
    accepted: AcceptedVersion,
}

impl EndpointConsumer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accepted: AcceptedVersion::fixed(),
        }
    }

    #[must_use]
    pub const fn accepted(&self) -> AcceptedVersion {
        self.accepted
    }

    /// Accepts one verified Protocol Line, or refuses that call only.
    pub fn check_line(
        &self,
        line: &VerifiedProtocolLine,
    ) -> Result<ProtocolVersion, VersionRefusal> {
        let version = ProtocolVersion::of(line);
        self.accepted.check(&version)?;
        Ok(version)
    }

    /// Resolves the peer's identity through the SDK's own trust entry.
    ///
    /// `TrustedIdentity::resolve` compares every identity key against the
    /// caller-owned trust facts for the verified line and refuses any mismatch
    /// (`src/endpoint/mod.rs:69-108`).
    pub fn trust_peer(
        &self,
        line: &VerifiedProtocolLine,
        trust: &impl TrustFactsPort,
        identity: &IdentityPublic,
    ) -> Result<TrustedIdentity, InboundRefusal> {
        self.check_line(line).map_err(InboundRefusal::Version)?;
        TrustedIdentity::resolve(line, trust, identity.clone()).map_err(InboundRefusal::of)
    }

    /// Consume a responder only after the SDK authenticates and commits this
    /// handshake. The returned session retains that exact endpoint, so later
    /// records cannot borrow another endpoint's author or replay identity.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_handshake<P, C, S>(
        &self,
        mut endpoint: licoarc::endpoint::Endpoint<licoarc::endpoint::Responder, P, C, S>,
        initiator: &TrustedIdentity,
        responder: &IdentityPublic,
        responder_authority: [u8; 32],
        packet: &FirstPacket,
        clock: &impl licoarc::state::Clock,
    ) -> Result<(InboundSession<P, C, S>, SessionAccept), InboundRefusal>
    where
        P: licoarc::provider::Provider,
        C: licoarc::state::KeyCustody,
        S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
    {
        let version = ProtocolVersion::restored(
            self.accepted.wire_id(),
            self.accepted.generation(),
            packet.protocol_line_id,
            packet.protection_profile_id,
        );
        self.accepted
            .check(&version)
            .map_err(InboundRefusal::Version)?;
        let accept = endpoint
            .accept_first_packet(initiator, responder, responder_authority, packet, clock)
            .map_err(InboundRefusal::of)?;
        let facts = TrustFacts::of_accepted_handshake(version, packet, &accept)?;
        Ok((InboundSession { endpoint, facts }, accept))
    }

    /// Delegate roster admission and active-device enforcement to the fixed SDK.
    /// Inputs are caller-owned authenticated session facts, not message claims.
    pub fn admit_authority<
        P: licoarc::provider::DigestProvider + licoarc::provider::SignatureProvider,
    >(
        &self,
        provider: &P,
        accepted: Option<&licoarc::identity::AcceptedUserAuthority>,
        session: &licoarc::identity::AuthenticatedAuthoritySession,
        state: &serde_json::Value,
        endpoints: &[licoarc::identity::EndpointStateKeys],
    ) -> Result<licoarc::identity::AcceptedUserAuthority, InboundRefusal> {
        licoarc::identity::admit_protected_authority_payload(
            provider,
            accepted,
            session,
            state,
            self.accepted.protocol_line_id(),
            endpoints,
        )
        .map_err(InboundRefusal::of)
    }

    /// Records that the peer endpoint accepted the logical message (delivery).
    ///
    /// The SDK applies the confirmation only on an authenticated session whose
    /// authorized sender is the expected endpoint, and only at
    /// `ConfirmationStage::EndpointAccepted` (`src/reliable.rs:71-163`).
    pub fn note_delivery(
        &self,
        current: FinalityState,
        logical_message_id: [u8; 16],
        confirmation: &EndpointConfirmation,
        session: &AuthorizedSession,
        attachment_complete: bool,
    ) -> Result<FinalityState, InboundRefusal> {
        apply_endpoint_confirmation(
            current,
            logical_message_id,
            confirmation,
            session,
            None,
            attachment_complete,
        )
        .map_err(InboundRefusal::of)
    }

    /// Records that the peer completed the task (acceptance).
    ///
    /// The SDK grants this only at `ConfirmationStage::EffectCompleted` with a
    /// successful outcome and the expected result digest; delivery alone never
    /// reaches it (`src/reliable.rs:121-150`).
    pub fn note_acceptance(
        &self,
        current: FinalityState,
        logical_message_id: [u8; 16],
        confirmation: &EndpointConfirmation,
        session: &AuthorizedSession,
        expected_result_digest: [u8; 32],
        attachment_complete: bool,
    ) -> Result<FinalityState, InboundRefusal> {
        apply_endpoint_confirmation(
            current,
            logical_message_id,
            confirmation,
            session,
            Some(expected_result_digest),
            attachment_complete,
        )
        .map_err(InboundRefusal::of)
    }

    /// Advances the intent's reliable-exchange state (`ReliableState::retry`,
    /// `src/reliable.rs:184-219`).
    ///
    /// A completed or failed intent cannot be retried, and a repeated route may
    /// only resend the identical protected packet.
    pub fn note_exchange(
        &self,
        current: &ReliableState,
        route: [u8; 32],
        intent: [u8; 32],
        protected_packet: [u8; 32],
    ) -> Result<ReliableState, InboundRefusal> {
        current
            .retry(route, intent, protected_packet)
            .map_err(InboundRefusal::of)
    }
}

/// An SDK-authenticated inbound session. No public constructor accepts raw
/// facts, and the endpoint cannot be replaced independently of its identity.
pub struct InboundSession<P, C, S> {
    endpoint: licoarc::endpoint::Endpoint<licoarc::endpoint::Responder, P, C, S>,
    facts: TrustFacts,
}

impl<P, C, S> InboundSession<P, C, S>
where
    P: licoarc::provider::Provider,
    C: licoarc::state::KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
{
    pub fn facts(&self) -> &TrustFacts {
        &self.facts
    }

    /// Verify and durably commit one inbound protected record through the SDK,
    /// then report the facts of that exact record.
    ///
    /// The returned [`PendingId`] is the SDK's content-derived identity of the
    /// committed record; callers release its plaintext and settle it with that
    /// id. A replayed or stale record is refused by the SDK itself
    /// (`src/protection/mod.rs:488`).
    ///
    /// Handshake authentication is not a command grant: consumers must recheck
    /// the current roster and application admission independently for every new
    /// effect a record asks for.
    pub fn receive_record(
        &mut self,
        packet: &[u8],
        fresh_private: Option<licoarc::state::StagedSecretHandle<licoarc::state::X25519Private>>,
    ) -> Result<(TrustFacts, PendingId), InboundRefusal> {
        let pending = self
            .endpoint
            .receive_record(packet, fresh_private)
            .map_err(InboundRefusal::of)?;
        Ok((self.facts.with_record(pending), pending))
    }

    /// The session's endpoint for outbound work — `send_record`,
    /// `dispatch_pending`, `release_pending_plaintext`, `retry_record`,
    /// `delete_session`.
    ///
    /// The session stays the endpoint's single owner; this borrow never lets a
    /// caller replace the endpoint the facts name.
    pub fn endpoint_mut(
        &mut self,
    ) -> &mut licoarc::endpoint::Endpoint<licoarc::endpoint::Responder, P, C, S> {
        &mut self.endpoint
    }

    /// Return the caller-owned store without discarding committed pending work.
    pub fn into_store(self) -> S {
        self.endpoint.into_store()
    }
}

#[cfg(test)]
mod tests {
    use licoarc::reliable::{
        ConfirmationOutcome, ConfirmationStage, EndpointConfirmation, FinalityState,
    };
    use licoarc::state::PendingId;

    use super::{
        AuthorFact, DeviceFact, EndpointConsumer, InboundRefusal, PermissionFact, ReplayIdentity,
        TrustFacts,
    };
    use crate::version::{ACCEPTED_GENERATION, ACCEPTED_WIRE_ID, ProtocolVersion, VersionRefusal};

    /// The client's own record of an accepted session. Every field here is a
    /// caller-supplied fact; the SDK re-checks all of them on every unit.
    fn session(
        authenticated: bool,
        authorized: bool,
        sender: [u8; 32],
    ) -> super::AuthorizedSession {
        super::AuthorizedSession {
            session_id: [7; 16],
            sender_endpoint: sender,
            expected_sender_endpoint: sender,
            authenticated,
            sender_authorized: authorized,
        }
    }

    fn confirmation(
        stage: ConfirmationStage,
        outcome: ConfirmationOutcome,
        ids: Vec<[u8; 16]>,
        digest: Option<[u8; 32]>,
    ) -> EndpointConfirmation {
        EndpointConfirmation {
            confirmation_id: [3; 16],
            confirmed_message_ids: ids,
            stage,
            outcome,
            failure_code: None,
            result_digest: digest,
        }
    }

    fn version() -> ProtocolVersion {
        ProtocolVersion::restored(ACCEPTED_WIRE_ID, ACCEPTED_GENERATION, [1; 32], [2; 32])
    }

    #[test]
    fn delivery_is_not_task_acceptance() {
        let consumer = EndpointConsumer::new();
        let peer = session(true, true, [5; 32]);
        let delivered = confirmation(
            ConfirmationStage::EndpointAccepted,
            ConfirmationOutcome::Succeeded,
            vec![[4; 16], [5; 16]],
            None,
        );

        // Delivery: the peer endpoint accepted the logical message.
        assert_eq!(
            consumer.note_delivery(FinalityState::Pending, [5; 16], &delivered, &peer, true),
            Ok(FinalityState::Accepted)
        );

        // The same delivered unit through the acceptance call is still only
        // delivery: an endpoint-accepted confirmation can never complete a task,
        // so the result stays `Accepted` and never becomes `Completed`.
        assert_eq!(
            consumer.note_acceptance(
                FinalityState::Pending,
                [5; 16],
                &delivered,
                &peer,
                [9; 32],
                true
            ),
            Ok(FinalityState::Accepted)
        );

        // A delivery confirmation that claims an effect result is refused.
        assert_eq!(
            consumer
                .note_delivery(
                    FinalityState::Pending,
                    [5; 16],
                    &confirmation(
                        ConfirmationStage::EndpointAccepted,
                        ConfirmationOutcome::Succeeded,
                        vec![[5; 16]],
                        Some([9; 32]),
                    ),
                    &peer,
                    true,
                )
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "an endpoint-accepted unit carries no effect result"
        );

        let completed = confirmation(
            ConfirmationStage::EffectCompleted,
            ConfirmationOutcome::Succeeded,
            vec![[5; 16]],
            Some([9; 32]),
        );

        // Acceptance is only reachable through the acceptance call, and only
        // with the expected result digest.
        assert_eq!(
            consumer
                .note_delivery(FinalityState::Accepted, [5; 16], &completed, &peer, true)
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "the delivery call cannot complete a task"
        );
        assert_eq!(
            consumer.note_acceptance(
                FinalityState::Accepted,
                [5; 16],
                &completed,
                &peer,
                [9; 32],
                true
            ),
            Ok(FinalityState::Completed)
        );
        assert_eq!(
            consumer
                .note_acceptance(
                    FinalityState::Accepted,
                    [5; 16],
                    &completed,
                    &peer,
                    [8; 32],
                    true
                )
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "a completed effect must carry the expected result digest"
        );
    }

    #[test]
    fn a_message_identity_never_becomes_authority() {
        let consumer = EndpointConsumer::new();
        let delivered = confirmation(
            ConfirmationStage::EndpointAccepted,
            ConfirmationOutcome::Succeeded,
            vec![[5; 16]],
            None,
        );

        assert_eq!(
            consumer
                .note_delivery(
                    FinalityState::Pending,
                    [5; 16],
                    &delivered,
                    &session(false, true, [5; 32]),
                    true
                )
                .unwrap_err(),
            InboundRefusal::Authentication(licoarc::error::Error::terminal(
                licoarc::error::ErrorCode::AuthenticationFailed,
                licoarc::error::Stage::Validation
            )),
            "an unauthenticated session refuses the unit"
        );
        assert_eq!(
            consumer
                .note_delivery(
                    FinalityState::Pending,
                    [5; 16],
                    &delivered,
                    &session(true, false, [5; 32]),
                    true
                )
                .unwrap_err()
                .code(),
            "authorization_failed",
            "the session, not the message, decides authorization"
        );

        let mut displaced = session(true, true, [5; 32]);
        displaced.expected_sender_endpoint = [6; 32];
        assert_eq!(
            consumer
                .note_delivery(
                    FinalityState::Pending,
                    [5; 16],
                    &delivered,
                    &displaced,
                    true
                )
                .unwrap_err()
                .code(),
            "authorization_failed",
            "a sender that is not the expected endpoint is refused"
        );
    }

    #[test]
    fn network_author_order_is_the_sdks_own_and_not_arrival_order() {
        let consumer = EndpointConsumer::new();
        let peer = session(true, true, [5; 32]);

        for ids in [vec![[5; 16], [5; 16]], vec![[6; 16], [5; 16]]] {
            let unordered = confirmation(
                ConfirmationStage::EndpointAccepted,
                ConfirmationOutcome::Succeeded,
                ids,
                None,
            );
            assert_eq!(
                consumer
                    .note_delivery(FinalityState::Pending, [5; 16], &unordered, &peer, true)
                    .unwrap_err()
                    .code(),
                "protocol_refusal",
                "confirmed ids must be strictly increasing"
            );
        }

        let ordered = confirmation(
            ConfirmationStage::EndpointAccepted,
            ConfirmationOutcome::Succeeded,
            vec![[4; 16], [5; 16]],
            None,
        );
        assert_eq!(
            consumer
                .note_delivery(FinalityState::Pending, [3; 16], &ordered, &peer, true)
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "a logical id the confirmation does not name cannot be accepted"
        );
    }

    #[test]
    fn reliable_exchange_is_reported_on_its_own() {
        let consumer = EndpointConsumer::new();
        let state = licoarc::reliable::ReliableState {
            intent_digest: [1; 32],
            route_digest: [2; 32],
            protected_packet_digest: [3; 32],
            retries: 0,
            migrations: 0,
            transitions: 0,
            outcome: licoarc::reliable::Outcome::Pending,
        };

        let retried = consumer
            .note_exchange(&state, [2; 32], [1; 32], [3; 32])
            .unwrap();
        assert_eq!(retried.retries, 1);
        assert_eq!(retried.outcome, licoarc::reliable::Outcome::Pending);

        assert_eq!(
            consumer
                .note_exchange(&state, [2; 32], [1; 32], [4; 32])
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "the same route may only resend the identical protected packet"
        );

        let completed = licoarc::reliable::ReliableState {
            outcome: licoarc::reliable::Outcome::EffectCompleted,
            ..state
        };
        assert_eq!(
            consumer
                .note_exchange(&completed, [2; 32], [1; 32], [3; 32])
                .unwrap_err()
                .code(),
            "protocol_refusal",
            "a completed intent is never retried"
        );
    }

    /// A structurally valid handshake packet and accept.
    ///
    /// They are not signature-verified: authenticity comes from the SDK's
    /// `accept_first_packet`, which needs the gated authority artifact. Only the
    /// fact-mapping below is exercised here.
    fn synthetic_handshake() -> (super::FirstPacket, super::SessionAccept) {
        (
            super::FirstPacket {
                protocol_line_id: [1; 32],
                protection_profile_id: [2; 32],
                initiator_identity_state_digest: [11; 32],
                initiator_user_authority_state_digest: [12; 32],
                responder_identity_state_digest: [13; 32],
                responder_user_authority_state_digest: [14; 32],
                prekey: licoarc::endpoint::PrekeyBundle {
                    protocol_line_id: [1; 32],
                    protection_profile_id: [2; 32],
                    responder_identity_state_digest: [13; 32],
                    ed25519_key_id: [15; 32],
                    ml_dsa_65_key_id: [16; 32],
                    pair_sequence: 1,
                    x25519_public: [17; 32],
                    ml_kem_768_public: vec![18; 4],
                    valid_from: 10,
                    valid_until: 20,
                    ed25519_signature: [19; 64],
                    ml_dsa_65_signature: vec![20; 4],
                },
                initiator_x25519_public: [21; 32],
                ml_kem_768_ciphertext: vec![22; 4],
                initiator_ed25519_key_id: [23; 32],
                initiator_ml_dsa_65_key_id: [24; 32],
                initiator_ed25519_signature: [25; 64],
                initiator_ml_dsa_65_signature: vec![26; 4],
                client_confirm_ciphertext: [27; 36],
                client_confirm_tag: [28; 16],
            },
            super::SessionAccept {
                transcript_digest: [31; 32],
                session_context_digest: [32; 32],
                initiator_user_authority_state_digest: [12; 32],
                responder_identity_state_digest: [13; 32],
                responder_user_authority_state_digest: [14; 32],
                pair_sequence: 1,
                mac: [33; 32],
            },
        )
    }

    #[test]
    fn an_accepted_handshake_records_every_fact_it_binds() {
        let (packet, accept) = synthetic_handshake();
        let facts = TrustFacts::of_accepted_handshake(version(), &packet, &accept).unwrap();

        assert_eq!(facts.protocol_version, version());
        assert_eq!(
            facts.author,
            AuthorFact {
                user_authority_state_digest: [12; 32]
            }
        );
        assert_eq!(
            facts.device,
            DeviceFact {
                identity_state_digest: [11; 32],
                ed25519_key_id: [23; 32],
                ml_dsa_65_key_id: [24; 32],
            }
        );
        assert_eq!(facts.permission, PermissionFact::HandshakeAuthenticated);
        assert_eq!(
            facts.replay_identity,
            ReplayIdentity::Handshake {
                transcript_digest: [31; 32],
                session_context_digest: [32; 32],
            }
        );

        // A packet from another device, or an accept from another transcript, is
        // a different trusted result.
        let mut other_device = packet;
        other_device.initiator_identity_state_digest = [99; 32];
        assert_ne!(
            TrustFacts::of_accepted_handshake(version(), &other_device, &accept)
                .unwrap()
                .device,
            facts.device
        );
    }

    #[test]
    fn one_record_keeps_the_established_facts_and_takes_its_own_identity() {
        let established = TrustFacts {
            protocol_version: version(),
            author: AuthorFact {
                user_authority_state_digest: [11; 32],
            },
            device: DeviceFact {
                identity_state_digest: [12; 32],
                ed25519_key_id: [13; 32],
                ml_dsa_65_key_id: [14; 32],
            },
            permission: PermissionFact::HandshakeAuthenticated,
            replay_identity: ReplayIdentity::Handshake {
                transcript_digest: [15; 32],
                session_context_digest: [16; 32],
            },
        };

        let record = established.with_record(PendingId::from_token(9));
        assert_eq!(record.author, established.author);
        assert_eq!(record.device, established.device);
        assert_eq!(record.protocol_version, established.protocol_version);
        assert_eq!(
            record.replay_identity,
            ReplayIdentity::ProtectedRecord {
                pending: PendingId::from_token(9)
            }
        );
        assert_eq!(
            record.permission, established.permission,
            "a record carries the established handshake's permission fact, not a \
             caller-supplied session claim"
        );
        assert_ne!(record.replay_identity, established.replay_identity);
    }

    #[test]
    fn the_inbound_schema_is_the_sdks_decoded_message_and_not_raw_wire() {
        use std::collections::BTreeMap;

        use licoarc::messaging::{Message, MessageKind};

        // Raw bytes are not the client's schema. Only the SDK's closed decoder
        // accepts a message, and it refuses anything outside its own
        // representation (`Message::decode`, `src/messaging.rs:136-140`).
        assert!(Message::decode(b"raw wire is not a message").is_err());

        let mut message = Message {
            id: [1; 16],
            kind: MessageKind::Event,
            relates_to: None,
            content_type: 1,
            payload: b"opaque".to_vec(),
            extensions: BTreeMap::new(),
            critical: Vec::new(),
            chunk_index: None,
            chunk_final: None,
            attachment_id: None,
            attachments: Vec::new(),
        };
        assert_eq!(message.validate(), Ok(()));

        // An unknown critical extension is refused rather than ignored, so a peer
        // cannot smuggle a field this client does not understand
        // (`src/messaging.rs:79-81`).
        message.critical = vec![7];
        assert_eq!(
            message.validate().unwrap_err().code,
            licoarc::error::ErrorCode::UnknownField
        );
    }

    #[test]
    fn a_refused_line_is_a_call_scoped_version_class() {
        let refusal = InboundRefusal::Version(VersionRefusal::ProtocolLine);
        assert_eq!(refusal.code(), "unsupported_protocol_line");
        assert_eq!(refusal.cause(), None);
        assert_eq!(refusal.to_string(), "unsupported_protocol_line");
    }

    #[test]
    fn an_unauthenticated_authority_session_never_admits_a_roster() {
        // The SDK entry owns this decision; the client only supplies the
        // accepted line id and the caller-owned authenticated-session facts.
        let consumer = EndpointConsumer::new();
        let session = licoarc::identity::AuthenticatedAuthoritySession {
            authenticated: false,
            authority_state_digest: [0; 32],
            endpoint_identity_ref: [0; 32],
            identity_state_digest: [0; 32],
        };
        let refusal = consumer
            .admit_authority(
                &licoarc::provider::RustCryptoProvider,
                None,
                &session,
                &serde_json::json!({}),
                &[],
            )
            .expect_err("an unauthenticated session cannot admit a roster");
        assert_eq!(refusal.code(), "authentication_failed");
        assert_eq!(
            refusal.cause().unwrap().code,
            licoarc::error::ErrorCode::AuthenticationFailed
        );
    }

    #[test]
    fn an_inbound_refusal_keeps_the_sdk_cause_and_a_stable_class() {
        let refusal = InboundRefusal::of(licoarc::error::Error::terminal(
            licoarc::error::ErrorCode::PrekeyConsumed,
            licoarc::error::Stage::Validation,
        ));
        assert_eq!(refusal.code(), "protocol_refusal");
        assert_eq!(
            refusal.cause().unwrap().code,
            licoarc::error::ErrorCode::PrekeyConsumed
        );
        assert!(refusal.to_string().starts_with("protocol_refusal: "));
        assert!(!refusal.cause().unwrap().retryable);
    }
}
