//! The verified-unit facts this boundary consumes.
//!
//! Verification belongs to the pinned SDK, which this domain reaches only
//! through the crate's own SDK boundary. This boundary verifies nothing and
//! decides no protocol outcome: it consumes one [`VerifiedUnit`] value that the
//! SDK boundary produced, and records what that value says. A value of
//! [`PeerMessage`](super::PeerMessage) therefore always names a unit some SDK
//! verification entry actually produced.
//!
//! # Producer
//!
//! The SDK boundary owns the producer. Its entries are
//! `crate::EndpointConsumer::accept_handshake` (which yields
//! an `InboundSession`) and `InboundSession::receive_record` (which yields the
//! `TrustFacts` of one committed protected record). Nothing here re-implements,
//! previews, or second-guesses them: the trait below is only the shape this
//! domain reads, and the adapter below is this domain's one implementation of it
//! for the boundary's own fact value, so no second facts type has to be kept in
//! step.
//!
//! # Plug-in point
//!
//! [`VerifiedUnit`] is implemented for `crate::TrustFacts`:
//!
//! * `verified_author` reads `TrustFacts::author().user_authority_state_digest`;
//! * `verified_device` reads `TrustFacts::device()`;
//! * `verified_record` reads `TrustFacts::replay_identity()` and chooses
//!   `RecordKey = crate::ReplayIdentity`, answering `None`
//!   for the handshake variant so an accepted handshake can never be admitted
//!   as a message unit.
//!
//! That implementation is the only one: callers and fixtures consume it instead
//! of declaring their own copy of the boundary's facts.

/// The verified device identity of one inbound unit.
///
/// Every field is an SDK identity reference, never a local display value and
/// never a permission. A fabricated value still admits nothing: admission
/// resolves the author and the device against the host's own binding table and
/// the existing conversation's active membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDevice {
    identity_state_digest: [u8; 32],
    ed25519_key_id: [u8; 32],
    ml_dsa_65_key_id: [u8; 32],
}

impl VerifiedDevice {
    /// Carries the device identity references an SDK verification entry bound.
    ///
    /// Only an SDK boundary implementation of [`VerifiedUnit`] calls this.
    #[must_use]
    pub const fn new(
        identity_state_digest: [u8; 32],
        ed25519_key_id: [u8; 32],
        ml_dsa_65_key_id: [u8; 32],
    ) -> Self {
        Self {
            identity_state_digest,
            ed25519_key_id,
            ml_dsa_65_key_id,
        }
    }

    #[must_use]
    pub const fn identity_state_digest(self) -> [u8; 32] {
        self.identity_state_digest
    }

    #[must_use]
    pub const fn ed25519_key_id(self) -> [u8; 32] {
        self.ed25519_key_id
    }

    #[must_use]
    pub const fn ml_dsa_65_key_id(self) -> [u8; 32] {
        self.ml_dsa_65_key_id
    }
}

/// What an SDK verification entry established about one inbound unit.
///
/// The implementing type is the SDK boundary's own fact value. The associated
/// [`VerifiedUnit::RecordKey`] is that owner's replay identity of a committed
/// protected record; this boundary only compares it, so it never interprets the
/// SDK's token and never mints one.
pub trait VerifiedUnit {
    /// The SDK's own identity of one committed protected record.
    ///
    /// Equality is the whole contract: a byte-identical replay of one unit
    /// carries an equal key, and two different units do not.
    type RecordKey: Clone + Eq;

    /// The user-authority state digest the accepted session bound.
    fn verified_author(&self) -> [u8; 32];

    /// The identity state digest and key ids the accepted session bound.
    fn verified_device(&self) -> VerifiedDevice;

    /// The replay identity of one committed protected record.
    ///
    /// `None` when the value describes an accepted handshake: a handshake is
    /// not a message unit, so there is nothing a message could be admitted
    /// under.
    fn verified_record(&self) -> Option<Self::RecordKey>;
}

/// The pinned SDK's verified facts are the production answer for this port.
///
/// The trait is generic over the record key precisely so the SDK's own replay
/// identity is carried through unchanged: nothing here re-derives, hashes or
/// re-encodes it, and a handshake (which binds no record) answers `None`.
impl VerifiedUnit for crate::TrustFacts {
    type RecordKey = crate::ReplayIdentity;

    fn verified_author(&self) -> [u8; 32] {
        self.author().user_authority_state_digest
    }

    fn verified_device(&self) -> VerifiedDevice {
        let device = self.device();
        VerifiedDevice::new(
            device.identity_state_digest,
            device.ed25519_key_id,
            device.ml_dsa_65_key_id,
        )
    }

    fn verified_record(&self) -> Option<Self::RecordKey> {
        match self.replay_identity() {
            crate::ReplayIdentity::Handshake { .. } => None,
            crate::ReplayIdentity::ProtectedRecord { .. } => Some(self.replay_identity().clone()),
        }
    }
}
