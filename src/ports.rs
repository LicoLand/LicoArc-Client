//! Consumer-owned ports the client adapter must supply to the pinned LicoArc SDK.
//!
//! The consumer owns custody, persistence, time, and transport; the SDK owns
//! the protocol. These traits are the caller side of that split, reduced from
//! the caller-owned requirements the pinned `licoarc` SDK actually declares.
//! Every item cites the SDK source it mirrors (`src/...` paths inside the
//! `licoarc` package):
//!
//! | port | SDK requirement |
//! | --- | --- |
//! | [`KeyCustody`] | `state::KeyCustody`, `src/state/mod.rs` |
//! | [`AtomicState`] | `state::AtomicState`, `src/state/mod.rs` |
//! | [`Clock`] | `state::Clock`, `src/state/mod.rs` |
//! | [`Transport`] | `state::PacketCarrier` + `transport::TransportOutcome`, `src/state/mod.rs`, `src/transport.rs` |
//!
//! These are consumer-owned traits: no SDK type appears in their signature,
//! and [`crate::adapters`] is the composition point that satisfies both sides.
//! Nothing here re-implements protocol
//! policy: the SDK alone decides protocol outcomes, and a port only performs the
//! caller-owned operation it is asked for.
//!
//! The pairing and relay-control branches of the SDK's `transport` surface are
//! not part of this contract: the committed-packet send below is the only
//! carrier operation this client needs, so it initializes no pairing transport
//! state and starts no listener.

use core::fmt;

/// One definite, uncertain, or refused caller-owned operation.
///
/// The distinction is the one the SDK's own recovery logic turns on
/// (`Error::retryable`, `src/error.rs`): an uncertain outcome must re-drive
/// the same already-committed item, never a fresh one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortFailure {
    /// The operation definitely did not happen. The SDK maps this to a terminal
    /// `ProviderFailure` (`src/endpoint/mod.rs`).
    Unavailable,
    /// The operation may or may not have happened. The SDK maps this to a
    /// retryable commit failure (`src/endpoint/mod.rs`).
    Uncertain,
    /// The store's expected revision was not current, so nothing was applied.
    /// The SDK maps this to `Conflict` and then re-reads
    /// (`src/endpoint/mod.rs`).
    Conflict,
    /// A protocol bound would be exceeded. Mirrors `Revision::successor`
    /// (`src/state/mod.rs`).
    BoundExceeded,
}

impl PortFailure {
    /// Whether the caller must re-drive the same already-committed item.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Uncertain)
    }
}

impl fmt::Display for PortFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Unavailable => "unavailable",
            Self::Uncertain => "uncertain",
            Self::Conflict => "conflict",
            Self::BoundExceeded => "bound exceeded",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for PortFailure {}

/// Purpose of one custody object, mirroring the SDK's marker types
/// (`src/state/mod.rs`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CustodyPurpose {
    Ed25519Signing,
    MlDsa65Signing,
    X25519Private,
    MlKem768Private,
    MlKemEncapsulationEntropy,
}

/// Whether a custody object is tentative or adopted, mirroring the SDK's
/// `StagedSecretHandle`/`SecretHandle` split (`src/state/mod.rs`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CustodyLifecycle {
    Adopted,
    Staged,
}

/// One opaque custody reference: a non-secret token plus the purpose and
/// lifecycle the caller must re-check.
///
/// The SDK's marker types are erased when a handle crosses this boundary, so
/// purpose and lifecycle travel as values instead. An implementation must still
/// look the token up and verify its purpose, lifecycle, and permission for the
/// requested operation; the SDK requires exactly that of its own
/// implementations (`src/state/mod.rs`).
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CustodyHandle {
    token: u128,
    purpose: CustodyPurpose,
    lifecycle: CustodyLifecycle,
}

impl CustodyHandle {
    #[must_use]
    pub const fn adopted(token: u128, purpose: CustodyPurpose) -> Self {
        Self {
            token,
            purpose,
            lifecycle: CustodyLifecycle::Adopted,
        }
    }

    #[must_use]
    pub const fn staged(token: u128, purpose: CustodyPurpose) -> Self {
        Self {
            token,
            purpose,
            lifecycle: CustodyLifecycle::Staged,
        }
    }

    /// The non-secret token the caller's coupled state/custody backend keys on
    /// (`SecretHandle::custody_token`, `src/state/mod.rs`).
    #[must_use]
    pub const fn custody_token(self) -> u128 {
        self.token
    }

    #[must_use]
    pub const fn purpose(self) -> CustodyPurpose {
        self.purpose
    }

    #[must_use]
    pub const fn lifecycle(self) -> CustodyLifecycle {
        self.lifecycle
    }
}

impl fmt::Debug for CustodyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The SDK redacts handles the same way (`src/state/mod.rs`).
        formatter.write_str("CustodyHandle([REDACTED])")
    }
}

/// Largest integer the authority permits for persisted generations
/// (`src/state/mod.rs`).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// One monotonically increasing protocol-state generation
/// (`src/state/mod.rs`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// The generation as the plain integer it is.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// One generation a caller already holds as an integer.
    ///
    /// A store that keeps its generation in its own storage reads it back as a
    /// number; this is how that number re-enters the contract unchanged. It
    /// neither advances nor validates a generation, and the store still decides
    /// whether a commit may use it.
    #[must_use]
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }

    pub fn successor(self) -> Result<Self, PortFailure> {
        if self.0 >= MAX_SAFE_INTEGER {
            return Err(PortFailure::BoundExceeded);
        }
        Ok(Self(self.0 + 1))
    }
}

/// One handle adoption or deletion committed together with the snapshot
/// (`src/state/mod.rs`).
///
/// `Adopt` carries a staged `X25519Private` or `MlKem768Private` handle;
/// `Delete` carries an adopted handle of a deletable purpose. The protocol layer
/// emits nothing else, and an implementation must refuse any other pairing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyMutation {
    Adopt(CustodyHandle),
    Delete(CustodyHandle),
}

/// Content-opaque identity of one committed delivery unit
/// (`src/state/mod.rs`).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingId(u128);

impl PendingId {
    #[must_use]
    pub const fn from_token(token: u128) -> Self {
        Self(token)
    }

    /// The opaque token, for a backend that stores the identity itself.
    ///
    /// It is a reference to a committed unit, not authority to settle one: the
    /// store still has to find the item at that revision before removing it.
    #[must_use]
    pub const fn token(self) -> u128 {
        self.0
    }
}

impl fmt::Debug for PendingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingId([REDACTED])")
    }
}

/// The payload that crosses one post-commit boundary
/// (`src/state/mod.rs`). The protocol layer already bounded its length.
#[derive(Clone, Eq, PartialEq)]
pub enum PendingPayload {
    /// Outbound protected packet for [`Transport::submit`].
    Packet(Vec<u8>),
    /// Application effect.
    Effect(Vec<u8>),
    /// Inbound plaintext for the client's own receiver.
    Plaintext(Vec<u8>),
}

impl fmt::Debug for PendingPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingPayload([REDACTED])")
    }
}

/// One committed delivery unit that is durable until its boundary settles it
/// (`src/state/mod.rs`).
#[derive(Clone, Eq, PartialEq)]
pub struct PendingItem {
    id: PendingId,
    payload: PendingPayload,
}

impl PendingItem {
    #[must_use]
    pub const fn packet(id: PendingId, packet: Vec<u8>) -> Self {
        Self {
            id,
            payload: PendingPayload::Packet(packet),
        }
    }

    #[must_use]
    pub const fn effect(id: PendingId, effect: Vec<u8>) -> Self {
        Self {
            id,
            payload: PendingPayload::Effect(effect),
        }
    }

    #[must_use]
    pub const fn plaintext(id: PendingId, plaintext: Vec<u8>) -> Self {
        Self {
            id,
            payload: PendingPayload::Plaintext(plaintext),
        }
    }

    #[must_use]
    pub const fn id(&self) -> PendingId {
        self.id
    }

    #[must_use]
    pub const fn payload(&self) -> &PendingPayload {
        &self.payload
    }
}

impl fmt::Debug for PendingItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingItem")
            .field("id", &self.id)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// One complete protocol snapshot at one revision, with the delivery units that
/// were committed with it (`src/state/mod.rs`).
///
/// `I` is one committed delivery unit. The protocol layer owns that type and
/// hands its own values across this boundary, so the adapter that satisfies a
/// protocol SDK never has to rebuild an item it did not create: the snapshot
/// carries the protocol layer's item values through unchanged.
#[derive(Clone, Eq, PartialEq)]
pub struct Versioned<S, I = PendingItem> {
    revision: Revision,
    state: S,
    pending: Vec<I>,
}

impl<S, I> Versioned<S, I> {
    #[must_use]
    pub const fn initial(state: S) -> Self {
        Self {
            revision: Revision::initial(),
            state,
            pending: Vec::new(),
        }
    }

    /// Presents one already-committed snapshot at the revision it was committed
    /// at, together with the delivery units committed with it.
    ///
    /// This is how a coupled port hands its own durable value to a consumer that
    /// reads the same protocol-state shape. The revision and the pending items
    /// are the ones the store committed, not values a caller may choose: it
    /// confers no authority, because the next commit still has to name this
    /// exact revision as its expected one and the store alone decides that.
    #[must_use]
    pub const fn restored(revision: Revision, state: S, pending: Vec<I>) -> Self {
        Self {
            revision,
            state,
            pending,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    #[must_use]
    pub fn pending(&self) -> &[I] {
        &self.pending
    }
}

impl<S, I> fmt::Debug for Versioned<S, I>
where
    I: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Versioned")
            .field("revision", &self.revision)
            .field("state", &"[REDACTED]")
            .field("pending", &self.pending)
            .finish()
    }
}

/// The complete next snapshot plus every custody mutation it requires
/// (`src/state/mod.rs`).
///
/// A store applies it old-or-new: the snapshot, the adoptions, and the deletions
/// are one transaction that advances exactly one revision, or applies nothing.
#[derive(Clone, Eq, PartialEq)]
pub struct StateCommit<S, I = PendingItem> {
    next_state: S,
    key_mutations: Vec<KeyMutation>,
    pending: Vec<I>,
}

impl<S, I> StateCommit<S, I> {
    #[must_use]
    pub const fn new(next_state: S, key_mutations: Vec<KeyMutation>, pending: Vec<I>) -> Self {
        Self {
            next_state,
            key_mutations,
            pending,
        }
    }

    #[must_use]
    pub const fn next_state(&self) -> &S {
        &self.next_state
    }

    #[must_use]
    pub fn key_mutations(&self) -> &[KeyMutation] {
        &self.key_mutations
    }

    #[must_use]
    pub fn pending(&self) -> &[I] {
        &self.pending
    }

    /// Converts a store-validated commit into its next complete snapshot
    /// (`src/state/mod.rs`).
    pub fn into_versioned(self, expected: Revision) -> Result<Versioned<S, I>, PortFailure> {
        Ok(Versioned {
            revision: expected.successor()?,
            state: self.next_state,
            pending: self.pending,
        })
    }
}

impl<S, I> fmt::Debug for StateCommit<S, I>
where
    I: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateCommit")
            .field("next_state", &"[REDACTED]")
            .field("key_mutations", &self.key_mutations)
            .field("pending", &self.pending)
            .finish()
    }
}

/// Performs only the fixed private operations the protocol needs
/// (`src/state/mod.rs`).
///
/// Implementations must look up every token in caller-owned custody and verify
/// its purpose and lifecycle for the requested operation. The handle's own
/// values are not proof that a token is authorized.
pub trait KeyCustody {
    fn ed25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure>;
    fn ed25519_sign(&self, handle: CustodyHandle, message: &[u8]) -> Result<[u8; 64], PortFailure>;
    fn ml_dsa_65_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure>;
    fn ml_dsa_65_sign(&self, handle: CustodyHandle, message: &[u8])
    -> Result<Vec<u8>, PortFailure>;
    fn x25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure>;
    fn x25519(&self, handle: CustodyHandle, public: &[u8; 32]) -> Result<[u8; 32], PortFailure>;
    fn ml_kem_768_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure>;
    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: CustodyHandle,
    ) -> Result<(Vec<u8>, [u8; 32]), PortFailure>;
    fn ml_kem_768_decapsulate(
        &self,
        handle: CustodyHandle,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], PortFailure>;
    /// Makes a definitely uncommitted tentative object logically unreachable.
    /// This does not claim physical erasure of provider media
    /// (`src/state/mod.rs`).
    fn abort_x25519(&mut self, staged: CustodyHandle);
    /// Makes a definitely uncommitted tentative object logically unreachable.
    /// This does not claim physical erasure of provider media.
    fn abort_ml_kem_768(&mut self, staged: CustodyHandle);
}

/// One caller-owned durable protocol store (`src/state/mod.rs`).
///
/// `compare_and_swap` applies the complete snapshot and all handle
/// adoptions/deletions in one transaction owned by the caller's coupled
/// state/custody backend and advances exactly one revision, or applies nothing.
/// A backend unable to provide that old-or-new result does not satisfy this
/// contract.
///
/// `Pending` is one committed delivery unit. The protocol layer owns that type:
/// it creates every item when it commits, and hands the same value back when it
/// re-drives or settles one. A store therefore persists the protocol layer's own
/// items instead of a mirrored copy, so nothing has to be rebuilt on the way
/// back into the protocol.
pub trait AtomicState {
    /// The protocol snapshot the protocol layer evolves. It stays opaque here.
    type Snapshot;

    /// One committed delivery unit, in the protocol layer's own vocabulary.
    type Pending;

    fn load(&self) -> Result<Versioned<Self::Snapshot, Self::Pending>, PortFailure>;

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: StateCommit<Self::Snapshot, Self::Pending>,
    ) -> Result<Revision, PortFailure>;

    /// Atomically removes exactly one pending item from `revision`, preserving
    /// the complete state and every other pending item, and advances once.
    ///
    /// `pending` is one committed item itself, not an identity the store has to
    /// re-resolve, so a store that keeps the protocol layer's items needs no
    /// second identity space of its own.
    fn settle(
        &mut self,
        revision: Revision,
        pending: &Self::Pending,
    ) -> Result<Revision, PortFailure>;
}

/// Caller-owned time (`src/state/mod.rs`).
pub trait Clock {
    fn now_unix_seconds(&self) -> Result<u64, PortFailure>;
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now_unix_seconds(&self) -> Result<u64, PortFailure> {
        (**self).now_unix_seconds()
    }
}

/// The SDK's own classification of one transport attempt
/// (`transport::classify_status`, `src/transport.rs`).
///
/// It is carried verbatim: a client must not add a fifth outcome, and
/// [`TransportOutcome::Ambiguous`] specifically means the attempt may or may not
/// have been accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOutcome {
    Accepted,
    Rejected,
    Transient,
    Ambiguous,
}

/// Sends exactly one already-committed protected packet
/// (`state::PacketCarrier::send`, `src/state/mod.rs`).
///
/// The packet is bounded and committed before this call; the caller classifies
/// the relay response with the SDK and reports it back as a
/// [`TransportOutcome`].
pub trait Transport {
    fn submit(&mut self, packet: &[u8]) -> Result<TransportOutcome, PortFailure>;
}

#[cfg(test)]
mod tests {
    use super::{
        CustodyHandle, CustodyPurpose, KeyMutation, MAX_SAFE_INTEGER, PendingId, PendingItem,
        PortFailure, Revision, Versioned,
    };

    #[test]
    fn revision_arithmetic_stops_at_the_protocol_bound() {
        assert_eq!(Revision::initial().value(), 0);
        assert_eq!(Revision::initial().successor().unwrap().value(), 1);
        let last = Revision(MAX_SAFE_INTEGER - 1);
        assert_eq!(last.successor().unwrap(), Revision(MAX_SAFE_INTEGER));
        assert_eq!(
            Revision(MAX_SAFE_INTEGER).successor(),
            Err(PortFailure::BoundExceeded)
        );
    }

    #[test]
    fn only_an_uncertain_failure_is_retryable() {
        for failure in [
            PortFailure::Unavailable,
            PortFailure::Conflict,
            PortFailure::BoundExceeded,
        ] {
            assert!(!failure.retryable());
        }
        assert!(PortFailure::Uncertain.retryable());
    }

    #[test]
    fn a_restored_snapshot_reports_exactly_the_value_it_was_given() {
        let pending = vec![PendingItem::packet(PendingId::from_token(4), vec![1, 2, 3])];
        let restored = Versioned::restored(Revision(7), 11_u8, pending.clone());

        assert_eq!(restored.revision(), Revision(7));
        assert_eq!(restored.state(), &11);
        assert_eq!(restored.pending().len(), 1);
        assert_eq!(restored.pending()[0].id(), PendingId::from_token(4));
        // It is a presentation of a committed value, not a way to advance one:
        // the next commit still has to name the same expected revision.
        assert_eq!(
            restored.revision().successor(),
            Ok(Revision(8)),
            "restoring changes no counter"
        );
    }

    #[test]
    fn every_key_mutation_names_a_honest_purpose_and_lifecycle() {
        // The port's mutation vocabulary is the protocol's: adoption is tentative
        // and deletion is adopted. A handle carries both, so a store can refuse a
        // pairing the protocol layer never emits.
        let adopt = KeyMutation::Adopt(CustodyHandle::staged(1, CustodyPurpose::X25519Private));
        let delete = KeyMutation::Delete(CustodyHandle::adopted(
            2,
            CustodyPurpose::MlKemEncapsulationEntropy,
        ));
        assert_ne!(adopt, delete);
        assert_eq!(
            adopt,
            KeyMutation::Adopt(CustodyHandle::staged(1, CustodyPurpose::X25519Private)),
            "the mutation is the handle it names, nothing more"
        );
    }
}
