//! The caller-owned port spine the fixed SDK's endpoint is composed from.
//!
//! The caller owns key custody, durable state, time, and packet transport;
//! [`crate::ports`] declares exactly those four as
//! consumer-owned traits, and the pinned LicoArc SDK declares its own
//! `KeyCustody`, `AtomicState`, `Clock`, and `PacketCarrier` for the same four
//! capabilities. This module is the one composition point between them: each
//! adapter below implements the SDK's trait by delegating to the caller's port
//! and translates only the vocabulary the two boundaries already share. It adds
//! no protocol policy of its own and decides no protocol outcome.
//!
//! Two properties are why the adapters exist instead of raw SDK types being
//! handed around:
//!
//! * **No side effect before accepted authority.** [`ProtocolWorkSetup`] is
//!   constructed from the caller's ports and the *unadmitted* authority bytes.
//!   Constructing it opens no store, starts no listener, sends no packet, and
//!   reads no clock; the ports stay inert until [`ProtocolWorkSetup::admit`]
//!   returns an SDK-verified Protocol Line. A refused artifact therefore
//!   produces no write and no network I/O, and the ports are handed back
//!   unchanged.
//! * **No locally constructible trusted facts.** The custody adapter accepts
//!   only the non-secret tokens the SDK already holds and resolves each one
//!   through the caller's own store, so a caller cannot re-label a token with a
//!   purpose it does not have. The verification facts themselves belong to
//!   [`crate::TrustFacts`], whose constructors are private
//!   and fallible; nothing here can mint, relabel, or edit one.
//!
//! The SDK is the pinned `licoarc` dependency, re-exported at the crate root
//! ([`crate::endpoint`], [`crate::state`], and siblings), so this module names
//! the fixed SDK boundary in `crate::` terms everywhere.

use crate::Error;
use crate::endpoint::EndpointState;
use crate::state::{
    AtomicState as SdkAtomicState, Clock as SdkClock, Commit as SdkCommit, CustodyRef,
    Ed25519Signing, KeyCustody as SdkKeyCustody, KeyMutation as SdkKeyMutation, MlDsa65Signing,
    MlKem768Private, MlKemEncapsulationEntropy, PacketCarrier, PendingId as SdkPendingId,
    PendingItem as SdkPendingItem, Revision as SdkRevision, SecretHandle, StagedSecretHandle,
    Versioned as SdkVersioned, X25519Private,
};
use crate::{
    AtomicState as AtomicStatePort, Clock as ClockPort, CustodyHandle, CustodyLifecycle,
    CustodyPurpose, KeyCustody as KeyCustodyPort, KeyMutation as PortKeyMutation, PortFailure,
    Revision as PortRevision, StateCommit as PortStateCommit, Transport as TransportPort,
    TransportOutcome,
};
use crate::{AuthorityInput, VerifiedProtocolLine};

mod replacement;

pub use replacement::{ReplacementRequest, admit_replacement, admit_replacement_with_authority};

/// Resolves a non-secret custody token to the caller's own custody handle.
///
/// The SDK hands its custody adapter a token, never a purpose or a lifecycle,
/// while the port contract requires the caller to look the token up and verify
/// both before the operation runs. An implementation therefore reports the
/// handle it really holds for that token, or [`PortFailure::Unavailable`]; it
/// never reports a handle it would like to be true.
pub trait CustodyHandles {
    fn custody_handle(
        &self,
        token: u128,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<CustodyHandle, PortFailure>;
}

/// The SDK's custody entry over the caller-owned [`KeyCustodyPort`].
pub struct KeyCustodyAdapter<C, H> {
    custody: C,
    handles: H,
}

impl<C, H> KeyCustodyAdapter<C, H> {
    #[must_use]
    pub const fn new(custody: C, handles: H) -> Self {
        Self { custody, handles }
    }
}

impl<C, H> SdkKeyCustody for KeyCustodyAdapter<C, H>
where
    C: KeyCustodyPort,
    H: CustodyHandles,
{
    fn ed25519_public(&self, handle: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error> {
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::Ed25519Signing,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ed25519_public(handle)
            .map_err(Error::of_port_failure)
    }

    fn ed25519_sign(
        &self,
        handle: &SecretHandle<Ed25519Signing>,
        message: &[u8],
    ) -> Result<[u8; 64], Error> {
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::Ed25519Signing,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ed25519_sign(handle, message)
            .map_err(Error::of_port_failure)
    }

    fn ml_dsa_65_public(&self, handle: &SecretHandle<MlDsa65Signing>) -> Result<Vec<u8>, Error> {
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::MlDsa65Signing,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ml_dsa_65_public(handle)
            .map_err(Error::of_port_failure)
    }

    fn ml_dsa_65_sign(
        &self,
        handle: &SecretHandle<MlDsa65Signing>,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::MlDsa65Signing,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ml_dsa_65_sign(handle, message)
            .map_err(Error::of_port_failure)
    }

    fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error> {
        let lifecycle = custody_lifecycle(&handle);
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::X25519Private,
                lifecycle,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .x25519_public(handle)
            .map_err(Error::of_port_failure)
    }

    fn x25519(
        &self,
        handle: CustodyRef<'_, X25519Private>,
        public: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let lifecycle = custody_lifecycle(&handle);
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::X25519Private,
                lifecycle,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .x25519(handle, public)
            .map_err(Error::of_port_failure)
    }

    fn ml_kem_768_public(&self, handle: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error> {
        let lifecycle = custody_lifecycle(&handle);
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::MlKem768Private,
                lifecycle,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ml_kem_768_public(handle)
            .map_err(Error::of_port_failure)
    }

    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: &SecretHandle<MlKemEncapsulationEntropy>,
    ) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let entropy = self
            .handles
            .custody_handle(
                entropy.custody_token(),
                CustodyPurpose::MlKemEncapsulationEntropy,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ml_kem_768_encapsulate(public, entropy)
            .map_err(Error::of_port_failure)
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: &SecretHandle<MlKem768Private>,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], Error> {
        let handle = self
            .handles
            .custody_handle(
                handle.custody_token(),
                CustodyPurpose::MlKem768Private,
                CustodyLifecycle::Adopted,
            )
            .map_err(Error::of_port_failure)?;
        self.custody
            .ml_kem_768_decapsulate(handle, ciphertext)
            .map_err(Error::of_port_failure)
    }

    fn abort_x25519(&mut self, staged: &StagedSecretHandle<X25519Private>) {
        if let Ok(handle) = self.handles.custody_handle(
            staged.custody_token(),
            CustodyPurpose::X25519Private,
            CustodyLifecycle::Staged,
        ) {
            self.custody.abort_x25519(handle);
        }
    }

    fn abort_ml_kem_768(&mut self, staged: &StagedSecretHandle<MlKem768Private>) {
        if let Ok(handle) = self.handles.custody_handle(
            staged.custody_token(),
            CustodyPurpose::MlKem768Private,
            CustodyLifecycle::Staged,
        ) {
            self.custody.abort_ml_kem_768(handle);
        }
    }
}

fn custody_lifecycle<P>(handle: &CustodyRef<'_, P>) -> CustodyLifecycle {
    match handle {
        CustodyRef::Adopted(_) => CustodyLifecycle::Adopted,
        CustodyRef::Staged(_) => CustodyLifecycle::Staged,
    }
}

/// The SDK's durable-state entry over the caller-owned [`AtomicStatePort`].
///
/// The port stays the single durable owner: this adapter forwards every
/// old-or-new decision to it and never applies a mutation, retries, or rewrites
/// a committed item itself. The port's pending type is the protocol layer's own
/// item, so the same value the protocol committed is the value it re-drives and
/// settles: nothing is mapped back into an identity the protocol would have to
/// recognise again.
pub struct AtomicStateAdapter<A> {
    state: A,
}

impl<A> AtomicStateAdapter<A> {
    #[must_use]
    pub const fn new(state: A) -> Self {
        Self { state }
    }

    /// Returns the caller-owned store without discarding committed pending work.
    #[must_use]
    pub fn into_state(self) -> A {
        self.state
    }
}

impl<A> SdkAtomicState<EndpointState> for AtomicStateAdapter<A>
where
    A: AtomicStatePort<Snapshot = EndpointState, Pending = SdkPendingItem>,
{
    fn load(&self) -> Result<SdkVersioned<EndpointState>, Error> {
        let loaded = self.state.load().map_err(Error::of_port_failure)?;
        sdk_snapshot(
            loaded.revision(),
            loaded.state().clone(),
            loaded.pending().to_vec(),
        )
    }

    fn compare_and_swap(
        &mut self,
        expected: SdkRevision,
        commit: SdkCommit<EndpointState>,
    ) -> Result<SdkRevision, Error> {
        let mutations = commit
            .key_mutations()
            .iter()
            .map(port_key_mutation)
            .collect();
        let port_commit = PortStateCommit::new(
            commit.next_state().clone(),
            mutations,
            commit.pending().to_vec(),
        );
        self.state
            .compare_and_swap(expected.into_port_revision(), port_commit)
            .map_err(Error::of_port_failure)
            .and_then(sdk_revision)
    }

    fn settle(
        &mut self,
        revision: SdkRevision,
        pending: SdkPendingId,
    ) -> Result<SdkRevision, Error> {
        // The item is what the protocol layer committed; the identity is only
        // how this call names it, so the store matches on the item it holds.
        let current = self.state.load().map_err(Error::of_port_failure)?;
        if current.revision() != revision.into_port_revision() {
            return Err(Error::of_port_failure(PortFailure::Conflict));
        }
        let stored = current
            .pending()
            .iter()
            .find(|item| item.id() == pending)
            .cloned()
            .ok_or_else(|| {
                Error::terminal(crate::ErrorCode::InvalidTransition, crate::Stage::Commit)
            })?;
        self.state
            .settle(revision.into_port_revision(), &stored)
            .map_err(Error::of_port_failure)
            .and_then(sdk_revision)
    }
}

/// The two revision vocabularies name the same generation.
trait RevisionBridge {
    fn into_port_revision(self) -> PortRevision;
}

impl RevisionBridge for SdkRevision {
    fn into_port_revision(self) -> PortRevision {
        PortRevision::from_value(self.value())
    }
}

/// The SDK's clock entry over the caller-owned [`ClockPort`].
pub struct ClockAdapter<K> {
    clock: K,
}

impl<K> ClockAdapter<K> {
    #[must_use]
    pub const fn new(clock: K) -> Self {
        Self { clock }
    }
}

impl<K> SdkClock for ClockAdapter<K>
where
    K: ClockPort,
{
    fn now_unix_seconds(&self) -> Result<u64, Error> {
        self.clock
            .now_unix_seconds()
            .map_err(Error::of_port_failure)
    }
}

/// The SDK's carrier entry over the caller-owned [`TransportPort`].
///
/// The packet handed to the carrier is already bounded and already committed.
/// The adapter forwards the caller's own classification and adds no fifth
/// outcome: an outcome that is not `Accepted` is reported as an outcome, never
/// as a plain success.
pub struct PacketCarrierAdapter<T> {
    transport: T,
}

impl<T> PacketCarrierAdapter<T> {
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T> PacketCarrier for PacketCarrierAdapter<T>
where
    T: TransportPort,
{
    fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.transport.submit(packet) {
            Ok(TransportOutcome::Accepted) => Ok(()),
            Ok(outcome) => Err(Error::of_port_failure(outcome.into_port_failure())),
            Err(failure) => Err(Error::of_port_failure(failure)),
        }
    }
}

/// The caller-owned ports one protocol session runs on, plus the exact
/// authority bytes the caller supplied.
///
/// Constructing this value has no side effect: no store is opened, no listener
/// starts, no packet is sent, and no clock is read. The bytes stay unadmitted
/// until [`ProtocolWorkSetup::admit`] succeeds.
pub struct ProtocolWorkSetup<C, H, A, K, T> {
    authority: Vec<u8>,
    custody: C,
    handles: H,
    state: A,
    clock: K,
    transport: T,
}

impl<C, H, A, K, T> ProtocolWorkSetup<C, H, A, K, T> {
    /// Takes the caller's ports and the exact authority bytes to admit later.
    #[must_use]
    pub const fn new(
        authority: Vec<u8>,
        custody: C,
        handles: H,
        state: A,
        clock: K,
        transport: T,
    ) -> Self {
        Self {
            authority,
            custody,
            handles,
            state,
            clock,
            transport,
        }
    }

    /// The authority bytes this setup will admit, exactly as supplied.
    #[must_use]
    pub fn authority(&self) -> &[u8] {
        &self.authority
    }

    /// Admits the caller's fixed Candidate, or refuses before any port is used.
    ///
    /// The decision is the SDK's: [`AuthorityInput::admit`] accepts these bytes
    /// only when they are the fixed Candidate this build integrates. On refusal
    /// every port is returned untouched by [`ProtocolWorkSetup::ports`], so a
    /// caller can correct the artifact and retry, having written nothing and
    /// sent nothing.
    pub fn admit(self) -> Result<AdmittedProtocolWork<C, H, A, K, T>, ProtocolAdmissionRefusal> {
        let Self {
            authority,
            custody,
            handles,
            state,
            clock,
            transport,
        } = self;
        let line = AuthorityInput::new(&authority).admit().map_err(|refusal| {
            ProtocolAdmissionRefusal {
                code: refusal.code(),
                cause: refusal.cause(),
            }
        })?;
        Ok(AdmittedProtocolWork {
            line,
            custody,
            handles,
            state,
            clock,
            transport,
        })
    }

    /// Returns the ports unchanged, for the branches that need no authority.
    #[must_use]
    pub fn ports(self) -> ProtocolPorts<C, H, A, K, T> {
        ProtocolPorts {
            custody: self.custody,
            handles: self.handles,
            state: self.state,
            clock: self.clock,
            transport: self.transport,
        }
    }
}

/// Refused authority artifact, reported in the caller-side boundary's own terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolAdmissionRefusal {
    code: &'static str,
    cause: Error,
}

impl ProtocolAdmissionRefusal {
    /// Stable code reported for every refused artifact.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// The bounded SDK cause that refused the artifact.
    #[must_use]
    pub const fn cause(self) -> Error {
        self.cause
    }
}

impl core::fmt::Display for ProtocolAdmissionRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.cause)
    }
}

impl std::error::Error for ProtocolAdmissionRefusal {}

/// The caller-owned ports, with no protocol authority attached.
pub struct ProtocolPorts<C, H, A, K, T> {
    custody: C,
    handles: H,
    state: A,
    clock: K,
    transport: T,
}

impl<C, H, A, K, T> ProtocolPorts<C, H, A, K, T> {
    /// The ports in the order [`ProtocolWorkSetup::new`] takes them.
    #[must_use]
    pub fn into_parts(self) -> (C, H, A, K, T) {
        (
            self.custody,
            self.handles,
            self.state,
            self.clock,
            self.transport,
        )
    }
}

/// The caller's ports beside one SDK-verified Protocol Line.
///
/// Only [`ProtocolWorkSetup::admit`] produces this value, so every adapter and
/// every later effect is built from an artifact the SDK accepted and never from
/// bytes a caller merely supplied.
pub struct AdmittedProtocolWork<C, H, A, K, T> {
    line: VerifiedProtocolLine,
    custody: C,
    handles: H,
    state: A,
    clock: K,
    transport: T,
}

impl<C, H, A, K, T> AdmittedProtocolWork<C, H, A, K, T> {
    /// The verified line every adapter and every later effect is bound to.
    #[must_use]
    pub const fn line(&self) -> &VerifiedProtocolLine {
        &self.line
    }

    /// The SDK's custody entry over the caller's custody port.
    #[must_use]
    pub const fn custody_adapter(&self) -> KeyCustodyAdapter<&C, &H> {
        KeyCustodyAdapter::new(&self.custody, &self.handles)
    }

    /// The SDK's clock entry over the caller's clock port.
    #[must_use]
    pub const fn clock_adapter(&self) -> ClockAdapter<&K> {
        ClockAdapter::new(&self.clock)
    }

    /// The SDK's carrier entry over the caller's transport port.
    #[must_use]
    pub const fn packet_carrier_adapter(&mut self) -> PacketCarrierAdapter<&mut T> {
        PacketCarrierAdapter::new(&mut self.transport)
    }

    /// Decomposes into the verified line and the caller's ports, so the ports
    /// that will back the endpoint are owned by the endpoint itself.
    #[must_use]
    pub fn into_parts(self) -> (VerifiedProtocolLine, C, H, A, K, T) {
        (
            self.line,
            self.custody,
            self.handles,
            self.state,
            self.clock,
            self.transport,
        )
    }
}

/// Converts one caller-owned failure into the SDK's bounded error vocabulary.
///
/// The split is the SDK's own (`Error::retryable`, `src/error.rs`): only
/// an uncertain outcome is retryable, because an uncertain operation must
/// re-drive the same already-committed item and never a fresh one.
trait PortFailureIntoError {
    fn of_port_failure(failure: PortFailure) -> Self;
}

impl PortFailureIntoError for Error {
    fn of_port_failure(failure: PortFailure) -> Self {
        let stage = crate::Stage::Provider;
        if failure.retryable() {
            return Self::retryable(crate::ErrorCode::ProviderFailure, stage);
        }
        Self::terminal(
            match failure {
                PortFailure::Unavailable => crate::ErrorCode::ProviderFailure,
                PortFailure::Conflict => crate::ErrorCode::Conflict,
                PortFailure::BoundExceeded => crate::ErrorCode::BoundExceeded,
                // An uncertain outcome is retryable and returned above.
                PortFailure::Uncertain => crate::ErrorCode::ProviderFailure,
            },
            stage,
        )
    }
}

/// The caller-owned classification, as the port failure the carrier reports.
trait TransportOutcomeFailure {
    fn into_port_failure(self) -> PortFailure;
}

impl TransportOutcomeFailure for TransportOutcome {
    fn into_port_failure(self) -> PortFailure {
        match self {
            // `Accepted` is handled by the carrier before this conversion.
            TransportOutcome::Accepted | TransportOutcome::Rejected => PortFailure::Unavailable,
            TransportOutcome::Transient | TransportOutcome::Ambiguous => PortFailure::Uncertain,
        }
    }
}

/// Rebuilds the SDK's own complete-snapshot value from the port's committed one.
///
/// The SDK exposes no snapshot constructor, so the adapter goes through the same
/// bounded commit door the protocol layer uses. Nothing is invented: the state,
/// the pending items, and the revision are the port's own committed values. A
/// generation the caller's store could not have committed is refused rather
/// than presented.
fn sdk_snapshot(
    revision: PortRevision,
    state: EndpointState,
    pending: Vec<SdkPendingItem>,
) -> Result<SdkVersioned<EndpointState>, Error> {
    if revision.value() == 0 {
        // The SDK's own generation-zero snapshot is the initial one, and it
        // carries no committed work. A generation-zero store holding pending
        // items describes a value the protocol could not have produced, so it
        // is refused rather than presented as a snapshot.
        if !pending.is_empty() {
            return Err(Error::terminal(
                crate::ErrorCode::InvalidTransition,
                crate::Stage::Commit,
            ));
        }
        return Ok(SdkVersioned::initial(state));
    }
    // Every later generation is rebuilt through the same bounded commit door
    // the protocol layer commits through, from the generation immediately
    // before it, so the value presented is the one the store committed.
    let expected = sdk_revision(PortRevision::from_value(revision.value() - 1))?;
    SdkCommit::bounded(state, Vec::new(), pending, usize::MAX, usize::MAX)?.into_versioned(expected)
}

/// The same generation, in the SDK's own monotonic progression.
///
/// The SDK exposes no integer constructor for a generation, so the adapter
/// advances the SDK's own counter to the generation the store committed. A
/// generation that is not on that progression is refused for what it is: a
/// value the protocol could not have produced.
fn sdk_revision(revision: PortRevision) -> Result<SdkRevision, Error> {
    let mut current = SdkRevision::initial();
    while current.value() < revision.value() {
        current = current.successor()?;
    }
    if current.value() == revision.value() {
        Ok(current)
    } else {
        Err(Error::terminal(
            crate::ErrorCode::StateRollback,
            crate::Stage::Commit,
        ))
    }
}

/// One protocol key mutation, in the caller-owned vocabulary.
///
/// The port names the purpose and the lifecycle the protocol layer already
/// decided; the mapping adds none.
fn port_key_mutation(mutation: &SdkKeyMutation) -> PortKeyMutation {
    match mutation {
        SdkKeyMutation::AdoptX25519(staged) => PortKeyMutation::Adopt(CustodyHandle::staged(
            staged.custody_token(),
            CustodyPurpose::X25519Private,
        )),
        SdkKeyMutation::AdoptMlKem768(staged) => PortKeyMutation::Adopt(CustodyHandle::staged(
            staged.custody_token(),
            CustodyPurpose::MlKem768Private,
        )),
        SdkKeyMutation::DeleteX25519(handle) => PortKeyMutation::Delete(CustodyHandle::adopted(
            handle.custody_token(),
            CustodyPurpose::X25519Private,
        )),
        SdkKeyMutation::DeleteMlKem768(handle) => PortKeyMutation::Delete(CustodyHandle::adopted(
            handle.custody_token(),
            CustodyPurpose::MlKem768Private,
        )),
        SdkKeyMutation::DeleteMlKemEncapsulationEntropy(handle) => {
            PortKeyMutation::Delete(CustodyHandle::adopted(
                handle.custody_token(),
                CustodyPurpose::MlKemEncapsulationEntropy,
            ))
        }
    }
}

#[cfg(test)]
mod tests;
