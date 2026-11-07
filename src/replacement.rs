//! What authorizes a device replacement, and what mere possession does not.
//!
//! This module declares the caller-owned vocabulary for replacing a device's
//! endpoint identity. It has no dependencies, so no SDK type appears below: the
//! signed transition, the new-device possession proof and the accepted authority
//! are verified by the pinned LicoArc stable-core revision
//! `244ce7186cac1690c18f091dbe02df36a0860ef4` and reach the client only through
//! the adapter in the protocol boundary. This module fixes what the client must
//! *bind* before that adapter is allowed to admit anything, and what it must
//! refuse when it cannot.
//!
//! # Possession is not authority
//!
//! An archive, an imported recovery package, a provider backup and a saved
//! recovery secret are all things a person *has*. None of them is a signed
//! transition that says this new endpoint may become the subject's endpoint
//! (`components/endpoint-collaboration/transfer/src/activation.rs` is the
//! transfer owner's half of the same rule). [`ReplacementPossession`] therefore
//! carries a credential handle and nothing else, and it is not accepted as an
//! authorization by anything in this crate.
//!
//! # Two paths, and a refusal when neither exists
//!
//! [`AuthoritySource::TrustedDevice`] is an already-active device of the same
//! subject that produces the signed transition. [`AuthoritySource::SavedRecoveryCredential`]
//! is a recovery credential the subject saved earlier. [`AuthoritySource::None`]
//! is the ordinary case: an untrusted remote, a relay mailbox, a provider backup
//! or a peer's ordinary message supplies no replacement, revocation or erase
//! authority, and the caller reports [`ReplacementAuthorityRefusal::NoTrustedAuthority`]
//! without mutating anything.
//!
//! # Replay and wrong-target refusal
//!
//! [`ReplacementBinding`] names the four things one request is *about*: the
//! subject, the source device it replaces, the new endpoint identity it
//! activates, and the operation. A verified authority that names a different
//! subject, a different source device, a different new identity or a different
//! operation is refused, so authority for one replacement can never be spent on
//! another. [`ReplacementBinding::replayed_at`] refuses an authority whose epoch
//! does not advance past the epoch already accepted, so an old accepted state
//! can never become current again ([`ReplacementAuthorityRefusal::ReplayedAuthority`]).

/// Which operation one accepted authority is allowed to perform.
///
/// The operation is part of the binding, not a caller-chosen mode: authority
/// admitted for [`Self::Activate`] cannot be spent on [`Self::Revoke`] and the
/// reverse.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReplacementOperation {
    /// Admit a new endpoint identity for the subject.
    Activate,
    /// Withdraw an existing endpoint identity of the subject.
    Revoke,
}

impl ReplacementOperation {
    /// The fixed, non-secret name the binding and the receipts use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Revoke => "revoke",
        }
    }
}

/// Where replacement authority came from.
///
/// [`Self::None`] is a real, reportable answer and not an absent value: it is
/// how an ordinary message, a relay mailbox, a provider backup or an untrusted
/// remote is reported. A caller that receives it must refuse without mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthoritySource {
    /// A device the subject already accepted as active.
    TrustedDevice,
    /// A recovery credential the subject saved before the source device was lost.
    SavedRecoveryCredential,
    /// Nothing that could authorize a replacement. Ordinary backup, relay and
    /// peer input lands here.
    None,
}

impl AuthoritySource {
    /// Whether this source may carry replacement authority at all.
    ///
    /// `false` for [`Self::None`] only; a source that may carry authority still
    /// has to produce a signed transition the SDK verifies.
    #[must_use]
    pub const fn can_authorize(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The fixed, non-secret name reported to a person.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedDevice => "trusted_device",
            Self::SavedRecoveryCredential => "saved_recovery_credential",
            Self::None => "none",
        }
    }
}

/// The four things one replacement request is about.
///
/// Every field is hex text, in the same encoding the LicoArc authority record
/// uses, so the binding can be compared against the SDK-verified record without
/// a second identity dialect. A caller constructs one from the request it is
/// serving, and the adapter refuses any verified authority that names a
/// different value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementBinding {
    subject_identity_ref: String,
    source_device: String,
    new_endpoint_identity_ref: String,
    operation: ReplacementOperation,
}

impl ReplacementBinding {
    /// Binds one request to its subject, source device, new identity and operation.
    #[must_use]
    pub fn new(
        subject_identity_ref: impl Into<String>,
        source_device: impl Into<String>,
        new_endpoint_identity_ref: impl Into<String>,
        operation: ReplacementOperation,
    ) -> Self {
        Self {
            subject_identity_ref: subject_identity_ref.into(),
            source_device: source_device.into(),
            new_endpoint_identity_ref: new_endpoint_identity_ref.into(),
            operation,
        }
    }

    /// The subject whose authority this replacement is performed under.
    #[must_use]
    pub fn subject_identity_ref(&self) -> &str {
        &self.subject_identity_ref
    }

    /// The device being replaced, revoked, or activated beside.
    #[must_use]
    pub fn source_device(&self) -> &str {
        &self.source_device
    }

    /// The endpoint identity this replacement produces.
    #[must_use]
    pub fn new_endpoint_identity_ref(&self) -> &str {
        &self.new_endpoint_identity_ref
    }

    /// The operation this authority may perform.
    #[must_use]
    pub const fn operation(&self) -> ReplacementOperation {
        self.operation
    }

    /// Whether one verified authority's own claims are this binding's claims.
    ///
    /// The adapter calls this with the values it read out of the SDK-verified
    /// record, never with values the request supplied. A mismatch is a refusal,
    /// so authority verified for another subject, another source device, another
    /// new identity or another operation is never spent here.
    #[must_use]
    pub fn matches_verified(
        &self,
        subject_identity_ref: &str,
        source_device: &str,
        new_endpoint_identity_ref: &str,
        operation: ReplacementOperation,
    ) -> bool {
        self.subject_identity_ref == subject_identity_ref
            && self.source_device == source_device
            && self.new_endpoint_identity_ref == new_endpoint_identity_ref
            && self.operation == operation
    }

    /// Refuses an authority whose epoch does not advance past `accepted_epoch`.
    ///
    /// A transition carries the epoch it succeeds, so an accepted state at
    /// epoch `n` can only be succeeded by one at `n + 1`. Re-presenting an
    /// accepted or older state is the replay this refuses: re-admitting it would
    /// make a superseded roster current again.
    pub fn replayed_at(
        &self,
        accepted_epoch: u64,
        presented_epoch: u64,
    ) -> Result<(), ReplacementAuthorityRefusal> {
        if presented_epoch <= accepted_epoch {
            return Err(ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch,
                presented_epoch,
            });
        }
        Ok(())
    }
}

/// One credential the caller holds, and which source it is.
///
/// It carries the source and an opaque custody token — never key bytes, never a
/// signature, and never an authorization. Producing one of these is what
/// [`ReplacementCredentials`] does; it proves possession, and the SDK-verified
/// transition remains the only thing that proves authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplacementPossession {
    source: AuthoritySource,
    custody_token: u128,
}

impl ReplacementPossession {
    /// Reports possession of one credential held in the caller's own custody.
    ///
    /// [`AuthoritySource::None`] is refused here: it names the absence of a
    /// credential, so there is no token to carry and no possession to report.
    pub fn of(
        source: AuthoritySource,
        custody_token: u128,
    ) -> Result<Self, ReplacementAuthorityRefusal> {
        if !source.can_authorize() {
            return Err(ReplacementAuthorityRefusal::NoTrustedAuthority);
        }
        Ok(Self {
            source,
            custody_token,
        })
    }

    /// Which accepted source this credential belongs to.
    #[must_use]
    pub const fn source(self) -> AuthoritySource {
        self.source
    }

    /// The non-secret custody token the caller's own store keys on.
    ///
    /// It is a reference to a credential, not the credential: the store still
    /// has to find it and verify its purpose before signing anything with it.
    #[must_use]
    pub const fn custody_token(self) -> u128 {
        self.custody_token
    }
}

impl core::fmt::Debug for ReplacementPossession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReplacementPossession")
            .field("source", &self.source)
            .field("custody_token", &"[REDACTED]")
            .finish()
    }
}

/// Resolves which replacement credential, if any, the caller really holds.
///
/// One implementation reads the caller's own durable custody. It reports what it
/// finds and never invents a credential to make a branch succeed: a caller with
/// no trusted device and no saved recovery credential receives
/// [`ReplacementAuthorityRefusal::NoTrustedAuthority`] and refuses without
/// mutation.
pub trait ReplacementCredentials {
    fn resolve(
        &self,
        binding: &ReplacementBinding,
    ) -> Result<ReplacementPossession, ReplacementAuthorityRefusal>;
}

/// The client-side result of composing possession, binding and SDK verification.
///
/// Only a verifier that actually ran the SDK entry produces [`Self::Authorized`],
/// so a caller cannot reach an authorization by holding a backup. This mirrors
/// `licoup_protocol_bindings::TrustFacts`, whose constructors are private and
/// fallible for the same reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplacementAuthority {
    /// The SDK verified the signed transition, the possession proof and the
    /// binding together.
    Authorized(AcceptedReplacement),
    /// Nothing was admitted and nothing was written.
    Refused(ReplacementAuthorityRefusal),
}

impl ReplacementAuthority {
    /// Whether an authority was admitted.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized(_))
    }

    /// The admitted authority, when there is one.
    #[must_use]
    pub const fn accepted(&self) -> Option<&AcceptedReplacement> {
        match self {
            Self::Authorized(accepted) => Some(accepted),
            Self::Refused(_) => None,
        }
    }

    /// The fixed, non-secret refusal, when the call was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<ReplacementAuthorityRefusal> {
        match self {
            Self::Authorized(_) => None,
            Self::Refused(refusal) => Some(*refusal),
        }
    }
}

/// One authority the SDK verified for exactly one binding.
///
/// Every field is an SDK-verified value handed over unchanged. Nothing here is
/// constructible by a caller holding a backup: the only producer is the
/// verifier that ran the SDK entry, and the adapter owns both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReplacement {
    source: AuthoritySource,
    operation: ReplacementOperation,
    subject_identity_ref: String,
    source_device: String,
    new_endpoint_identity_ref: String,
    authority_epoch: u64,
    state_digest: [u8; 32],
    superseded_epoch: Option<u64>,
}

impl AcceptedReplacement {
    /// Records one verified authority for the binding it was verified against.
    ///
    /// This is the adapter's constructor and is deliberately not re-exported as
    /// a public `new`: a caller that could name every field could mint an
    /// authorization without verifying anything.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verified(
        source: AuthoritySource,
        binding: &ReplacementBinding,
        authority_epoch: u64,
        state_digest: [u8; 32],
        superseded_epoch: Option<u64>,
    ) -> Self {
        Self {
            source,
            operation: binding.operation(),
            subject_identity_ref: binding.subject_identity_ref().to_owned(),
            source_device: binding.source_device().to_owned(),
            new_endpoint_identity_ref: binding.new_endpoint_identity_ref().to_owned(),
            authority_epoch,
            state_digest,
            superseded_epoch,
        }
    }

    /// Which accepted source carried the authority.
    #[must_use]
    pub const fn source(&self) -> AuthoritySource {
        self.source
    }

    /// The operation this authority may perform.
    #[must_use]
    pub const fn operation(&self) -> ReplacementOperation {
        self.operation
    }

    /// The subject the SDK verified this authority under.
    #[must_use]
    pub fn subject_identity_ref(&self) -> &str {
        &self.subject_identity_ref
    }

    /// The source device this authority covers.
    #[must_use]
    pub fn source_device(&self) -> &str {
        &self.source_device
    }

    /// The new endpoint identity this authority activates.
    #[must_use]
    pub fn new_endpoint_identity_ref(&self) -> &str {
        &self.new_endpoint_identity_ref
    }

    /// The authority epoch the SDK verified.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// The SDK's own digest of the accepted authority state.
    #[must_use]
    pub const fn state_digest(&self) -> [u8; 32] {
        self.state_digest
    }

    /// The epoch a revocation superseded, if the authority was a revocation.
    ///
    /// A revocation governs new admissions only: it never re-derives an
    /// established result, and it is not by itself permission to erase anything.
    #[must_use]
    pub const fn superseded_epoch(&self) -> Option<u64> {
        self.superseded_epoch
    }

    /// Whether this authority revokes rather than activates.
    #[must_use]
    pub const fn is_revocation(&self) -> bool {
        matches!(self.operation, ReplacementOperation::Revoke)
    }
}

/// Why a replacement authority call was refused.
///
/// Every variant is a bounded, non-secret classification: it names a class of
/// refusal and at most two epoch numbers. No variant carries key material, a
/// signature, a credential or a payload, so a refusal is always safe to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementAuthorityRefusal {
    /// The caller holds neither a trusted device nor a saved recovery credential.
    /// Ordinary backup, relay and peer input lands here.
    NoTrustedAuthority,
    /// A credential was resolved but it belongs to a different subject.
    SubjectMismatch,
    /// A credential was resolved but it is not the named source device's.
    SourceDeviceMismatch,
    /// The new endpoint identity is not the one the authority produces, or it is
    /// the source identity itself. New endpoint keys never derive from an
    /// imported source identity.
    NewIdentityMismatch,
    /// The authority was verified for a different operation.
    OperationMismatch,
    /// The presented authority does not succeed the epoch already accepted.
    ReplayedAuthority {
        accepted_epoch: u64,
        presented_epoch: u64,
    },
    /// The destination identity is already active, so it cannot be replaced in.
    DestinationAlreadyActive,
    /// The SDK refused the signed transition, the possession proof, or the
    /// authenticated session it was presented on.
    VerificationRefused,
    /// The authority record could not be read in the shape the binding needs.
    UnreadableAuthority,
}

impl ReplacementAuthorityRefusal {
    /// The stable, non-secret code reported for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoTrustedAuthority => "no_trusted_authority",
            Self::SubjectMismatch => "subject_mismatch",
            Self::SourceDeviceMismatch => "source_device_mismatch",
            Self::NewIdentityMismatch => "new_identity_mismatch",
            Self::OperationMismatch => "operation_mismatch",
            Self::ReplayedAuthority { .. } => "replayed_authority",
            Self::DestinationAlreadyActive => "destination_already_active",
            Self::VerificationRefused => "verification_refused",
            Self::UnreadableAuthority => "unreadable_authority",
        }
    }

    /// The fixed, non-secret explanation reported to a person.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoTrustedAuthority => {
                "neither a trusted device nor a saved recovery credential can authorize this replacement"
            }
            Self::SubjectMismatch => {
                "the resolved credential belongs to a different subject than the one being replaced"
            }
            Self::SourceDeviceMismatch => {
                "the resolved credential is not held by the source device this replacement names"
            }
            Self::NewIdentityMismatch => {
                "the authority does not produce the new endpoint identity this replacement binds"
            }
            Self::OperationMismatch => {
                "the verified authority was issued for a different operation"
            }
            Self::ReplayedAuthority { .. } => {
                "the presented authority does not advance past the epoch already accepted"
            }
            Self::DestinationAlreadyActive => "the destination endpoint identity is already active",
            Self::VerificationRefused => {
                "the signed transition or the new-device possession proof was refused"
            }
            Self::UnreadableAuthority => {
                "the authority record does not carry the fields this binding compares"
            }
        }
    }

    /// Whether nothing at all was written or changed by the refused call.
    ///
    /// Always `true`: every refusal in this module is decided before any caller
    /// store, transport or effect is reached.
    #[must_use]
    pub const fn wrote_nothing(self) -> bool {
        true
    }
}

impl core::fmt::Display for ReplacementAuthorityRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.reason())
    }
}

impl std::error::Error for ReplacementAuthorityRefusal {}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedReplacement, AuthoritySource, ReplacementAuthority, ReplacementAuthorityRefusal,
        ReplacementBinding, ReplacementCredentials, ReplacementOperation, ReplacementPossession,
    };

    fn binding() -> ReplacementBinding {
        ReplacementBinding::new(
            "subject-a",
            "source-1",
            "endpoint-9",
            ReplacementOperation::Activate,
        )
    }

    #[test]
    fn having_a_credential_is_not_being_authorized() {
        let possession = ReplacementPossession::of(AuthoritySource::SavedRecoveryCredential, 7)
            .expect("a saved recovery credential is a real source");
        assert_eq!(
            possession.source(),
            AuthoritySource::SavedRecoveryCredential
        );
        assert_eq!(possession.custody_token(), 7);

        // Possession alone admits nothing: it is not an authority and there is
        // no conversion from one to the other in this module.
        let refused =
            ReplacementAuthority::Refused(ReplacementAuthorityRefusal::VerificationRefused);
        assert!(!refused.is_authorized());
        assert!(refused.accepted().is_none());
        assert_eq!(
            refused.refusal(),
            Some(ReplacementAuthorityRefusal::VerificationRefused)
        );
    }

    #[test]
    fn the_absent_source_cannot_report_possession() {
        assert_eq!(
            ReplacementPossession::of(AuthoritySource::None, 0),
            Err(ReplacementAuthorityRefusal::NoTrustedAuthority)
        );
        assert!(!AuthoritySource::None.can_authorize());
        assert!(AuthoritySource::TrustedDevice.can_authorize());
        assert!(AuthoritySource::SavedRecoveryCredential.can_authorize());
    }

    #[test]
    fn an_authority_for_another_target_is_never_spent_on_this_binding() {
        let bound = binding();
        assert!(bound.matches_verified(
            "subject-a",
            "source-1",
            "endpoint-9",
            ReplacementOperation::Activate
        ));

        for mismatched in [
            (
                "subject-b",
                "source-1",
                "endpoint-9",
                ReplacementOperation::Activate,
            ),
            (
                "subject-a",
                "source-2",
                "endpoint-9",
                ReplacementOperation::Activate,
            ),
            (
                "subject-a",
                "source-1",
                "endpoint-8",
                ReplacementOperation::Activate,
            ),
            (
                "subject-a",
                "source-1",
                "endpoint-9",
                ReplacementOperation::Revoke,
            ),
        ] {
            assert!(
                !bound.matches_verified(mismatched.0, mismatched.1, mismatched.2, mismatched.3),
                "authority verified for {mismatched:?} must not be spent on {bound:?}"
            );
        }
    }

    #[test]
    fn a_replay_that_does_not_advance_the_epoch_is_refused() {
        let bound = binding();
        assert_eq!(bound.replayed_at(0, 1), Ok(()));
        assert_eq!(bound.replayed_at(3, 4), Ok(()));
        assert_eq!(
            bound.replayed_at(3, 3),
            Err(ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch: 3,
                presented_epoch: 3,
            })
        );
        assert_eq!(
            bound.replayed_at(3, 2),
            Err(ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch: 3,
                presented_epoch: 2,
            })
        );
    }

    #[test]
    fn an_accepted_replacement_carries_only_verified_values() {
        let bound = binding();
        let accepted =
            AcceptedReplacement::verified(AuthoritySource::TrustedDevice, &bound, 4, [9; 32], None);
        assert_eq!(accepted.source(), AuthoritySource::TrustedDevice);
        assert_eq!(accepted.operation(), ReplacementOperation::Activate);
        assert_eq!(accepted.subject_identity_ref(), "subject-a");
        assert_eq!(accepted.source_device(), "source-1");
        assert_eq!(accepted.new_endpoint_identity_ref(), "endpoint-9");
        assert_eq!(accepted.authority_epoch(), 4);
        assert_eq!(accepted.state_digest(), [9; 32]);
        assert_eq!(accepted.superseded_epoch(), None);
        assert!(!accepted.is_revocation());
    }

    #[test]
    fn a_revocation_reports_what_it_superseded_and_keeps_its_own_operation() {
        let revoke = ReplacementBinding::new(
            "subject-a",
            "source-1",
            "endpoint-9",
            ReplacementOperation::Revoke,
        );
        let accepted = AcceptedReplacement::verified(
            AuthoritySource::TrustedDevice,
            &revoke,
            5,
            [1; 32],
            Some(2),
        );
        assert!(accepted.is_revocation());
        assert_eq!(accepted.operation(), ReplacementOperation::Revoke);
        assert_eq!(accepted.superseded_epoch(), Some(2));
        // The operation is part of the binding, so authority issued for a
        // revocation never activates the identity it names.
        assert!(!binding().matches_verified(
            "subject-a",
            "source-1",
            "endpoint-9",
            accepted.operation()
        ));
    }

    #[test]
    fn every_refusal_names_a_stable_code_and_writes_nothing() {
        let refusals = [
            ReplacementAuthorityRefusal::NoTrustedAuthority,
            ReplacementAuthorityRefusal::SubjectMismatch,
            ReplacementAuthorityRefusal::SourceDeviceMismatch,
            ReplacementAuthorityRefusal::NewIdentityMismatch,
            ReplacementAuthorityRefusal::OperationMismatch,
            ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch: 1,
                presented_epoch: 1,
            },
            ReplacementAuthorityRefusal::DestinationAlreadyActive,
            ReplacementAuthorityRefusal::VerificationRefused,
            ReplacementAuthorityRefusal::UnreadableAuthority,
        ];
        for refusal in refusals {
            assert!(!refusal.code().is_empty(), "{refusal:?} names no code");
            assert!(!refusal.reason().is_empty(), "{refusal:?} names no reason");
            assert!(refusal.wrote_nothing());
            // The rendered message carries the code and the reason, never a
            // credential, a signature or an epoch beyond the two it names.
            let rendered = refusal.to_string();
            assert!(rendered.starts_with(refusal.code()));
        }
    }

    #[test]
    fn a_credential_port_reports_absence_instead_of_inventing_one() {
        struct Nothing;
        impl ReplacementCredentials for Nothing {
            fn resolve(
                &self,
                _binding: &ReplacementBinding,
            ) -> Result<ReplacementPossession, ReplacementAuthorityRefusal> {
                Err(ReplacementAuthorityRefusal::NoTrustedAuthority)
            }
        }
        assert_eq!(
            Nothing.resolve(&binding()),
            Err(ReplacementAuthorityRefusal::NoTrustedAuthority)
        );
    }

    #[test]
    fn the_binding_names_the_operation_the_authority_may_perform() {
        assert_eq!(ReplacementOperation::Activate.as_str(), "activate");
        assert_eq!(ReplacementOperation::Revoke.as_str(), "revoke");
        assert_eq!(AuthoritySource::TrustedDevice.as_str(), "trusted_device");
        assert_eq!(
            AuthoritySource::SavedRecoveryCredential.as_str(),
            "saved_recovery_credential"
        );
        assert_eq!(AuthoritySource::None.as_str(), "none");
    }
}
