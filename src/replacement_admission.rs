//! Device replacement authority through the pinned SDK's own verification entries.
//!
//! This is the client-side consumer of the pinned `licoarc` SDK's replacement
//! surface. It never decides a protocol outcome: it calls the SDK entry that
//! owns the decision and hands back exactly what that entry verified. Every rule
//! below names the SDK behaviour it mirrors (`src/...` paths inside the
//! `licoarc` package).
//!
//! # What the SDK owns
//!
//! | decision | SDK entry |
//! | --- | --- |
//! | the signed management/recovery transition, its epoch and its predecessor | `validate_user_authority_state`, `src/identity.rs` |
//! | the new-device possession proof | reached inside the same entry, `src/identity.rs` |
//! | the replacement possession proof over the new authority keys | same entry, `src/identity.rs`; the message is `replacement_possession_input`, `src/identity.rs` |
//! | the authenticated session, its authority digest and its active device entry | `admit_protected_authority_payload`, `src/identity.rs` |
//! | a self-verifying record with no session | `validate_user_authority_state`, `src/identity.rs` |
//! | a snapshot chain catching up missed transitions | `apply_user_authority_catch_up`, `src/identity.rs` |
//!
//! Nothing here re-verifies a signature and no local type mirrors an SDK type:
//! the adapter calls the SDK entries above and returns the SDK's own
//! [`AcceptedUserAuthority`]. `verify_replacement_possession`
//! is private in the SDK (`src/identity.rs`) and is deliberately *not*
//! re-implemented here; it is reached only through the public entries above.
//!
//! # Why the binding lives elsewhere
//!
//! The SDK verifies that *some* subject's roster accepted *some* device. It
//! cannot know which replacement the local person asked for, which source device
//! it replaces, or which operation it performs. That comparison is the
//! caller-owned binding contract in [`crate::replacement`] — vocabulary with no
//! SDK dependencies at all — and the replacement adapter in [`crate::adapters`]
//! is where the two sides are composed.
//!
//! # No side effect before admitted authority
//!
//! [`SdkReplacementAuthority`] holds no store, opens no transport, starts no
//! listener and reads no clock. It is constructed with an
//! `Option<VerifiedProtocolLine>`: a build without an admitted Candidate
//! constructs the refusing form and reports
//! [`ReplacementAdmissionRefusal::NoAdmittedLine`] without borrowing another
//! source's authority.

use licoarc::identity::{
    AcceptedUserAuthority, AuthenticatedAuthoritySession, EndpointStateKeys,
    admit_protected_authority_payload, apply_user_authority_catch_up,
    validate_user_authority_state,
};
use licoarc::provider::RustCryptoProvider;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::VerifiedProtocolLine;

/// One device identity the caller holds keys for, in the shape the SDK verifies.
///
/// The SDK matches a roster entry on `endpointIdentityRef` **and**
/// `identityStateDigest`, then verifies that entry's possession proof against
/// these keys (`src/identity.rs`). Supplying the wrong digest or the
/// wrong keys therefore fails closed inside the SDK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementEndpointKeys {
    /// The roster's `endpointIdentityRef`, as hex text.
    pub endpoint_identity_ref: String,
    /// The roster's `identityStateDigest`, as hex text.
    pub identity_state_digest: String,
    /// The device's accepted ed25519 key id, as hex text.
    pub ed25519_key_id: String,
    /// The device's accepted ed25519 public key, as hex text.
    pub ed25519_public: String,
    /// The device's accepted ml-dsa-65 key id, as hex text.
    pub ml_dsa_65_key_id: String,
    /// The device's accepted ml-dsa-65 public key, as hex text.
    pub ml_dsa_65_public: String,
}

impl ReplacementEndpointKeys {
    /// The roster endpoint reference this key set belongs to.
    #[must_use]
    pub fn endpoint_identity_ref(&self) -> &str {
        &self.endpoint_identity_ref
    }

    /// The identity state digest this key set belongs to.
    #[must_use]
    pub fn identity_state_digest(&self) -> &str {
        &self.identity_state_digest
    }

    /// Converts to the SDK's own key projection.
    ///
    /// Every value is decoded as 32-byte hex except the ml-dsa-65 public key,
    /// which is variable length. A malformed value is reported as
    /// [`ReplacementAdmissionRefusal::UnreadableKeys`] before any SDK call.
    fn to_sdk(&self) -> Result<EndpointStateKeys, ReplacementAdmissionRefusal> {
        Ok(EndpointStateKeys {
            endpoint_identity_ref: decode_hex_32(&self.endpoint_identity_ref)?,
            identity_state_digest: decode_hex_32(&self.identity_state_digest)?,
            ed25519_key_id: decode_hex_32(&self.ed25519_key_id)?,
            ed25519_public: decode_hex_32(&self.ed25519_public)?,
            ml_dsa_65_key_id: decode_hex_32(&self.ml_dsa_65_key_id)?,
            ml_dsa_65_public: decode_hex(&self.ml_dsa_65_public)?,
        })
    }
}

/// The predecessor authority the caller already accepted, if any.
///
/// It is passed through to the SDK unchanged as `accepted`. The transition rules
/// that make it required — epoch `n + 1`, matching
/// `previousUserAuthorityStateDigest`, equal `userIdentityRef` and
/// `protocolLineId` — belong to the SDK (`src/identity.rs`).
///
/// The record also carries the fresh-admission proof its own acceptance
/// retained: the endpoints its transition rostered that the roster it
/// succeeded did not hold. When the record is itself the admission a claim
/// names, that proof — not the record alone — decides whether the named
/// destination was genuinely new.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPredecessor {
    authority: AcceptedUserAuthority,
    /// The endpoint identity references this record's own transition
    /// admitted fresh, retained from the acceptance that verified it. Empty
    /// for a predecessor rebuilt from the bare record: the record alone
    /// cannot prove a destination was new, so the claim must then carry the
    /// verified pre-admission roster.
    fresh_admissions: BTreeSet<String>,
}

impl ReplacementPredecessor {
    /// Takes an accepted authority the caller already holds, with no
    /// retained fresh-admission proof.
    ///
    /// A caller that holds the proof — [`VerifiedReplacementAuthority`]
    /// reports it as [`VerifiedReplacementAuthority::fresh_admissions`], and
    /// [`VerifiedReplacementAuthority::predecessor`] carries it over —
    /// supplies it through [`Self::with_fresh_admissions`] instead.
    #[must_use]
    pub const fn new(authority: AcceptedUserAuthority) -> Self {
        Self {
            authority,
            fresh_admissions: BTreeSet::new(),
        }
    }

    /// Takes an accepted authority and the endpoints its own transition
    /// admitted fresh.
    ///
    /// `fresh_admissions` is the set [`VerifiedReplacementAuthority`]
    /// reported when the caller accepted this record: endpoint references
    /// present in its roster and absent from the roster the SDK validated
    /// the transition against (`validate_roster_transition`,
    /// `src/identity.rs`). The proof survives a restart only when the caller
    /// persisted it alongside the activation record.
    #[must_use]
    pub const fn with_fresh_admissions(
        authority: AcceptedUserAuthority,
        fresh_admissions: BTreeSet<String>,
    ) -> Self {
        Self {
            authority,
            fresh_admissions,
        }
    }

    /// The authority epoch already accepted.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.authority.authority_epoch
    }

    /// The SDK's digest of the accepted state.
    #[must_use]
    pub const fn state_digest(&self) -> [u8; 32] {
        self.authority.state_digest
    }

    /// The user identity reference the accepted state is bound to.
    #[must_use]
    pub const fn user_identity_ref(&self) -> [u8; 32] {
        self.authority.user_identity_ref
    }

    /// The accepted state record, exactly as the SDK verified it.
    #[must_use]
    pub const fn state(&self) -> &Value {
        &self.authority.state
    }

    /// Whether this record's own transition admitted `endpoint_identity_ref`
    /// fresh — the retained proof the binding needs when this record is the
    /// claimed admission.
    pub(crate) fn proves_fresh_admission(&self, endpoint_identity_ref: &str) -> bool {
        self.fresh_admissions.contains(endpoint_identity_ref)
    }

    fn as_sdk(&self) -> &AcceptedUserAuthority {
        &self.authority
    }
}

/// The authenticated session facts one replacement is presented on.
///
/// These are caller-owned authenticated facts the SDK established for this
/// session, never message claims. `admit_protected_authority_payload` refuses
/// the call when `authenticated` is false, when the payload digest differs from
/// `authority_state_digest`, or when the session's
/// `(endpoint_identity_ref, identity_state_digest)` is not an active authorized
/// device (`src/identity.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementSession {
    /// Whether the SDK authenticated this session.
    pub authenticated: bool,
    /// The authority state digest the authenticated session bound.
    pub authority_state_digest: [u8; 32],
    /// The endpoint identity reference that produced the transition.
    pub endpoint_identity_ref: [u8; 32],
    /// The identity state digest that produced the transition.
    pub identity_state_digest: [u8; 32],
}

impl ReplacementSession {
    /// The caller's system clock as Unix seconds, for a session that has none.
    ///
    /// The SDK's own session facts do not carry a timestamp, so this is the one
    /// caller-owned time input a replacement admission needs. It is reported
    /// here rather than invented by each adapter, so every adapter records the
    /// same convention. A clock before the Unix epoch reports `0`, which is
    /// still a definite answer and never a negative time.
    #[must_use]
    pub fn system_now_unix_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    const fn as_sdk(self) -> AuthenticatedAuthoritySession {
        AuthenticatedAuthoritySession {
            authenticated: self.authenticated,
            authority_state_digest: self.authority_state_digest,
            endpoint_identity_ref: self.endpoint_identity_ref,
            identity_state_digest: self.identity_state_digest,
        }
    }
}

/// Everything the SDK needs to decide one replacement transition.
///
/// It carries no local policy: which subject, source device, new identity and
/// operation the caller *asked* for is compared by the platform adapter after
/// this call, against what the SDK verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementAdmission {
    /// The authority the caller already accepted, if any.
    pub predecessor: Option<ReplacementPredecessor>,
    /// The authenticated session facts the transition arrived on.
    pub session: ReplacementSession,
    /// The local device keys known to the caller, for possession verification.
    pub endpoints: Vec<ReplacementEndpointKeys>,
}

/// Everything the SDK needs to decide authority material that arrived with no
/// authenticated session.
///
/// A saved recovery credential, an offline export or an untrusted relay hands
/// the caller a signed authority record before any session could have
/// authenticated it. The SDK validates the record itself — the signed
/// transition, the epoch chain and the possession proofs are self-verifying
/// (`validate_user_authority_state`, `apply_user_authority_catch_up`,
/// `src/identity.rs`), so no `ReplacementSession` exists here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdAdmission {
    /// The authority the caller already accepted, if any.
    pub predecessor: Option<ReplacementPredecessor>,
    /// The local device keys known to the caller, for possession verification.
    pub endpoints: Vec<ReplacementEndpointKeys>,
}

/// Why the SDK refused one replacement transition.
///
/// It is a bounded, non-secret classification. No variant carries key material,
/// a signature, a credential or a payload, so a refusal is always safe to report
/// and is safe to persist as a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementAdmissionRefusal {
    /// This build holds no admitted Protocol Line, so no replacement authority
    /// exists to spend. Nothing was read and nothing was written.
    NoAdmittedLine,
    /// The SDK refused the signed transition, the possession proof, or the
    /// authenticated session it was presented on
    /// (`src/identity.rs`).
    VerificationRefused,
    /// A caller-supplied key set or record field was not readable in the shape
    /// the SDK requires.
    UnreadableKeys,
}

impl ReplacementAdmissionRefusal {
    /// The stable, non-secret code reported for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoAdmittedLine => "no_admitted_line",
            Self::VerificationRefused => "verification_refused",
            Self::UnreadableKeys => "unreadable_keys",
        }
    }

    /// The fixed, non-secret explanation reported to a person.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoAdmittedLine => {
                "this build holds no admitted Protocol Line, so no replacement authority is available"
            }
            Self::VerificationRefused => {
                "the signed transition, the possession proof, or the authenticated session was refused"
            }
            Self::UnreadableKeys => {
                "a caller-supplied device key set is not readable in the shape the protocol requires"
            }
        }
    }
}

impl core::fmt::Display for ReplacementAdmissionRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.reason())
    }
}

impl std::error::Error for ReplacementAdmissionRefusal {}

/// What the SDK verified about one replacement, beside the transition it accepted.
///
/// Only [`SdkReplacementAuthority::admit`] produces this value, so a caller
/// cannot reach an accepted authority by holding a backup, an archive or a
/// provider package. The value keeps the SDK's own [`AcceptedUserAuthority`],
/// because that is the predecessor the next transition must name and the value
/// the caller's durable activation record refers to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReplacementAuthority {
    authority: AcceptedUserAuthority,
    /// The endpoint identity references this record's own transition
    /// admitted fresh — present in its roster and absent from the roster the
    /// SDK validated that transition against. It is the SDK-backed proof a
    /// later claim needs when this record is the destination's admission
    /// record: the record alone cannot tell that admission from an
    /// identity-state-digest restamp (`validate_roster_transition`,
    /// `src/identity.rs`). A caller that persists the activation record
    /// persists the proof alongside it.
    fresh_admissions: BTreeSet<String>,
}

impl VerifiedReplacementAuthority {
    /// The authority epoch the SDK accepted.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority.authority_epoch
    }

    /// The SDK's own digest of the accepted state.
    #[must_use]
    pub const fn state_digest(&self) -> [u8; 32] {
        self.authority.state_digest
    }

    /// The user identity reference the accepted state is bound to.
    #[must_use]
    pub const fn user_identity_ref(&self) -> [u8; 32] {
        self.authority.user_identity_ref
    }

    /// The accepted state record, exactly as the SDK verified it.
    ///
    /// It carries public keys, endpoint references, epochs and signatures only:
    /// no private key, no credential and no payload ever appears in it. It is
    /// the predecessor a later transition must name.
    #[must_use]
    pub const fn state(&self) -> &Value {
        &self.authority.state
    }

    /// The endpoint identity references this record's own transition
    /// admitted fresh.
    ///
    /// Each named endpoint was absent from the roster the SDK validated the
    /// transition against, so the transition really admitted it — the
    /// distinction the record alone cannot make between a fresh admission
    /// and an identity-state-digest restamp. The proof is bound to this
    /// record's own epoch.
    #[must_use]
    pub const fn fresh_admissions(&self) -> &BTreeSet<String> {
        &self.fresh_admissions
    }

    /// The predecessor a later transition must name, retaining the
    /// fresh-admission proof this record carries.
    ///
    /// Equivalent to [`ReplacementPredecessor::with_fresh_admissions`] with
    /// this authority and its [`Self::fresh_admissions`]; a caller that
    /// persists the activation record rebuilds the predecessor the same way
    /// after a restart.
    #[must_use]
    pub fn predecessor(&self) -> ReplacementPredecessor {
        ReplacementPredecessor::with_fresh_admissions(
            self.authority.clone(),
            self.fresh_admissions.clone(),
        )
    }

    /// The SDK's own accepted authority, handed over unchanged.
    #[must_use]
    pub const fn authority(&self) -> &AcceptedUserAuthority {
        &self.authority
    }

    /// Consumes the value, yielding the SDK's accepted authority.
    #[must_use]
    pub fn into_authority(self) -> AcceptedUserAuthority {
        self.authority
    }
}

/// Admits a device replacement through the fixed SDK, or refuses without a write.
///
/// The adapter holds no store, opens no transport, starts no listener and reads
/// no clock, so a refused call reaches none of them and is reportable as having
/// written nothing.
pub struct SdkReplacementAuthority {
    line: Option<VerifiedProtocolLine>,
}

impl Default for SdkReplacementAuthority {
    fn default() -> Self {
        Self::without_admitted_line()
    }
}

impl SdkReplacementAuthority {
    /// The adapter for a build whose fixed Candidate has been admitted.
    ///
    /// Only [`crate::AuthorityInput::admit`] produces the line.
    #[must_use]
    pub const fn with_admitted_line(line: VerifiedProtocolLine) -> Self {
        Self { line: Some(line) }
    }

    /// The adapter for a build with no admitted Candidate.
    ///
    /// This is the ordinary absent-artifact form. It is constructible and
    /// harmless: every call reports
    /// [`ReplacementAdmissionRefusal::NoAdmittedLine`] instead of borrowing
    /// another source's authority. That is the same fail-closed shape as
    /// [`crate::AUTHORIZATION_REQUIRED`].
    #[must_use]
    pub const fn without_admitted_line() -> Self {
        Self { line: None }
    }

    /// Whether this adapter holds an admitted Protocol Line.
    #[must_use]
    pub const fn has_admitted_line(&self) -> bool {
        self.line.is_some()
    }

    /// The line this adapter admits against, when one was admitted.
    #[must_use]
    pub const fn line(&self) -> Option<&VerifiedProtocolLine> {
        self.line.as_ref()
    }

    /// Admits one replacement transition, or refuses before any caller-owned
    /// effect.
    ///
    /// The decision is the SDK's. This method adds no policy of its own: it
    /// resolves the caller's key sets, calls
    /// [`licoarc::identity::admit_protected_authority_payload`] with the line's
    /// own protocol id, and returns the SDK's accepted authority unchanged.
    pub fn admit(
        &self,
        state: &Value,
        admission: &ReplacementAdmission,
    ) -> Result<VerifiedReplacementAuthority, ReplacementAdmissionRefusal> {
        let Some(line) = self.line.as_ref() else {
            return Err(ReplacementAdmissionRefusal::NoAdmittedLine);
        };
        let endpoints = admission
            .endpoints
            .iter()
            .map(ReplacementEndpointKeys::to_sdk)
            .collect::<Result<Vec<EndpointStateKeys>, ReplacementAdmissionRefusal>>()?;
        admit_protected_authority_payload(
            &RustCryptoProvider,
            admission
                .predecessor
                .as_ref()
                .map(ReplacementPredecessor::as_sdk),
            &admission.session.as_sdk(),
            state,
            *line.protocol_line_id(),
            &endpoints,
        )
        .map(|authority| VerifiedReplacementAuthority {
            fresh_admissions: retained_fresh_admissions(
                &authority,
                admission
                    .predecessor
                    .as_ref()
                    .map(ReplacementPredecessor::state),
                admission.predecessor.as_ref(),
            ),
            authority,
        })
        .map_err(|_cause: crate::Error| ReplacementAdmissionRefusal::VerificationRefused)
    }

    /// Admits one authority state that arrived with no authenticated session,
    /// or refuses before any caller-owned effect.
    ///
    /// The decision is the SDK's: [`licoarc::identity::validate_user_authority_state`]
    /// verifies the signed transition, the epoch chain against the caller's
    /// accepted predecessor and the possession proofs — the record is
    /// self-verifying, which is what a saved recovery credential or an
    /// offline record can deliver. This method adds no policy of its own.
    pub fn admit_state(
        &self,
        state: &Value,
        admission: &ColdAdmission,
    ) -> Result<VerifiedReplacementAuthority, ReplacementAdmissionRefusal> {
        let Some(line) = self.line.as_ref() else {
            return Err(ReplacementAdmissionRefusal::NoAdmittedLine);
        };
        let endpoints = admission
            .endpoints
            .iter()
            .map(ReplacementEndpointKeys::to_sdk)
            .collect::<Result<Vec<EndpointStateKeys>, ReplacementAdmissionRefusal>>()?;
        validate_user_authority_state(
            &RustCryptoProvider,
            state,
            admission
                .predecessor
                .as_ref()
                .map(|predecessor| predecessor.state()),
            *line.protocol_line_id(),
            &endpoints,
        )
        .map(|authority| VerifiedReplacementAuthority {
            fresh_admissions: retained_fresh_admissions(
                &authority,
                admission
                    .predecessor
                    .as_ref()
                    .map(ReplacementPredecessor::state),
                admission.predecessor.as_ref(),
            ),
            authority,
        })
        .map_err(|_cause: crate::Error| ReplacementAdmissionRefusal::VerificationRefused)
    }

    /// Admits a chain of authority snapshots with no authenticated session, or
    /// refuses before any caller-owned effect.
    ///
    /// A device that was offline across several transitions receives the
    /// records it missed in order; [`licoarc::identity::apply_user_authority_catch_up`]
    /// validates each against the one it succeeds, from the caller's accepted
    /// predecessor, and returns the tip it verified. An empty chain is refused
    /// by the SDK itself.
    pub fn catch_up(
        &self,
        snapshots: &[Value],
        admission: &ColdAdmission,
    ) -> Result<VerifiedReplacementAuthority, ReplacementAdmissionRefusal> {
        let Some(line) = self.line.as_ref() else {
            return Err(ReplacementAdmissionRefusal::NoAdmittedLine);
        };
        let endpoints = admission
            .endpoints
            .iter()
            .map(ReplacementEndpointKeys::to_sdk)
            .collect::<Result<Vec<EndpointStateKeys>, ReplacementAdmissionRefusal>>()?;
        apply_user_authority_catch_up(
            &RustCryptoProvider,
            admission
                .predecessor
                .as_ref()
                .map(ReplacementPredecessor::as_sdk),
            snapshots,
            *line.protocol_line_id(),
            &endpoints,
        )
        .map(|authority| {
            // The tip's own transition was validated against the previous
            // chain element — or the accepted predecessor when the chain
            // holds one snapshot.
            let prior = snapshots
                .len()
                .checked_sub(2)
                .map(|index| &snapshots[index])
                .or_else(|| {
                    admission
                        .predecessor
                        .as_ref()
                        .map(ReplacementPredecessor::state)
                });
            VerifiedReplacementAuthority {
                fresh_admissions: retained_fresh_admissions(
                    &authority,
                    prior,
                    admission.predecessor.as_ref(),
                ),
                authority,
            }
        })
        .map_err(|_cause: crate::Error| ReplacementAdmissionRefusal::VerificationRefused)
    }
}

/// The fresh-admission set one admission result retains.
///
/// `prior` is the roster the returned record's own transition was validated
/// against and `predecessor` the caller's accepted record. When the SDK
/// returns the already-accepted record unchanged — an authenticated session
/// re-presenting it is admitted as itself — the roster diff against itself
/// is empty, but the proof belongs to the record, not to this call: the
/// predecessor's retained set is carried forward rather than recomputed.
fn retained_fresh_admissions(
    authority: &AcceptedUserAuthority,
    prior: Option<&Value>,
    predecessor: Option<&ReplacementPredecessor>,
) -> BTreeSet<String> {
    if let Some(predecessor) = predecessor
        && predecessor.state_digest() == authority.state_digest
    {
        return predecessor.fresh_admissions.clone();
    }
    fresh_admissions(&authority.state, prior)
}

/// The endpoint references `record`'s roster holds that `prior`'s does not —
/// the endpoints the record's own transition admitted fresh.
///
/// `prior` is the record the SDK validated the transition against: the
/// accepted predecessor's state for a single record, or the previous chain
/// element for a catch-up tip. The SDK's roster rule leaves no other kind of
/// new entry — an endpoint absent from the prior roster must carry this
/// transition's own admission epoch (`validate_roster_transition`,
/// `src/identity.rs`) — so absence here is exactly the fresh-admission set.
fn fresh_admissions(record: &Value, prior: Option<&Value>) -> BTreeSet<String> {
    let prior_refs: BTreeSet<&str> = prior
        .and_then(|prior| prior.get("authorizedDevices"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|device| device.get("endpointIdentityRef").and_then(Value::as_str))
        .collect();
    record
        .get("authorizedDevices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|device| device.get("endpointIdentityRef").and_then(Value::as_str))
        .filter(|reference| !prior_refs.contains(reference))
        .map(str::to_owned)
        .collect()
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], ReplacementAdmissionRefusal> {
    let bytes = decode_hex(value)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_length| ReplacementAdmissionRefusal::UnreadableKeys)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ReplacementAdmissionRefusal> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReplacementAdmissionRefusal::UnreadableKeys);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_error| ReplacementAdmissionRefusal::UnreadableKeys)
        })
        .collect()
}
#[cfg(test)]
mod tests {
    //! Synthetic authority records, over the SDK's own fixture recipe.
    //!
    //! The record shape, the two-pass signing order and the replacement
    //! possession proof all mirror the SDK's own conformance fixture
    //! (`src/conformance/executor.rs` in the `licoarc` package). None
    //! of it is a second verifier: every assertion below is made about what
    //! `admit_protected_authority_payload` decided.
    //!
    //! The artifact-dependent cases are `#[ignore]`d on
    //! `LICOARC_AUTHORITY_BUNDLE`, exactly like the gated cases in
    //! `crate::session::drive`, so an absent authorized bundle is reported as
    //! not run instead of passing silently.

    use std::{env, fs};

    use licoarc::identity::{
        self, AcceptedUserAuthority, authority_signature_input, replacement_possession_input,
        validate_user_authority_state,
    };
    use licoarc::provider::{DigestProvider, Provider, RustCryptoProvider};
    use serde_json::{Value, json};

    use super::{
        ColdAdmission, ReplacementAdmission, ReplacementAdmissionRefusal, ReplacementEndpointKeys,
        ReplacementPredecessor, ReplacementSession, SdkReplacementAuthority,
    };
    use crate::version::ACCEPTED_PROTOCOL_LINE_ID;
    use crate::{
        AuthoritySource, ColdReplacementRequest, ReplacementAuthorityRefusal, ReplacementBinding,
        ReplacementOperation, ReplacementRequest, admit_replacement_catch_up,
        admit_replacement_cold, admit_replacement_cold_with_authority,
        admit_replacement_with_authority,
    };

    const ED25519_PROFILE: &str =
        "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
    const ML_DSA_65_PROFILE: &str =
        "427e788bb9aed076acc2fb5a94715d14e694ec5fbc846ac52c8c7e118a6b1b8f";

    /// One ed25519 + ml-dsa-65 signing pair, in the shape an authority record holds.
    struct Pair {
        keys: Vec<Value>,
        ed25519_seed: [u8; 32],
        ml_dsa_65_seed: [u8; 32],
        ed25519_key_id: [u8; 32],
        ml_dsa_65_key_id: [u8; 32],
        ed25519_public: [u8; 32],
        ml_dsa_65_public: Vec<u8>,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// A seed that is stable for one marker within this test process and never
    /// checked in: it is derived from a salt drawn from the OS at first use.
    fn seed(provider: &impl Provider, algorithm: &[u8], marker: u8) -> [u8; 32] {
        static SALT: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let salt = SALT.get_or_init(|| {
            let mut salt = [0u8; 32];
            getrandom::fill(&mut salt).expect("test salt");
            salt
        });
        provider.sha256(&[salt.as_slice(), algorithm, &[marker]].concat())
    }

    /// Mirrors the SDK's own `authority_pair`
    /// (`src/conformance/executor.rs`).
    fn pair(provider: &impl Provider, purpose: &'static str, marker: u8) -> Pair {
        let ed25519_seed = seed(provider, b"ed25519", marker);
        let ml_dsa_65_seed = seed(provider, b"ml-dsa-65", marker);
        let ed25519_public = provider.ed25519_public(&ed25519_seed);
        let ml_dsa_65_public = provider.ml_dsa_65_public(&ml_dsa_65_seed);
        let ed25519_key_id =
            provider.sha256(&[b"authority-ed25519-key".as_slice(), &[marker]].concat());
        let ml_dsa_65_key_id =
            provider.sha256(&[b"authority-ml-dsa-key".as_slice(), &[marker]].concat());
        Pair {
            keys: vec![
                json!({
                    "keyId": hex(&ed25519_key_id), "keyPurpose": purpose,
                    "keyProfileId": ED25519_PROFILE, "publicKey": hex(&ed25519_public)
                }),
                json!({
                    "keyId": hex(&ml_dsa_65_key_id), "keyPurpose": purpose,
                    "keyProfileId": ML_DSA_65_PROFILE, "publicKey": hex(&ml_dsa_65_public)
                }),
            ],
            ed25519_seed,
            ml_dsa_65_seed,
            ed25519_key_id,
            ml_dsa_65_key_id,
            ed25519_public,
            ml_dsa_65_public,
        }
    }

    /// Mirrors the SDK's own `placeholder_authority_signatures`
    /// (`src/conformance/executor.rs`). The digest covers the signature
    /// array, so the record needs its final shape before it is signed.
    fn placeholder_signatures(pair: &Pair, purpose: &str) -> Vec<Value> {
        vec![
            json!({
                "keyProfileId": ED25519_PROFILE,
                "keyId": hex(&pair.ed25519_key_id),
                "signaturePurpose": purpose,
                "signatureValue": "00".repeat(64)
            }),
            json!({
                "keyProfileId": ML_DSA_65_PROFILE,
                "keyId": hex(&pair.ml_dsa_65_key_id),
                "signaturePurpose": purpose,
                "signatureValue": "00".repeat(3_309)
            }),
        ]
    }

    fn signatures(
        provider: &impl Provider,
        pair: &Pair,
        input: &[u8],
        purpose: &str,
    ) -> Vec<Value> {
        vec![
            json!({
                "keyProfileId": ED25519_PROFILE,
                "keyId": hex(&pair.ed25519_key_id),
                "signaturePurpose": purpose,
                "signatureValue": hex(&provider.ed25519_sign(&pair.ed25519_seed, input))
            }),
            json!({
                "keyProfileId": ML_DSA_65_PROFILE,
                "keyId": hex(&pair.ml_dsa_65_key_id),
                "signaturePurpose": purpose,
                "signatureValue": hex(&provider.ml_dsa_65_sign(&pair.ml_dsa_65_seed, input))
            }),
        ]
    }

    /// The SDK's own two-pass signing recipe (`src/conformance/executor.rs`).
    fn sign_state(
        provider: &impl Provider,
        state: &mut Value,
        pair: &Pair,
        purpose: &str,
    ) -> Result<(), licoarc::Error> {
        state["authoritySignatures"] = Value::Array(placeholder_signatures(pair, purpose));
        let input = authority_signature_input(provider, state)?;
        state["authoritySignatures"] = Value::Array(signatures(provider, pair, &input, purpose));
        Ok(())
    }

    /// The SDK's own successor skeleton (`src/conformance/executor.rs`).
    fn successor_skeleton(
        provider: &impl Provider,
        previous: &Value,
        signer: &Pair,
        transition: &str,
    ) -> Result<Value, licoarc::Error> {
        let mut state = previous.clone();
        let epoch = previous
            .get("authorityEpoch")
            .and_then(Value::as_u64)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                licoarc::Error::terminal(
                    licoarc::ErrorCode::BoundExceeded,
                    licoarc::Stage::Validation,
                )
            })?;
        state["authorityEpoch"] = json!(epoch);
        state["previousUserAuthorityStateDigest"] = Value::String(hex(
            &identity::user_authority_state_digest(provider, previous)?,
        ));
        state["authorityTransitionKind"] = Value::String(transition.to_owned());
        if let Some(record) = state.as_object_mut() {
            record.remove("possessionProof");
        }
        state["authoritySignatures"] = Value::Array(placeholder_signatures(
            signer,
            if transition == "recovery" {
                "authority-recovery"
            } else {
                "authority-management"
            },
        ));
        Ok(state)
    }

    fn endpoint_keys(
        pair: &Pair,
        endpoint_identity_ref: &[u8; 32],
        identity_state_digest: &[u8; 32],
    ) -> identity::EndpointStateKeys {
        identity::EndpointStateKeys {
            endpoint_identity_ref: *endpoint_identity_ref,
            identity_state_digest: *identity_state_digest,
            ed25519_key_id: pair.ed25519_key_id,
            ed25519_public: pair.ed25519_public,
            ml_dsa_65_key_id: pair.ml_dsa_65_key_id,
            ml_dsa_65_public: pair.ml_dsa_65_public.clone(),
        }
    }

    /// One genesis record, its accepted authority, and the devices it names.
    ///
    /// The record's `protocolLineId` is this build's own pinned line id, because
    /// the SDK refuses any other (`src/identity.rs`). The roster holds two
    /// active devices: the one every session presents, and a second one that
    /// stays active across transitions so an "already-active destination"
    /// claim is expressible.
    struct Fixture {
        genesis: Value,
        accepted: AcceptedUserAuthority,
        line_id: [u8; 32],
        keys: Vec<ReplacementEndpointKeys>,
        endpoint_identity_ref: [u8; 32],
        identity_state_digest: [u8; 32],
        second_endpoint_identity_ref: [u8; 32],
        second_identity_state_digest: [u8; 32],
    }

    /// One roster entry with a placeholder possession proof, as the SDK's own
    /// recipe builds it (`src/conformance/executor.rs`).
    fn device_entry(
        endpoint_identity_ref: &[u8; 32],
        identity_state_digest: &[u8; 32],
        device: &Pair,
        admitted: u64,
    ) -> Value {
        json!({
            "endpointIdentityRef": hex(endpoint_identity_ref),
            "identityStateDigest": hex(identity_state_digest),
            "deviceStatus": "active",
            "admittedAuthorityEpoch": admitted,
            "possessionProof": placeholder_signatures(device, "device-possession"),
        })
    }

    /// The SDK requires `authorizedDevices` sorted by `endpointIdentityRef`
    /// (`src/identity.rs`).
    fn sort_devices(state: &mut Value) {
        if let Some(devices) = state["authorizedDevices"].as_array_mut() {
            devices.sort_by_cached_key(|entry| {
                super::decode_hex(entry["endpointIdentityRef"].as_str().unwrap_or_default())
                    .unwrap_or_default()
            });
        }
    }

    fn device_index(state: &Value, endpoint_identity_ref: &str) -> usize {
        state["authorizedDevices"]
            .as_array()
            .expect("roster")
            .iter()
            .position(|entry| entry["endpointIdentityRef"] == json!(endpoint_identity_ref))
            .expect("the device is in the roster")
    }

    fn sign_device_possession(
        provider: &impl Provider,
        state: &mut Value,
        device: &Pair,
        index: usize,
    ) {
        let input = identity::device_possession_input(state, &state["authorizedDevices"][index])
            .expect("device possession input");
        state["authorizedDevices"][index]["possessionProof"] =
            Value::Array(signatures(provider, device, &input, "device-possession"));
    }

    fn fixture(provider: &impl Provider) -> Fixture {
        let management = pair(provider, "management", 10);
        let recovery = pair(provider, "recovery", 20);
        let device = pair(provider, "management", 40);
        let second_device = pair(provider, "management", 50);
        let line_id = ACCEPTED_PROTOCOL_LINE_ID;
        let endpoint_identity_ref = provider.sha256(b"synthetic-replacement:endpoint");
        let identity_state_digest = provider.sha256(b"synthetic-replacement:endpoint-state");
        let second_endpoint_identity_ref =
            provider.sha256(b"synthetic-replacement:endpoint-second");
        let second_identity_state_digest =
            provider.sha256(b"synthetic-replacement:endpoint-state-second");
        let user_identity_ref =
            identity::derive_user_identity_ref(provider, &management.keys, &recovery.keys)
                .expect("user identity ref");
        let mut genesis = json!({
            "recordType": "userAuthorityState",
            "protocolLineId": hex(&line_id),
            "userIdentityRef": hex(&user_identity_ref),
            "authorityEpoch": 0,
            "authorityTransitionKind": "genesis",
            "managementSigningKeys": management.keys.clone(),
            "recoverySigningKeys": recovery.keys.clone(),
            "authorizedDevices": [
                device_entry(&endpoint_identity_ref, &identity_state_digest, &device, 0),
                device_entry(
                    &second_endpoint_identity_ref,
                    &second_identity_state_digest,
                    &second_device,
                    0,
                ),
            ],
            "authoritySignatures": placeholder_signatures(&management, "authority-genesis")
        });
        sort_devices(&mut genesis);
        for index in 0..genesis["authorizedDevices"]
            .as_array()
            .expect("roster")
            .len()
        {
            let signer = if genesis["authorizedDevices"][index]["endpointIdentityRef"]
                == json!(hex(&endpoint_identity_ref))
            {
                &device
            } else {
                &second_device
            };
            sign_device_possession(provider, &mut genesis, signer, index);
        }
        sign_state(provider, &mut genesis, &management, "authority-genesis")
            .expect("genesis signature");
        let accepted = validate_user_authority_state(
            provider,
            &genesis,
            None,
            line_id,
            &[
                endpoint_keys(&device, &endpoint_identity_ref, &identity_state_digest),
                endpoint_keys(
                    &second_device,
                    &second_endpoint_identity_ref,
                    &second_identity_state_digest,
                ),
            ],
        )
        .expect("genesis authority");
        Fixture {
            genesis,
            accepted,
            line_id,
            keys: vec![
                ReplacementEndpointKeys {
                    endpoint_identity_ref: hex(&endpoint_identity_ref),
                    identity_state_digest: hex(&identity_state_digest),
                    ed25519_key_id: hex(&device.ed25519_key_id),
                    ed25519_public: hex(&device.ed25519_public),
                    ml_dsa_65_key_id: hex(&device.ml_dsa_65_key_id),
                    ml_dsa_65_public: hex(&device.ml_dsa_65_public),
                },
                ReplacementEndpointKeys {
                    endpoint_identity_ref: hex(&second_endpoint_identity_ref),
                    identity_state_digest: hex(&second_identity_state_digest),
                    ed25519_key_id: hex(&second_device.ed25519_key_id),
                    ed25519_public: hex(&second_device.ed25519_public),
                    ml_dsa_65_key_id: hex(&second_device.ml_dsa_65_key_id),
                    ml_dsa_65_public: hex(&second_device.ml_dsa_65_public),
                },
            ],
            endpoint_identity_ref,
            identity_state_digest,
            second_endpoint_identity_ref,
            second_identity_state_digest,
        }
    }

    /// The recovery-transition replacement the SDK's own suite builds
    /// (`src/conformance/executor.rs`). This is a *key* replacement:
    /// the recovery key authorizes new management and recovery key sets, and the
    /// new keys prove possession over the new record.
    fn replacement_transition(provider: &impl Provider, fixture: &Fixture) -> Value {
        let recovery = pair(provider, "recovery", 20);
        let new_management = pair(provider, "management", 60);
        let new_recovery = pair(provider, "recovery", 70);
        let mut replaced = successor_skeleton(provider, &fixture.genesis, &recovery, "recovery")
            .expect("successor skeleton");
        replaced["managementSigningKeys"] = Value::Array(new_management.keys.clone());
        replaced["recoverySigningKeys"] = Value::Array(new_recovery.keys.clone());
        let proof_input =
            replacement_possession_input(&replaced).expect("replacement possession input");
        replaced["possessionProof"] = json!({
            "managementSignatures": signatures(
                provider, &new_management, &proof_input, "replacement-management-possession"
            ),
            "recoverySignatures": signatures(
                provider, &new_recovery, &proof_input, "replacement-recovery-possession"
            ),
        });
        sign_state(provider, &mut replaced, &recovery, "authority-recovery")
            .expect("recovery authority signature");
        replaced
    }

    /// A real device replacement: one management transition retires the
    /// fixture's first device and admits a new endpoint in the same step.
    /// Returns the signed record and the new device's key set.
    fn device_replacement_transition(
        provider: &impl Provider,
        fixture: &Fixture,
    ) -> (Value, ReplacementEndpointKeys) {
        let management = pair(provider, "management", 10);
        let new_device = pair(provider, "management", 80);
        let new_ref = provider.sha256(b"synthetic-replacement:endpoint-new");
        let new_digest = provider.sha256(b"synthetic-replacement:endpoint-state-new");
        let mut replaced =
            successor_skeleton(provider, &fixture.genesis, &management, "management")
                .expect("successor skeleton");
        let source_index = device_index(&replaced, &hex(&fixture.endpoint_identity_ref));
        replaced["authorizedDevices"][source_index]["deviceStatus"] = json!("revoked");
        replaced["authorizedDevices"][source_index]["revokedAuthorityEpoch"] = json!(1);
        replaced["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .push(device_entry(&new_ref, &new_digest, &new_device, 1));
        sort_devices(&mut replaced);
        let new_index = device_index(&replaced, &hex(&new_ref));
        sign_device_possession(provider, &mut replaced, &new_device, new_index);
        sign_state(provider, &mut replaced, &management, "authority-management")
            .expect("management authority signature");
        (
            replaced,
            ReplacementEndpointKeys {
                endpoint_identity_ref: hex(&new_ref),
                identity_state_digest: hex(&new_digest),
                ed25519_key_id: hex(&new_device.ed25519_key_id),
                ed25519_public: hex(&new_device.ed25519_public),
                ml_dsa_65_key_id: hex(&new_device.ml_dsa_65_key_id),
                ml_dsa_65_public: hex(&new_device.ml_dsa_65_public),
            },
        )
    }

    /// A signed management transition that revokes one device and changes
    /// nothing else.
    fn revocation_transition(
        provider: &impl Provider,
        previous: &Value,
        revoked_ref: &[u8; 32],
    ) -> Value {
        let management = pair(provider, "management", 10);
        let epoch = previous["authorityEpoch"]
            .as_u64()
            .expect("the predecessor carries an epoch")
            + 1;
        let mut revoked = successor_skeleton(provider, previous, &management, "management")
            .expect("successor skeleton");
        let index = device_index(&revoked, &hex(revoked_ref));
        revoked["authorizedDevices"][index]["deviceStatus"] = json!("revoked");
        revoked["authorizedDevices"][index]["revokedAuthorityEpoch"] = json!(epoch);
        sign_state(provider, &mut revoked, &management, "authority-management")
            .expect("management authority signature");
        revoked
    }

    /// A signed management successor that changes nothing: the SDK admits it,
    /// and it is the transition that must not be spent on a roster claim.
    fn no_op_transition(provider: &impl Provider, previous: &Value) -> Value {
        let management = pair(provider, "management", 10);
        let mut successor = successor_skeleton(provider, previous, &management, "management")
            .expect("successor skeleton");
        sign_state(
            provider,
            &mut successor,
            &management,
            "authority-management",
        )
        .expect("management authority signature");
        successor
    }

    fn admission(fixture: &Fixture) -> ReplacementAdmission {
        ReplacementAdmission {
            predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
            session: ReplacementSession {
                authenticated: true,
                authority_state_digest: fixture.accepted.state_digest,
                endpoint_identity_ref: fixture.endpoint_identity_ref,
                identity_state_digest: fixture.identity_state_digest,
            },
            endpoints: fixture.keys.clone(),
        }
    }

    /// The cold counterpart of [`admission`]: the same predecessor and key
    /// sets, and deliberately no session.
    fn cold(fixture: &Fixture) -> ColdAdmission {
        ColdAdmission {
            predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
            endpoints: fixture.keys.clone(),
        }
    }

    /// The explicit read-only authority artifact the caller supplied.
    fn authority_bytes() -> Vec<u8> {
        let path = env::var_os("LICOARC_AUTHORITY_BUNDLE")
            .expect("LICOARC_AUTHORITY_BUNDLE must name the explicit read-only authority artifact");
        fs::read(path).expect("the explicit authority artifact must be readable")
    }

    #[test]
    fn an_absent_admitted_line_refuses_before_reading_anything() {
        let adapter = SdkReplacementAuthority::without_admitted_line();
        assert!(!adapter.has_admitted_line());
        assert!(adapter.line().is_none());
        assert!(!SdkReplacementAuthority::default().has_admitted_line());

        let admission = ReplacementAdmission {
            predecessor: None,
            session: ReplacementSession {
                authenticated: false,
                authority_state_digest: [0; 32],
                endpoint_identity_ref: [0; 32],
                identity_state_digest: [0; 32],
            },
            endpoints: Vec::new(),
        };
        // The refusal is the absent line, not an incidental parse failure: the
        // record below is not even a record.
        assert_eq!(
            adapter
                .admit(&json!({"not": "a record"}), &admission)
                .expect_err("no admitted line means no replacement authority"),
            ReplacementAdmissionRefusal::NoAdmittedLine
        );

        // The sessionless paths refuse the same way before reading anything.
        let cold = ColdAdmission {
            predecessor: None,
            endpoints: Vec::new(),
        };
        assert_eq!(
            adapter
                .admit_state(&json!({"not": "a record"}), &cold)
                .expect_err("no admitted line means no cold admission"),
            ReplacementAdmissionRefusal::NoAdmittedLine
        );
        assert_eq!(
            adapter
                .catch_up(&[json!({"not": "a record"})], &cold)
                .expect_err("no admitted line means no catch-up"),
            ReplacementAdmissionRefusal::NoAdmittedLine
        );
        assert_eq!(
            adapter
                .catch_up(&[], &cold)
                .expect_err("an empty chain is refused before it is read"),
            ReplacementAdmissionRefusal::NoAdmittedLine
        );
    }

    #[test]
    fn every_refusal_names_a_stable_code_and_reason() {
        for refusal in [
            ReplacementAdmissionRefusal::NoAdmittedLine,
            ReplacementAdmissionRefusal::VerificationRefused,
            ReplacementAdmissionRefusal::UnreadableKeys,
        ] {
            assert!(!refusal.code().is_empty(), "{refusal:?} names no code");
            assert!(!refusal.reason().is_empty(), "{refusal:?} names no reason");
            assert!(
                refusal.to_string().starts_with(refusal.code()),
                "{refusal:?} must render its own code"
            );
        }
    }

    #[test]
    fn a_malformed_key_set_is_refused_in_the_boundarys_own_terms() {
        // `to_sdk` is reached only once a line exists, so the classification is
        // proved directly on the decoder the key projection uses.
        assert_eq!(
            super::decode_hex_32("not-hex"),
            Err(ReplacementAdmissionRefusal::UnreadableKeys)
        );
        assert_eq!(
            super::decode_hex_32("00"),
            Err(ReplacementAdmissionRefusal::UnreadableKeys),
            "a 1-byte value is not a 32-byte reference"
        );
        assert_eq!(super::decode_hex_32(&"0a".repeat(32)), Ok([0x0a; 32]));
        assert_eq!(
            super::decode_hex("abc"),
            Err(ReplacementAdmissionRefusal::UnreadableKeys),
            "an odd-length hex string is not readable"
        );
    }

    /// The end-to-end proof over real ed25519 and ml-dsa-65 signatures.
    ///
    /// It needs the authorized bundle (for the admitted Protocol Line) and it
    /// performs real ml-dsa-65 signing and verification, so it is `#[ignore]`.
    /// Run it explicitly:
    ///
    /// ```text
    /// LICOARC_AUTHORITY_BUNDLE=<path> \
    ///   cargo test -p licoarc-client --lib -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_recovery_key_replacement_over_real_keys_is_admitted() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let replaced = replacement_transition(&provider, &fixture);

        // The transition itself is admitted by the SDK, which is what proves
        // the fixture carries a real signed transition and a real possession
        // proof authored by the new keys.
        let direct = validate_user_authority_state(
            &provider,
            &replaced,
            Some(&fixture.accepted.state),
            fixture.line_id,
            &[endpoint_keys(
                &pair(&provider, "management", 40),
                &fixture.endpoint_identity_ref,
                &fixture.identity_state_digest,
            )],
        )
        .expect("the recovery key replacement is a valid transition");
        assert_eq!(direct.authority_epoch, 1);
        assert_eq!(direct.user_identity_ref, fixture.accepted.user_identity_ref);
        assert_ne!(
            direct.state_digest, fixture.accepted.state_digest,
            "the replacement is a new state, not a replay of the accepted one"
        );

        // And the boundary admits it through the SDK entry it delegates to.
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);
        // The authenticated session is bound to the state it is presenting.
        let mut admission = admission(&fixture);
        admission.session.authority_state_digest = direct.state_digest;
        let verified = adapter
            .admit(&replaced, &admission)
            .expect("the SDK admits the replacement over the pinned line");
        assert_eq!(verified.authority_epoch(), 1);
        assert_eq!(
            verified.user_identity_ref(),
            fixture.accepted.user_identity_ref
        );
        assert_ne!(verified.state_digest(), fixture.accepted.state_digest);
        assert_eq!(verified.state(), &replaced);
    }

    /// The same replacement presented to a session the SDK did not authenticate.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn an_unauthenticated_session_never_admits_a_replacement() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let replaced = replacement_transition(&provider, &fixture);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        let mut admission = admission(&fixture);
        admission.session.authenticated = false;
        assert_eq!(
            adapter
                .admit(&replaced, &admission)
                .expect_err("an unauthenticated session admits nothing"),
            ReplacementAdmissionRefusal::VerificationRefused
        );
    }

    /// Re-presenting the accepted state is idempotent: the SDK returns the
    /// accepted authority itself and nothing advances.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn re_presenting_the_accepted_state_admits_it_unchanged() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        let verified = adapter
            .admit(&fixture.genesis, &admission(&fixture))
            .expect("the accepted state is re-admitted as itself");
        assert_eq!(verified.authority_epoch(), 0);
        assert_eq!(verified.state_digest(), fixture.accepted.state_digest);
        assert_eq!(verified.state(), &fixture.genesis);
    }

    /// A record signed for another subject's authority is refused.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_transition_the_sdk_never_signed_is_refused() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let mut replaced = replacement_transition(&provider, &fixture);
        // Change the record after it was signed, so the signatures no longer
        // cover it. The SDK recomputes the digest and refuses.
        replaced["authorityEpoch"] = json!(7);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        assert_eq!(
            adapter
                .admit(&replaced, &admission(&fixture))
                .expect_err("a mutated record admits nothing"),
            ReplacementAdmissionRefusal::VerificationRefused
        );
    }

    /// The same recovery transition with no session at all: the record is
    /// self-verifying, which is what a saved recovery credential delivers.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_recovery_key_replacement_admits_without_a_session() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let replaced = replacement_transition(&provider, &fixture);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        let verified = adapter
            .admit_state(&replaced, &cold(&fixture))
            .expect("the SDK admits the self-verifying record cold");
        assert_eq!(verified.authority_epoch(), 1);
        assert_eq!(verified.state(), &replaced);
        assert_eq!(
            verified.user_identity_ref(),
            fixture.accepted.user_identity_ref
        );
    }

    /// A genesis alone admits cold, and a missed transition catches up from
    /// the accepted tip through a snapshot chain.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_snapshot_chain_catches_up_the_missed_transition() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let replaced = replacement_transition(&provider, &fixture);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // With nothing accepted, one genesis record is the whole catch-up.
        let from_nothing = ColdAdmission {
            predecessor: None,
            endpoints: fixture.keys.clone(),
        };
        let genesis = adapter
            .admit_state(&fixture.genesis, &from_nothing)
            .expect("genesis admits cold");
        assert_eq!(genesis.authority_epoch(), 0);
        assert_eq!(genesis.state_digest(), fixture.accepted.state_digest);

        // The missed recovery transition arrives as the snapshot after the
        // accepted tip; the SDK validates the chain and returns that tip.
        let tip = adapter
            .catch_up(std::slice::from_ref(&replaced), &cold(&fixture))
            .expect("the chain catches up to the replacement");
        assert_eq!(tip.authority_epoch(), 1);
        assert_eq!(tip.state(), &replaced);

        // From nothing at all, both snapshots validate to the same tip.
        let tip = adapter
            .catch_up(&[fixture.genesis.clone(), replaced.clone()], &from_nothing)
            .expect("the full chain catches up");
        assert_eq!(tip.authority_epoch(), 1);
        assert_eq!(tip.state(), &replaced);

        // An empty chain and a chain that does not advance are refused by the
        // SDK itself.
        assert_eq!(
            adapter
                .catch_up(&[], &cold(&fixture))
                .expect_err("an empty chain admits nothing"),
            ReplacementAdmissionRefusal::VerificationRefused
        );
        assert_eq!(
            adapter
                .catch_up(std::slice::from_ref(&fixture.genesis), &cold(&fixture))
                .expect_err("the accepted epoch is not a successor"),
            ReplacementAdmissionRefusal::VerificationRefused
        );
    }

    /// The composition's binding, exercised with a real signed replacement.
    ///
    /// The transition retires the fixture's first device and admits a new
    /// endpoint in one signed step; the claim that names exactly that change
    /// is the only one the verified record authorizes.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_signed_replacement_authorizes_only_the_change_it_made() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let (replaced, new_keys) = device_replacement_transition(&provider, &fixture);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = new_keys.endpoint_identity_ref.clone();
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        let mut endpoints = fixture.keys.clone();
        endpoints.push(new_keys);
        let cold_request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Activate,
            ),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                endpoints: endpoints.clone(),
            },
        );

        // Cold admission: the self-verifying record authorizes the replacement.
        let (claim, verified) =
            admit_replacement_cold_with_authority(&adapter, &replaced, &cold_request)
                .expect("a signed replacement admits the claim it made");
        assert_eq!(claim.operation(), ReplacementOperation::Activate);
        assert_eq!(claim.subject_identity_ref(), subject);
        assert_eq!(claim.source_device(), source);
        assert_eq!(claim.new_endpoint_identity_ref(), destination);
        assert_eq!(claim.authority_epoch(), 1);
        // The source device the destination superseded was admitted at epoch 0.
        assert_eq!(claim.superseded_epoch(), Some(0));
        assert_eq!(verified.state(), &replaced);

        // Snapshot catch-up reaches the same claim from the same record.
        let tip =
            admit_replacement_catch_up(&adapter, std::slice::from_ref(&replaced), &cold_request);
        let tip = tip.accepted().expect("catch-up admits the same claim");
        assert_eq!(tip.authority_epoch(), 1);
        assert_eq!(tip.superseded_epoch(), Some(0));

        // The session path admits the same signed transition; the still-active
        // second device is the session's presenting endpoint, because the
        // replaced source is no longer active.
        let request = ReplacementRequest::new(
            AuthoritySource::TrustedDevice,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Activate,
            ),
            ReplacementAdmission {
                predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                session: ReplacementSession {
                    authenticated: true,
                    authority_state_digest: verified.state_digest(),
                    endpoint_identity_ref: fixture.second_endpoint_identity_ref,
                    identity_state_digest: fixture.second_identity_state_digest,
                },
                endpoints,
            },
        );
        let (session_claim, _) = admit_replacement_with_authority(&adapter, &replaced, &request)
            .expect("the session path admits the same replacement");
        assert_eq!(session_claim.authority_epoch(), 1);
        assert_eq!(session_claim.superseded_epoch(), Some(0));

        // The same verified transition refuses every claim it did not make:
        // an already-active destination is not activated by it, and a Revoke
        // claim finds no revocation in it.
        let mut stale = cold_request.clone();
        stale.binding = ReplacementBinding::new(
            &subject,
            &source,
            hex(&fixture.second_endpoint_identity_ref),
            ReplacementOperation::Activate,
        );
        let refusal = admit_replacement_cold(&adapter, &replaced, &stale);
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::DestinationAlreadyActive),
            "the still-active second device was not activated by this transition"
        );
        let mut revoke = cold_request;
        revoke.binding = ReplacementBinding::new(
            &subject,
            &source,
            &destination,
            ReplacementOperation::Revoke,
        );
        let refusal = admit_replacement_cold(&adapter, &replaced, &revoke);
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::OperationMismatch),
            "the transition performed an activation, not a revocation"
        );
    }

    /// The cold paths bind a Revoke claim to the actual verified roster change
    /// and refuse every transition that never made it.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn an_unrelated_signed_transition_authorizes_no_claim() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let (replaced, new_keys) = device_replacement_transition(&provider, &fixture);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = new_keys.endpoint_identity_ref.clone();
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        let mut endpoints = fixture.keys.clone();
        endpoints.push(new_keys);
        let cold = ColdAdmission {
            predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
            endpoints: endpoints.clone(),
        };

        // (a) A recovery key rotation leaves the roster untouched: the
        // already-active second device is not activated by it, and the source
        // device it names is not retired by it either.
        let rotated = replacement_transition(&provider, &fixture);
        let request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                hex(&fixture.second_endpoint_identity_ref),
                ReplacementOperation::Activate,
            ),
            cold.clone(),
        );
        assert_eq!(
            admit_replacement_cold(&adapter, &rotated, &request).refusal(),
            Some(ReplacementAuthorityRefusal::DestinationAlreadyActive)
        );

        // (b) The destination must have superseded the named source: a
        // transition that admits a new device without retiring the source
        // made no replacement the claim binds.
        let admitted_only = {
            let management = pair(&provider, "management", 10);
            let mut state =
                successor_skeleton(&provider, &fixture.genesis, &management, "management")
                    .expect("successor skeleton");
            state["authorizedDevices"]
                .as_array_mut()
                .expect("roster")
                .push(device_entry(
                    &provider.sha256(b"synthetic-replacement:endpoint-new"),
                    &provider.sha256(b"synthetic-replacement:endpoint-state-new"),
                    &pair(&provider, "management", 80),
                    1,
                ));
            sort_devices(&mut state);
            let index = device_index(&state, &destination);
            sign_device_possession(
                &provider,
                &mut state,
                &pair(&provider, "management", 80),
                index,
            );
            sign_state(&provider, &mut state, &management, "authority-management")
                .expect("management authority signature");
            state
        };
        let request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Activate,
            ),
            cold.clone(),
        );
        assert_eq!(
            admit_replacement_cold(&adapter, &admitted_only, &request).refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "the source stayed active, so the transition replaced nothing"
        );

        // (c) A real revocation at epoch 2 is admitted and bound to the
        // destination's own admission epoch as the superseded one. The
        // predecessor carries the fresh-admission proof its acceptance
        // retained — the epoch-1 record is itself the admission the claim
        // names, so the proof is what shows the destination was new.
        let accepted_replacement = adapter
            .admit_state(&replaced, &cold)
            .expect("the replacement admits cold");
        let revoked = revocation_transition(
            &provider,
            &replaced,
            &super::decode_hex_32(&destination).expect("hex destination ref"),
        );
        let revoke_cold = ColdAdmission {
            predecessor: Some(accepted_replacement.predecessor()),
            endpoints: endpoints.clone(),
        };
        let revoke_request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            ),
            revoke_cold,
        );
        let decision = admit_replacement_cold(&adapter, &revoked, &revoke_request);
        let claim = decision
            .accepted()
            .expect("a signed revocation admits the claim it made");
        assert_eq!(claim.operation(), ReplacementOperation::Revoke);
        assert_eq!(claim.authority_epoch(), 2);
        assert_eq!(claim.superseded_epoch(), Some(1));
        let tip =
            admit_replacement_catch_up(&adapter, std::slice::from_ref(&revoked), &revoke_request);
        assert_eq!(
            tip.accepted()
                .expect("catch-up admits the same revocation")
                .authority_epoch(),
            2
        );

        // (d) A signed no-op successor revokes nothing: the already-revoked
        // destination is not revoked again by a later unrelated transition.
        let accepted_revoked = adapter
            .admit_state(
                &revoked,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(
                        accepted_replacement.authority().clone(),
                    )),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the revocation admits cold");
        let noop = no_op_transition(&provider, &revoked);
        let noop_request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            ),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(
                    accepted_revoked.into_authority(),
                )),
                endpoints,
            },
        );
        assert_eq!(
            admit_replacement_cold(&adapter, &noop, &noop_request).refusal(),
            Some(ReplacementAuthorityRefusal::OperationMismatch),
            "the destination was revoked by an earlier transition, not this one"
        );
        assert_eq!(
            admit_replacement_catch_up(&adapter, std::slice::from_ref(&noop), &noop_request)
                .refusal(),
            Some(ReplacementAuthorityRefusal::OperationMismatch),
            "catch-up binds the claim to the tip's change the same way"
        );
    }

    /// One signed transition may retire two devices while admitting one —
    /// the SDK's roster rules permit it (`validate_roster_transition`,
    /// `src/identity.rs`). The epoch match alone would then pair the
    /// destination with either retired device, so the binding refuses it:
    /// a transition whose verified roster changes leave the pair ambiguous
    /// authorizes no claim.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn an_ambiguous_same_epoch_change_authorizes_no_pair() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let second = hex(&fixture.second_endpoint_identity_ref);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Two devices retired at the destination's own admission epoch:
        // either one could be the source the destination superseded.
        let management = pair(&provider, "management", 10);
        let new_device = pair(&provider, "management", 80);
        let new_ref = provider.sha256(b"synthetic-replacement:endpoint-new");
        let new_digest = provider.sha256(b"synthetic-replacement:endpoint-state-new");
        let mut doubled =
            successor_skeleton(&provider, &fixture.genesis, &management, "management")
                .expect("successor skeleton");
        for retired_ref in [
            &fixture.endpoint_identity_ref,
            &fixture.second_endpoint_identity_ref,
        ] {
            let index = device_index(&doubled, &hex(retired_ref));
            doubled["authorizedDevices"][index]["deviceStatus"] = json!("revoked");
            doubled["authorizedDevices"][index]["revokedAuthorityEpoch"] = json!(1);
        }
        doubled["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .push(device_entry(&new_ref, &new_digest, &new_device, 1));
        sort_devices(&mut doubled);
        let new_index = device_index(&doubled, &hex(&new_ref));
        sign_device_possession(&provider, &mut doubled, &new_device, new_index);
        sign_state(&provider, &mut doubled, &management, "authority-management")
            .expect("management authority signature");
        let destination = hex(&new_ref);
        let mut endpoints = fixture.keys.clone();
        endpoints.push(ReplacementEndpointKeys {
            endpoint_identity_ref: destination.clone(),
            identity_state_digest: hex(&new_digest),
            ed25519_key_id: hex(&new_device.ed25519_key_id),
            ed25519_public: hex(&new_device.ed25519_public),
            ml_dsa_65_key_id: hex(&new_device.ml_dsa_65_key_id),
            ml_dsa_65_public: hex(&new_device.ml_dsa_65_public),
        });
        let cold = ColdAdmission {
            predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
            endpoints,
        };
        for named_source in [&source, &second] {
            let request = ColdReplacementRequest::new(
                AuthoritySource::SavedRecoveryCredential,
                ReplacementBinding::new(
                    &subject,
                    named_source,
                    &destination,
                    ReplacementOperation::Activate,
                ),
                cold.clone(),
            );
            assert_eq!(
                admit_replacement_cold(&adapter, &doubled, &request).refusal(),
                Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
                "the epoch stamps two retired sources, so no pair is bound"
            );
            assert_eq!(
                admit_replacement_catch_up(&adapter, std::slice::from_ref(&doubled), &request)
                    .refusal(),
                Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
                "catch-up reads the same ambiguous change set"
            );
        }
    }

    /// The SDK permits a later snapshot to drop an already-revoked roster
    /// entry (`validate_roster_transition`, `src/identity.rs`). A verified
    /// catch-up chain can then contain the replacement and end with its
    /// destination still active while the retired source is gone from the
    /// tip: the pairing is decided on the snapshot that recorded it, and the
    /// destination's required status is still confirmed at the verified tip.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_pruned_source_keeps_the_pairing_the_recording_snapshot_made() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let (replaced, new_keys) = device_replacement_transition(&provider, &fixture);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = new_keys.endpoint_identity_ref.clone();
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 2 prunes the retired source: the roster keeps the still-active
        // second device and the active destination, and the SDK admits the
        // drop because the entry it removes was already revoked.
        let management = pair(&provider, "management", 10);
        let mut pruned = successor_skeleton(&provider, &replaced, &management, "management")
            .expect("successor skeleton");
        let source_index = device_index(&pruned, &source);
        pruned["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .remove(source_index);
        sign_state(&provider, &mut pruned, &management, "authority-management")
            .expect("management authority signature");

        let mut endpoints = fixture.keys.clone();
        endpoints.push(new_keys);
        let binding = ReplacementBinding::new(
            &subject,
            &source,
            &destination,
            ReplacementOperation::Activate,
        );
        let request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            binding.clone(),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                endpoints: endpoints.clone(),
            },
        );

        // The tip alone proves nothing: the retired source is gone from it,
        // and the activation the claim names predates the span it would have
        // to advance.
        let accepted_replacement = adapter
            .admit_state(
                &replaced,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the replacement admits cold");
        let tip_only = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            binding,
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(
                    accepted_replacement.authority().clone(),
                )),
                endpoints,
            },
        );
        assert_eq!(
            admit_replacement_cold(&adapter, &pruned, &tip_only).refusal(),
            Some(ReplacementAuthorityRefusal::DestinationAlreadyActive),
            "a tip that never shows the pairing cannot bind the claim"
        );

        // The verified chain does: snapshot 1 recorded the replacement, and
        // the tip still holds the destination active.
        let caught_up = admit_replacement_catch_up(&adapter, &[replaced, pruned], &request);
        let claim = caught_up
            .accepted()
            .expect("the chain carries the pairing the pruned tip lost");
        assert_eq!(claim.operation(), ReplacementOperation::Activate);
        assert_eq!(claim.authority_epoch(), 2);
        assert_eq!(claim.source_device(), source);
        assert_eq!(claim.new_endpoint_identity_ref(), destination);
        assert_eq!(
            claim.superseded_epoch(),
            Some(0),
            "the superseded epoch is read from the recording snapshot"
        );
    }

    /// The accepted predecessor is itself a verified record. When it is the
    /// transition that admitted the destination, it preserves the pair the
    /// successor pruned: a Revoke claim whose verified tip already dropped
    /// the retired source still binds, because the evidence comes from the
    /// admission record the caller accepted — not from the pruned roster.
    /// The newness evidence is the proof that acceptance retained: the
    /// destination is among the endpoints the record's own transition
    /// admitted fresh.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn the_accepted_predecessor_supplies_the_pairing_the_tip_pruned() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let (replaced, new_keys) = device_replacement_transition(&provider, &fixture);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = new_keys.endpoint_identity_ref.clone();
        let new_ref = super::decode_hex_32(&destination).expect("hex destination ref");
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 2 drops the retired source; epoch 3 revokes the destination.
        // The tip's roster no longer shows what epoch 1 stamped.
        let management = pair(&provider, "management", 10);
        let mut pruned = successor_skeleton(&provider, &replaced, &management, "management")
            .expect("successor skeleton");
        let source_index = device_index(&pruned, &source);
        pruned["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .remove(source_index);
        sign_state(&provider, &mut pruned, &management, "authority-management")
            .expect("management authority signature");
        let revoked = revocation_transition(&provider, &pruned, &new_ref);

        let mut endpoints = fixture.keys.clone();
        endpoints.push(new_keys);
        let accepted_replacement = adapter
            .admit_state(
                &replaced,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the replacement admits cold");
        assert!(
            accepted_replacement
                .fresh_admissions()
                .contains(&destination),
            "the destination is the endpoint the transition admitted fresh"
        );

        // The accepted tip is the epoch-1 admission record itself. The
        // chain that succeeds it has already dropped the source, yet the
        // pairing the claim needs is the one that record preserved — and the
        // fresh-admission proof its acceptance retained is what proves the
        // destination was new.
        let request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            ),
            ColdAdmission {
                predecessor: Some(accepted_replacement.predecessor()),
                endpoints,
            },
        );
        let caught_up = admit_replacement_catch_up(&adapter, &[pruned, revoked], &request);
        let claim = caught_up
            .accepted()
            .expect("the predecessor preserves the pair the pruned tip lost");
        assert_eq!(claim.operation(), ReplacementOperation::Revoke);
        assert_eq!(claim.authority_epoch(), 3);
        assert_eq!(claim.source_device(), source);
        assert_eq!(claim.new_endpoint_identity_ref(), destination);
        assert_eq!(claim.superseded_epoch(), Some(1));
    }

    /// A snapshot taken after the admission can already have dropped an
    /// entry the admission retired — and then the pruned roster hides the
    /// ambiguity instead of revealing it. Here one transition retires two
    /// devices and admits the destination; a later snapshot drops one of
    /// the retired devices, so its roster stamps only one retirement at
    /// the admission epoch and a uniqueness check against it would bind
    /// an ambiguous pair. The binding requires the verified record that
    /// recorded the admission — a chain element at that epoch, or the
    /// accepted predecessor when it is that record — and refuses the
    /// claim when neither preserves it.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_pruned_roster_is_not_evidence_of_the_pair() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let second = hex(&fixture.second_endpoint_identity_ref);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 1 retires two devices and admits the destination: either
        // retired device could be the named source.
        let management = pair(&provider, "management", 10);
        let new_device = pair(&provider, "management", 80);
        let new_ref = provider.sha256(b"synthetic-replacement:endpoint-new");
        let new_digest = provider.sha256(b"synthetic-replacement:endpoint-state-new");
        let mut doubled =
            successor_skeleton(&provider, &fixture.genesis, &management, "management")
                .expect("successor skeleton");
        for retired_ref in [
            &fixture.endpoint_identity_ref,
            &fixture.second_endpoint_identity_ref,
        ] {
            let index = device_index(&doubled, &hex(retired_ref));
            doubled["authorizedDevices"][index]["deviceStatus"] = json!("revoked");
            doubled["authorizedDevices"][index]["revokedAuthorityEpoch"] = json!(1);
        }
        doubled["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .push(device_entry(&new_ref, &new_digest, &new_device, 1));
        sort_devices(&mut doubled);
        let new_index = device_index(&doubled, &hex(&new_ref));
        sign_device_possession(&provider, &mut doubled, &new_device, new_index);
        sign_state(&provider, &mut doubled, &management, "authority-management")
            .expect("management authority signature");
        let destination = hex(&new_ref);

        // Epoch 2 drops one of the retired devices — the SDK permits
        // pruning an already-revoked entry — so the roster it leaves
        // stamps only one retirement at the admission epoch.
        let mut pruned = successor_skeleton(&provider, &doubled, &management, "management")
            .expect("successor skeleton");
        let second_index = device_index(&pruned, &second);
        pruned["authorizedDevices"]
            .as_array_mut()
            .expect("roster")
            .remove(second_index);
        sign_state(&provider, &mut pruned, &management, "authority-management")
            .expect("management authority signature");

        // Epoch 3 revokes the destination. Its roster still holds the
        // source retired at epoch 1 — and nothing else stamped then.
        let revoked = revocation_transition(&provider, &pruned, &new_ref);

        let mut endpoints = fixture.keys.clone();
        endpoints.push(ReplacementEndpointKeys {
            endpoint_identity_ref: destination.clone(),
            identity_state_digest: hex(&new_digest),
            ed25519_key_id: hex(&new_device.ed25519_key_id),
            ed25519_public: hex(&new_device.ed25519_public),
            ml_dsa_65_key_id: hex(&new_device.ml_dsa_65_key_id),
            ml_dsa_65_public: hex(&new_device.ml_dsa_65_public),
        });

        // The chain is genuine — each record verifies — but the request
        // the binding sees carries only the post-admission views: the
        // accepted tip is epoch 2, and the presented snapshot is epoch 3.
        let accepted_doubled = adapter
            .admit_state(
                &doubled,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the doubled transition admits cold");
        let accepted_pruned = adapter
            .admit_state(
                &pruned,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(
                        accepted_doubled.authority().clone(),
                    )),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the pruning transition admits cold");

        let revoke_binding = || {
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            )
        };
        let hidden = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            revoke_binding(),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(
                    accepted_pruned.into_authority(),
                )),
                endpoints: endpoints.clone(),
            },
        );
        assert_eq!(
            admit_replacement_catch_up(&adapter, std::slice::from_ref(&revoked), &hidden).refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "a pruned roster cannot prove the pair was unique"
        );
        assert_eq!(
            admit_replacement_cold(&adapter, &revoked, &hidden).refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "cold admission reads the same incomplete evidence"
        );

        // When the verified chain does carry the epoch-1 record, the same
        // claim still refuses — the complete evidence shows both retired
        // devices, so the pair is ambiguous either way.
        let recorded = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            revoke_binding(),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                endpoints,
            },
        );
        assert_eq!(
            admit_replacement_catch_up(&adapter, &[doubled, pruned, revoked], &recorded).refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "the recording snapshot shows the ambiguity the pruned tip hid"
        );
    }

    /// The SDK restamps `admittedAuthorityEpoch` to the transition's own
    /// epoch when an already-rostered endpoint changes its identity-state
    /// digest (`validate_roster_transition`, `src/identity.rs`). One signed
    /// transition can then revoke a device and present the restamped
    /// endpoint as the replacement: the admission record's evidence is
    /// identical to a real admission. The roster immediately before that
    /// transition decides — it still holds the destination, so the claim
    /// is refused instead of binding an already-rostered endpoint as a new
    /// activation.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_restamped_endpoint_is_not_a_new_activation() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = hex(&fixture.second_endpoint_identity_ref);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 1: the already-active second device rotates its identity
        // state — the SDK admits the change only when the entry's
        // admission epoch is restamped to this transition — and the same
        // transition retires the first device. The epoch evidence is
        // identical to a genuine admission that superseded the source.
        let management = pair(&provider, "management", 10);
        let rotated_device = pair(&provider, "management", 80);
        let rotated_digest = provider.sha256(b"synthetic-replacement:endpoint-state-rotated");
        let mut restamped =
            successor_skeleton(&provider, &fixture.genesis, &management, "management")
                .expect("successor skeleton");
        let source_index = device_index(&restamped, &source);
        restamped["authorizedDevices"][source_index]["deviceStatus"] = json!("revoked");
        restamped["authorizedDevices"][source_index]["revokedAuthorityEpoch"] = json!(1);
        let second_index = device_index(&restamped, &destination);
        restamped["authorizedDevices"][second_index] = device_entry(
            &fixture.second_endpoint_identity_ref,
            &rotated_digest,
            &rotated_device,
            1,
        );
        sort_devices(&mut restamped);
        let second_index = device_index(&restamped, &destination);
        sign_device_possession(&provider, &mut restamped, &rotated_device, second_index);
        sign_state(
            &provider,
            &mut restamped,
            &management,
            "authority-management",
        )
        .expect("management authority signature");
        let restamped = adapter
            .admit_state(
                &restamped,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: {
                        let mut endpoints = fixture.keys.clone();
                        endpoints.push(ReplacementEndpointKeys {
                            endpoint_identity_ref: destination.clone(),
                            identity_state_digest: hex(&rotated_digest),
                            ed25519_key_id: hex(&rotated_device.ed25519_key_id),
                            ed25519_public: hex(&rotated_device.ed25519_public),
                            ml_dsa_65_key_id: hex(&rotated_device.ml_dsa_65_key_id),
                            ml_dsa_65_public: hex(&rotated_device.ml_dsa_65_public),
                        });
                        endpoints
                    },
                },
            )
            .expect("the SDK admits a restamp plus one revocation");
        assert_eq!(
            restamped.state()["authorizedDevices"][device_index(restamped.state(), &destination)]["admittedAuthorityEpoch"],
            json!(1),
            "the SDK restamps the admission epoch on the rotated endpoint"
        );

        // Epoch 2 revokes the restamped endpoint, so both claims reach the
        // binding: the Activate on the restamp record itself, the Revoke on
        // its successor.
        let revoked = revocation_transition(
            &provider,
            restamped.state(),
            &fixture.second_endpoint_identity_ref,
        );
        let mut endpoints = fixture.keys.clone();
        endpoints.push(ReplacementEndpointKeys {
            endpoint_identity_ref: destination.clone(),
            identity_state_digest: hex(&rotated_digest),
            ed25519_key_id: hex(&rotated_device.ed25519_key_id),
            ed25519_public: hex(&rotated_device.ed25519_public),
            ml_dsa_65_key_id: hex(&rotated_device.ml_dsa_65_key_id),
            ml_dsa_65_public: hex(&rotated_device.ml_dsa_65_public),
        });
        let predecessor = || Some(ReplacementPredecessor::new(fixture.accepted.clone()));
        let activate = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Activate,
            ),
            ColdAdmission {
                predecessor: predecessor(),
                endpoints: endpoints.clone(),
            },
        );
        for (path, decision) in [
            (
                "cold",
                admit_replacement_cold(&adapter, restamped.state(), &activate),
            ),
            (
                "catch-up",
                admit_replacement_catch_up(
                    &adapter,
                    std::slice::from_ref(restamped.state()),
                    &activate,
                ),
            ),
        ] {
            assert_eq!(
                decision.refusal(),
                Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
                "{path}: the pre-admission roster already held the destination"
            );
        }

        // The Revoke claim reads the same evidence through the verified
        // chain: the epoch-1 snapshot records the restamp, and the
        // predecessor — the roster immediately before it — still holds the
        // destination.
        let revoke = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            ),
            ColdAdmission {
                predecessor: predecessor(),
                endpoints,
            },
        );
        assert_eq!(
            admit_replacement_catch_up(&adapter, &[restamped.state().clone(), revoked], &revoke)
                .refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "a restamped endpoint is not the new device the claim pairs"
        );
    }

    /// When the accepted predecessor *is* the destination's admission
    /// record, the roster immediately before that transition is nowhere
    /// among the claim's verified evidence — the only remaining proof the
    /// destination was new is the one that acceptance retained. The record
    /// here restamps an endpoint the genesis roster already held: its
    /// acceptance retains no fresh-admission proof for it, so the Revoke
    /// claim that pairs it with the retired source is refused — presented
    /// with the retained proof or with the bare record alike.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn the_admission_record_must_prove_the_destination_was_new() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = hex(&fixture.second_endpoint_identity_ref);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 1: the already-active second device rotates its identity
        // state — restamped to this epoch — and the same transition retires
        // the first device. The record is indistinguishable from a genuine
        // replacement admission until the roster before it is read.
        let management = pair(&provider, "management", 10);
        let rotated_device = pair(&provider, "management", 80);
        let rotated_digest = provider.sha256(b"synthetic-replacement:endpoint-state-rotated");
        let mut restamped =
            successor_skeleton(&provider, &fixture.genesis, &management, "management")
                .expect("successor skeleton");
        let source_index = device_index(&restamped, &source);
        restamped["authorizedDevices"][source_index]["deviceStatus"] = json!("revoked");
        restamped["authorizedDevices"][source_index]["revokedAuthorityEpoch"] = json!(1);
        let second_index = device_index(&restamped, &destination);
        restamped["authorizedDevices"][second_index] = device_entry(
            &fixture.second_endpoint_identity_ref,
            &rotated_digest,
            &rotated_device,
            1,
        );
        sort_devices(&mut restamped);
        let second_index = device_index(&restamped, &destination);
        sign_device_possession(&provider, &mut restamped, &rotated_device, second_index);
        sign_state(
            &provider,
            &mut restamped,
            &management,
            "authority-management",
        )
        .expect("management authority signature");

        let endpoints = {
            let mut endpoints = fixture.keys.clone();
            endpoints.push(ReplacementEndpointKeys {
                endpoint_identity_ref: destination.clone(),
                identity_state_digest: hex(&rotated_digest),
                ed25519_key_id: hex(&rotated_device.ed25519_key_id),
                ed25519_public: hex(&rotated_device.ed25519_public),
                ml_dsa_65_key_id: hex(&rotated_device.ml_dsa_65_key_id),
                ml_dsa_65_public: hex(&rotated_device.ml_dsa_65_public),
            });
            endpoints
        };
        let restamped = adapter
            .admit_state(
                &restamped,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the SDK admits a restamp plus one revocation");
        assert!(
            restamped.fresh_admissions().is_empty(),
            "the restamp rostered nothing the genesis roster did not hold"
        );

        // Epoch 2 revokes the restamped endpoint so the claim reaches the
        // binding. The roster before the admission record is not among the
        // verified evidence — the chain starts after it, and the accepted
        // predecessor is it.
        let revoked = revocation_transition(
            &provider,
            restamped.state(),
            &fixture.second_endpoint_identity_ref,
        );
        let revoke_binding = || {
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            )
        };

        // The retained proof names no fresh admission for the destination:
        // the same Revoke claim the previous test's genuine replacement
        // authorized is refused here.
        let retained = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            revoke_binding(),
            ColdAdmission {
                predecessor: Some(restamped.predecessor()),
                endpoints: endpoints.clone(),
            },
        );
        for (path, decision) in [
            (
                "catch-up",
                admit_replacement_catch_up(&adapter, std::slice::from_ref(&revoked), &retained),
            ),
            (
                "cold",
                admit_replacement_cold(&adapter, &revoked, &retained),
            ),
        ] {
            assert_eq!(
                decision.refusal(),
                Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
                "{path}: a restamped endpoint is not the new device the claim pairs"
            );
        }

        // The bare record is refused the same way: without the retained
        // proof, the admission record alone cannot prove the destination
        // was new.
        let bare = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            revoke_binding(),
            ColdAdmission {
                predecessor: Some(ReplacementPredecessor::new(restamped.authority().clone())),
                endpoints,
            },
        );
        assert_eq!(
            admit_replacement_catch_up(&adapter, std::slice::from_ref(&revoked), &bare).refusal(),
            Some(ReplacementAuthorityRefusal::SourceDeviceMismatch),
            "the bare admission record carries no fresh-admission proof"
        );
    }

    /// An authenticated session that presents the already-accepted record is
    /// re-admitted by the SDK with that record unchanged. The retained
    /// authority must carry the fresh-admission proof the first acceptance
    /// computed forward — diffing the returned roster against the identical
    /// predecessor roster yields an empty set, and a later revocation claim
    /// whose predecessor is that record has no other evidence the destination
    /// was new.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn a_re_admitted_record_keeps_the_fresh_admission_proof() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let (replaced, new_keys) = device_replacement_transition(&provider, &fixture);
        let subject = hex(&fixture.accepted.user_identity_ref);
        let source = hex(&fixture.endpoint_identity_ref);
        let destination = new_keys.endpoint_identity_ref.clone();
        let new_ref = super::decode_hex_32(&destination).expect("hex destination ref");
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        // Epoch 1 admits the destination; the acceptance retains the proof.
        let mut endpoints = fixture.keys.clone();
        endpoints.push(new_keys);
        let accepted = adapter
            .admit_state(
                &replaced,
                &ColdAdmission {
                    predecessor: Some(ReplacementPredecessor::new(fixture.accepted.clone())),
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the replacement admits cold");
        assert!(
            accepted.fresh_admissions().contains(&destination),
            "the destination is the endpoint the transition admitted fresh"
        );

        // An authenticated session presents the accepted record itself: the
        // SDK returns it unchanged, so the retained authority must carry the
        // proof forward rather than recompute an empty set. The still-active
        // second device presents, because the transition retired the first.
        let readmitted = adapter
            .admit(
                accepted.state(),
                &ReplacementAdmission {
                    predecessor: Some(accepted.predecessor()),
                    session: ReplacementSession {
                        authenticated: true,
                        authority_state_digest: accepted.state_digest(),
                        endpoint_identity_ref: fixture.second_endpoint_identity_ref,
                        identity_state_digest: fixture.second_identity_state_digest,
                    },
                    endpoints: endpoints.clone(),
                },
            )
            .expect("the accepted record is re-admitted as itself");
        assert_eq!(readmitted.state_digest(), accepted.state_digest());
        assert_eq!(
            readmitted.fresh_admissions(),
            accepted.fresh_admissions(),
            "re-admission carries the retained proof forward"
        );

        // Epoch 2 revokes the destination. The re-admitted record is the
        // destination's own admission record, so the carried-forward proof
        // is the only evidence the destination was new.
        let revoked = revocation_transition(&provider, &replaced, &new_ref);
        let request = ColdReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            ReplacementBinding::new(
                &subject,
                &source,
                &destination,
                ReplacementOperation::Revoke,
            ),
            ColdAdmission {
                predecessor: Some(readmitted.predecessor()),
                endpoints,
            },
        );
        for (path, decision) in [
            ("cold", admit_replacement_cold(&adapter, &revoked, &request)),
            (
                "catch-up",
                admit_replacement_catch_up(&adapter, std::slice::from_ref(&revoked), &request),
            ),
        ] {
            let claim = decision.accepted().unwrap_or_else(|| {
                panic!("{path}: the re-admitted record still proves the destination was new")
            });
            assert_eq!(claim.operation(), ReplacementOperation::Revoke);
            assert_eq!(claim.authority_epoch(), 2);
            assert_eq!(claim.source_device(), source);
            assert_eq!(claim.new_endpoint_identity_ref(), destination);
            assert_eq!(claim.superseded_epoch(), Some(1));
        }
    }
}
