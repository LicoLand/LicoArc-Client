//! The composition point between signed-transition verification and the binding.
//!
//! Two halves make one device replacement, and neither names the other:
//! [`crate::replacement_admission`] holds the fixed-SDK delegation, while the
//! binding vocabulary in [`crate::replacement`] is the caller-owned replacement
//! contract and declares no SDK types of its own. This module is where they
//! meet, exactly as the adapters beside it are where the caller-owned ports
//! meet the SDK's own traits.
//!
//! It adds no protocol policy. The SDK alone decides whether the signed
//! transition, the possession proof and the authenticated session hold; this
//! module only compares what the SDK verified against what the caller asked for,
//! and refuses every mismatch:
//!
//! * **the credential** — the caller must really hold one of the two accepted
//!   sources. With neither, the call is refused before the SDK is reached, so
//!   ordinary backup, relay and peer input admits nothing.
//! * **replay** — a presented record must advance past the epoch already
//!   accepted, decided from the caller's own durable epoch before the SDK is
//!   reached, so a superseded roster is never re-verified into acceptance.
//! * **the subject** — the verified record's `userIdentityRef` must be the
//!   subject the binding names.
//! * **the operation** — the successor roster's device status for the
//!   destination decides whether the transition activates or revokes, and the
//!   binding's operation must be that one.
//! * **the new identity** — the destination must be a distinct endpoint the
//!   successor roster really holds at this epoch, never the source identity
//!   itself, so new endpoint keys never derive from an imported source identity.
//! * **the source device** — the successor roster must account for it, so
//!   authority that never mentions the device being replaced belongs to another
//!   replacement.

use crate::{
    AcceptedReplacement, AuthoritySource, ReplacementAuthority, ReplacementAuthorityRefusal,
    ReplacementBinding, ReplacementOperation,
};
use crate::{
    ColdAdmission, ReplacementAdmission, ReplacementAdmissionRefusal, ReplacementPredecessor,
    SdkReplacementAuthority, VerifiedReplacementAuthority,
};
use serde_json::Value;

/// One replacement request in the caller's own terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementRequest {
    /// Which accepted source the caller resolved for this request.
    pub source: AuthoritySource,
    /// The subject, source device, new identity and operation it is about.
    pub binding: ReplacementBinding,
    /// The authority and session facts the fixed SDK decides on.
    pub admission: ReplacementAdmission,
}

impl ReplacementRequest {
    /// Builds one request from the caller's resolved credential and its binding.
    #[must_use]
    pub const fn new(
        source: AuthoritySource,
        binding: ReplacementBinding,
        admission: ReplacementAdmission,
    ) -> Self {
        Self {
            source,
            binding,
            admission,
        }
    }
}

/// One replacement request whose authority material arrived with no
/// authenticated session.
///
/// This is the saved-recovery-credential shape: a fresh device holds an
/// offline record or a relayed snapshot chain, not a live session from a
/// roster device. The credential, replay and binding rules are identical to
/// [`ReplacementRequest`]; only the SDK entry that verifies the material
/// differs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdReplacementRequest {
    /// Which accepted source the caller resolved for this request.
    pub source: AuthoritySource,
    /// The subject, source device, new identity and operation it is about.
    pub binding: ReplacementBinding,
    /// The authority facts the fixed SDK decides on, without a session.
    pub admission: ColdAdmission,
}

impl ColdReplacementRequest {
    /// Builds one cold request from the resolved credential and its binding.
    #[must_use]
    pub const fn new(
        source: AuthoritySource,
        binding: ReplacementBinding,
        admission: ColdAdmission,
    ) -> Self {
        Self {
            source,
            binding,
            admission,
        }
    }
}

/// Admits one device replacement, or refuses without a caller-owned effect.
///
/// The order is deliberate: the credential and the replay are decided from
/// caller-owned values *before* the SDK is reached, so an unauthorized or
/// replayed request never becomes an SDK call, and a mismatch discovered after
/// the SDK call never becomes a write.
#[must_use]
pub fn admit_replacement(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ReplacementRequest,
) -> ReplacementAuthority {
    match verify_replacement(authority, state, request) {
        Ok(verified) => ReplacementAuthority::Authorized(verified.claim),
        Err(refusal) => ReplacementAuthority::Refused(refusal),
    }
}

/// Admits one replacement and keeps the SDK's accepted authority as well.
///
/// This is the durable variant: a caller that persists an activation record
/// needs the accepted state as the predecessor a later transition must name,
/// and the session facts that were actually admitted.
pub fn admit_replacement_with_authority(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ReplacementRequest,
) -> Result<(AcceptedReplacement, VerifiedReplacementAuthority), ReplacementAuthorityRefusal> {
    let verified = verify_replacement(authority, state, request)?;
    Ok((verified.claim, verified.authority))
}

/// Admits one replacement whose authority material arrived with no
/// authenticated session, or refuses without a caller-owned effect.
///
/// The credential, replay and binding rules are the same as
/// [`admit_replacement`]; the SDK verifies the self-authenticating record
/// itself, which is what a saved recovery credential or an offline export can
/// deliver.
#[must_use]
pub fn admit_replacement_cold(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ColdReplacementRequest,
) -> ReplacementAuthority {
    match verify_replacement_cold(authority, state, request) {
        Ok(verified) => ReplacementAuthority::Authorized(verified.claim),
        Err(refusal) => ReplacementAuthority::Refused(refusal),
    }
}

/// [`admit_replacement_cold`] keeping the SDK's accepted authority as well.
pub fn admit_replacement_cold_with_authority(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ColdReplacementRequest,
) -> Result<(AcceptedReplacement, VerifiedReplacementAuthority), ReplacementAuthorityRefusal> {
    let verified = verify_replacement_cold(authority, state, request)?;
    Ok((verified.claim, verified.authority))
}

/// Admits one replacement from a chain of authority snapshots with no
/// authenticated session, or refuses without a caller-owned effect.
///
/// A device that was offline across several transitions catches up through
/// the snapshots it missed; the replay guard compares the tip snapshot's
/// epoch against the caller's accepted epoch, and the binding compares the
/// tip the SDK verified.
#[must_use]
pub fn admit_replacement_catch_up(
    authority: &SdkReplacementAuthority,
    snapshots: &[Value],
    request: &ColdReplacementRequest,
) -> ReplacementAuthority {
    match verify_replacement_catch_up(authority, snapshots, request) {
        Ok(verified) => ReplacementAuthority::Authorized(verified.claim),
        Err(refusal) => ReplacementAuthority::Refused(refusal),
    }
}

/// [`admit_replacement_catch_up`] keeping the SDK's accepted tip authority.
pub fn admit_replacement_catch_up_with_authority(
    authority: &SdkReplacementAuthority,
    snapshots: &[Value],
    request: &ColdReplacementRequest,
) -> Result<(AcceptedReplacement, VerifiedReplacementAuthority), ReplacementAuthorityRefusal> {
    let verified = verify_replacement_catch_up(authority, snapshots, request)?;
    Ok((verified.claim, verified.authority))
}

/// What the composition verified, before it is reduced to one claim.
struct VerifiedBinding {
    claim: AcceptedReplacement,
    authority: VerifiedReplacementAuthority,
}

/// The checks every path decides from caller-owned values before the SDK is
/// reached: a credential that can authorize, and a presented record that
/// advances past the epoch already accepted.
fn admit_preflight(
    source: AuthoritySource,
    binding: &ReplacementBinding,
    predecessor: Option<&ReplacementPredecessor>,
    presented: &Value,
) -> Result<Option<u64>, ReplacementAuthorityRefusal> {
    // 1. The caller must really hold one of the two accepted sources. Ordinary
    //    backup, relay and peer input arrives as `None` and stops here, before
    //    any store, transport or effect is named.
    if !source.can_authorize() {
        return Err(ReplacementAuthorityRefusal::NoTrustedAuthority);
    }

    // 2. Replay is decided from the caller's own accepted epoch, so a superseded
    //    roster is refused rather than re-verified into acceptance.
    let accepted_epoch = predecessor.map(|predecessor| predecessor.epoch());
    if let Some(accepted_epoch) = accepted_epoch {
        binding.replayed_at(accepted_epoch, read_epoch(presented)?)?;
    }
    Ok(accepted_epoch)
}

fn verify_replacement(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    let superseded_epoch = admit_preflight(
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        state,
    )?;
    // 3. The SDK's own decision on the transition, the possession proof and the
    //    authenticated session. The three are not separable from the caller's
    //    side, so every refusal is one class.
    let verified = authority
        .admit(state, &request.admission)
        .map_err(map_admission_refusal)?;
    verify_binding(verified, request.source, &request.binding, superseded_epoch)
}

fn verify_replacement_cold(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ColdReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    let superseded_epoch = admit_preflight(
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        state,
    )?;
    let verified = authority
        .admit_state(state, &request.admission)
        .map_err(map_admission_refusal)?;
    verify_binding(verified, request.source, &request.binding, superseded_epoch)
}

fn verify_replacement_catch_up(
    authority: &SdkReplacementAuthority,
    snapshots: &[Value],
    request: &ColdReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    // The replay guard reads the tip's epoch; an empty chain has no tip, so a
    // caller with an accepted epoch reads an unreadable authority, and a caller
    // without one is refused by the SDK's own empty-chain bound.
    let superseded_epoch = admit_preflight(
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        snapshots.last().unwrap_or(&Value::Null),
    )?;
    let verified = authority
        .catch_up(snapshots, &request.admission)
        .map_err(map_admission_refusal)?;
    verify_binding(verified, request.source, &request.binding, superseded_epoch)
}

/// The binding comparison, against the verified record's own values.
fn verify_binding(
    verified: VerifiedReplacementAuthority,
    source: AuthoritySource,
    binding: &ReplacementBinding,
    superseded_epoch: Option<u64>,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    let verified_state = verified.state();

    // 4. The binding comparison, against the verified record's own values.
    if read_text(verified_state, "userIdentityRef")? != binding.subject_identity_ref() {
        return Err(ReplacementAuthorityRefusal::SubjectMismatch);
    }
    if binding.new_endpoint_identity_ref() == binding.source_device() {
        return Err(ReplacementAuthorityRefusal::NewIdentityMismatch);
    }

    let destination = read_device(verified_state, binding.new_endpoint_identity_ref())
        .ok_or(ReplacementAuthorityRefusal::NewIdentityMismatch)?;
    let operation = match read_text(destination, "deviceStatus")? {
        "active" => ReplacementOperation::Activate,
        "revoked" => ReplacementOperation::Revoke,
        _ => return Err(ReplacementAuthorityRefusal::NewIdentityMismatch),
    };
    if operation != binding.operation() {
        return Err(ReplacementAuthorityRefusal::OperationMismatch);
    }

    // The successor roster must account for the device being replaced. An
    // authority that never mentions it is about a different replacement.
    if read_device(verified_state, binding.source_device()).is_none() {
        return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch);
    }

    let claim = AcceptedReplacement::verified(
        source,
        binding,
        verified.authority_epoch(),
        verified.state_digest(),
        superseded_epoch,
    );
    Ok(VerifiedBinding {
        claim,
        authority: verified,
    })
}

fn read_epoch(state: &Value) -> Result<u64, ReplacementAuthorityRefusal> {
    state
        .get("authorityEpoch")
        .and_then(Value::as_u64)
        .ok_or(ReplacementAuthorityRefusal::UnreadableAuthority)
}

fn read_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReplacementAuthorityRefusal> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ReplacementAuthorityRefusal::UnreadableAuthority)
}

fn read_device<'a>(state: &'a Value, endpoint_identity_ref: &str) -> Option<&'a Value> {
    state
        .get("authorizedDevices")?
        .as_array()?
        .iter()
        .find(|device| {
            device.get("endpointIdentityRef").and_then(Value::as_str) == Some(endpoint_identity_ref)
        })
}

const fn map_admission_refusal(
    refusal: ReplacementAdmissionRefusal,
) -> ReplacementAuthorityRefusal {
    match refusal {
        ReplacementAdmissionRefusal::NoAdmittedLine => {
            ReplacementAuthorityRefusal::NoTrustedAuthority
        }
        ReplacementAdmissionRefusal::VerificationRefused
        | ReplacementAdmissionRefusal::UnreadableKeys => {
            ReplacementAuthorityRefusal::VerificationRefused
        }
    }
}
