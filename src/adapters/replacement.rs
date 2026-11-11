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
    ReplacementAdmission, ReplacementAdmissionRefusal, SdkReplacementAuthority,
    VerifiedReplacementAuthority,
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

/// What the composition verified, before it is reduced to one claim.
struct VerifiedBinding {
    claim: AcceptedReplacement,
    authority: VerifiedReplacementAuthority,
}

fn verify_replacement(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    let binding = &request.binding;

    // 1. The caller must really hold one of the two accepted sources. Ordinary
    //    backup, relay and peer input arrives as `None` and stops here, before
    //    any store, transport or effect is named.
    if !request.source.can_authorize() {
        return Err(ReplacementAuthorityRefusal::NoTrustedAuthority);
    }

    // 2. Replay is decided from the caller's own accepted epoch, so a superseded
    //    roster is refused rather than re-verified into acceptance.
    let accepted_epoch = request
        .admission
        .predecessor
        .as_ref()
        .map_or(0, |predecessor| predecessor.epoch());
    if request.admission.predecessor.is_some() {
        let presented = read_epoch(state)?;
        binding.replayed_at(accepted_epoch, presented)?;
    }

    // 3. The SDK's own decision on the transition, the possession proof and the
    //    authenticated session. The three are not separable from the caller's
    //    side, so every refusal is one class.
    let verified = authority
        .admit(state, &request.admission)
        .map_err(map_admission_refusal)?;
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
        request.source,
        binding,
        verified.authority_epoch(),
        verified.state_digest(),
        request
            .admission
            .predecessor
            .as_ref()
            .map(|_predecessor| accepted_epoch),
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
