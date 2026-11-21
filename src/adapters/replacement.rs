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
//! * **the operation** — the destination's `deviceStatus` must be the one the
//!   binding names, and the epoch the SDK stamped on it
//!   (`admittedAuthorityEpoch` / `revokedAuthorityEpoch`) must fall inside the
//!   verified span, so a status an earlier transition wrote never authorizes
//!   this request.
//! * **the new identity** — the destination must be a distinct endpoint the
//!   successor roster really holds, never the source identity itself, so new
//!   endpoint keys never derive from an imported source identity. It must
//!   also be genuinely new at the transition that admitted it: the SDK
//!   restamps `admittedAuthorityEpoch` to the transition's own epoch when an
//!   existing active endpoint's identity-state digest changes, so the
//!   roster immediately before that transition — a chain snapshot at
//!   `admitted - 1`, or the accepted predecessor when it is that record —
//!   must not already hold the destination.
//! * **the source device** — the destination must have superseded it: the
//!   source's entry is `revoked` at the destination's own admission epoch,
//!   decided on the verified record that recorded that transition — a
//!   chain snapshot at that epoch, or the accepted predecessor when it is
//!   that record — and that transition must have admitted or revoked
//!   nothing else at that epoch, so the pair cannot name two different
//!   devices. A roster view that postdates the admission is not that
//!   evidence: the SDK permits it to drop entries the transition already
//!   retired, so a claim whose admission record no verified record
//!   preserves is refused rather than bound to a pruned roster.

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
) -> Result<(), ReplacementAuthorityRefusal> {
    // 1. The caller must really hold one of the two accepted sources. Ordinary
    //    backup, relay and peer input arrives as `None` and stops here, before
    //    any store, transport or effect is named.
    if !source.can_authorize() {
        return Err(ReplacementAuthorityRefusal::NoTrustedAuthority);
    }

    // 2. Replay is decided from the caller's own accepted epoch, so a superseded
    //    roster is refused rather than re-verified into acceptance.
    if let Some(accepted_epoch) = predecessor.map(ReplacementPredecessor::epoch) {
        binding.replayed_at(accepted_epoch, read_epoch(presented)?)?;
    }
    Ok(())
}

fn verify_replacement(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    admit_preflight(
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
    verify_binding(
        verified,
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        std::slice::from_ref(state),
    )
}

fn verify_replacement_cold(
    authority: &SdkReplacementAuthority,
    state: &Value,
    request: &ColdReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    admit_preflight(
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        state,
    )?;
    let verified = authority
        .admit_state(state, &request.admission)
        .map_err(map_admission_refusal)?;
    verify_binding(
        verified,
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        std::slice::from_ref(state),
    )
}

fn verify_replacement_catch_up(
    authority: &SdkReplacementAuthority,
    snapshots: &[Value],
    request: &ColdReplacementRequest,
) -> Result<VerifiedBinding, ReplacementAuthorityRefusal> {
    // The replay guard reads the tip's epoch; an empty chain has no tip, so a
    // caller with an accepted epoch reads an unreadable authority, and a caller
    // without one is refused by the SDK's own empty-chain bound.
    admit_preflight(
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        snapshots.last().unwrap_or(&Value::Null),
    )?;
    let verified = authority
        .catch_up(snapshots, &request.admission)
        .map_err(map_admission_refusal)?;
    verify_binding(
        verified,
        request.source,
        &request.binding,
        request.admission.predecessor.as_ref(),
        snapshots,
    )
}

/// The binding comparison, against the verified record's own values.
///
/// `predecessor` is the authority the caller already accepted, if any: the
/// verified span is `(accepted_epoch, tip_epoch]`, and the claimed change must
/// have been made inside it. `records` is every verified authority record the
/// path holds — one presented state, or the whole catch-up chain — and the
/// source-destination pairing is decided on whichever verified record
/// recorded the transition that admitted the destination, with the roster
/// immediately before it confirming the destination was genuinely new.
fn verify_binding(
    verified: VerifiedReplacementAuthority,
    source: AuthoritySource,
    binding: &ReplacementBinding,
    predecessor: Option<&ReplacementPredecessor>,
    records: &[Value],
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
    let admitted = read_epoch_field(destination, "admittedAuthorityEpoch")?;
    let status = read_text(destination, "deviceStatus")?;

    // 5. The verified chain must have made the claimed change itself. The SDK
    //    marks every roster write with the epoch of the transition that made
    //    it (`validate_roster_transition`, `src/identity.rs`), so a status an
    //    earlier transition already held authorizes nothing here: an unrelated
    //    transition can neither activate an already-active destination nor
    //    revoke an already-revoked one.
    let floor = predecessor
        .map(ReplacementPredecessor::epoch)
        .map_or(0, |epoch| epoch.saturating_add(1));
    let changed_at = match (binding.operation(), status) {
        (ReplacementOperation::Activate, "active") => admitted,
        (ReplacementOperation::Revoke, "revoked") => {
            read_epoch_field(destination, "revokedAuthorityEpoch")?
        }
        _ => return Err(ReplacementAuthorityRefusal::OperationMismatch),
    };
    if changed_at < floor {
        return Err(match binding.operation() {
            ReplacementOperation::Activate => ReplacementAuthorityRefusal::DestinationAlreadyActive,
            ReplacementOperation::Revoke => ReplacementAuthorityRefusal::OperationMismatch,
        });
    }

    // 6. The source device is the one the destination superseded: the
    //    transition that admitted the destination revoked it. The pairing is
    //    decided on the verified record that recorded that transition — a
    //    chain snapshot at the admission epoch, or the accepted predecessor
    //    when it is that record. Any other view is not complete evidence: the
    //    SDK permits a later snapshot to drop entries that transition already
    //    retired (`validate_roster_transition`, `src/identity.rs`), so a
    //    successor's roster can hide the retired source and every other device
    //    the admission stamped. With no verified record at the admission
    //    epoch the pair cannot be bound, and the claim is refused rather than
    //    decided against a pruned roster.
    let pairing = records
        .iter()
        .find(|state| read_epoch(state).is_ok_and(|epoch| epoch == admitted))
        .or_else(|| {
            predecessor
                .filter(|predecessor| predecessor.epoch() == admitted)
                .map(ReplacementPredecessor::state)
        })
        .ok_or(ReplacementAuthorityRefusal::SourceDeviceMismatch)?;
    if read_device(pairing, binding.new_endpoint_identity_ref()).is_none() {
        return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch);
    }
    let source_device = read_device(pairing, binding.source_device())
        .ok_or(ReplacementAuthorityRefusal::SourceDeviceMismatch)?;
    match read_text(source_device, "deviceStatus")? {
        "revoked" if read_epoch_field(source_device, "revokedAuthorityEpoch")? == admitted => {}
        _ => return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch),
    }

    // The admission record alone cannot tell a fresh admission from a
    //    restamp: the SDK stamps the transition's own epoch on an already
    //    rostered endpoint whose identity-state digest changed
    //    (`validate_roster_transition`, `src/identity.rs`), so that record
    //    can pair a revoked source with an endpoint that was never new.
    //    The roster immediately before the transition decides — a genuinely
    //    new destination is absent from it. That roster is a chain snapshot
    //    at `admitted - 1`, or the accepted predecessor when it is that
    //    record. When the predecessor *is* the admission record its own
    //    verified state is already the caller's anchor, and a genesis
    //    admission (`admitted == 0`) has no roster before it; any other
    //    claim must carry the pre-admission record among its verified
    //    evidence or be refused.
    let before = admitted.checked_sub(1).and_then(|prior| {
        records
            .iter()
            .find(|state| read_epoch(state).is_ok_and(|epoch| epoch == prior))
            .or_else(|| {
                predecessor
                    .filter(|predecessor| predecessor.epoch() == prior)
                    .map(ReplacementPredecessor::state)
            })
    });
    if let Some(before) = before {
        if read_device(before, binding.new_endpoint_identity_ref()).is_some() {
            return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch);
        }
    } else if admitted != 0 && predecessor.is_none_or(|predecessor| predecessor.epoch() != admitted)
    {
        return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch);
    }

    // One signed transition may admit or revoke several devices in the same
    // epoch, and a roster entry never names the device it was paired with.
    // The pair is bound only when that transition stamped nothing else at the
    // destination's admission epoch: any further admission or revocation at
    // `admitted` leaves which device actually superseded the source
    // ambiguous, and an ambiguous pair authorizes no claim.
    for device in pairing
        .get("authorizedDevices")
        .and_then(Value::as_array)
        .ok_or(ReplacementAuthorityRefusal::UnreadableAuthority)?
    {
        let endpoint = read_text(device, "endpointIdentityRef")?;
        if endpoint == binding.new_endpoint_identity_ref() || endpoint == binding.source_device() {
            continue;
        }
        if read_epoch_field(device, "admittedAuthorityEpoch")? == admitted
            || device.get("revokedAuthorityEpoch").and_then(Value::as_u64) == Some(admitted)
        {
            return Err(ReplacementAuthorityRefusal::SourceDeviceMismatch);
        }
    }

    // The epoch a revocation supersedes is the admission epoch of the device
    // the claim retires — read from the verified record, not inherited.
    let superseded_epoch = match binding.operation() {
        ReplacementOperation::Activate => {
            read_epoch_field(source_device, "admittedAuthorityEpoch")?
        }
        ReplacementOperation::Revoke => admitted,
    };

    let claim = AcceptedReplacement::verified(
        source,
        binding,
        verified.authority_epoch(),
        verified.state_digest(),
        Some(superseded_epoch),
    );
    Ok(VerifiedBinding {
        claim,
        authority: verified,
    })
}

fn read_epoch(state: &Value) -> Result<u64, ReplacementAuthorityRefusal> {
    read_epoch_field(state, "authorityEpoch")
}

fn read_epoch_field(value: &Value, key: &str) -> Result<u64, ReplacementAuthorityRefusal> {
    value
        .get(key)
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
