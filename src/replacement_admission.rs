//! Device replacement authority through the pinned SDK's own verification entries.
//!
//! This is the client-side consumer of the LicoArc stable-core replacement
//! surface. It never decides a protocol outcome: it calls the SDK entry that
//! owns the decision and hands back exactly what that entry verified. Every rule
//! below names the SDK behaviour it mirrors, read at revision
//! `244ce7186cac1690c18f091dbe02df36a0860ef4`.
//!
//! # What the SDK owns
//!
//! | decision | SDK entry |
//! | --- | --- |
//! | the signed management/recovery transition, its epoch and its predecessor | `validate_user_authority_state`, `src/identity.rs:129-311` |
//! | the new-device possession proof | reached inside the same entry, `src/identity.rs:286-302` |
//! | the replacement possession proof over the new authority keys | same entry, `src/identity.rs:593-638`; the message is `replacement_possession_input`, `src/identity.rs:111-127` |
//! | the authenticated session, its authority digest and its active device entry | `admit_protected_authority_payload`, `src/identity.rs:351-406` |
//!
//! Nothing here re-verifies a signature and no local type mirrors an SDK type:
//! the adapter calls [`licoarc::identity::admit_protected_authority_payload`] and
//! returns the SDK's own [`AcceptedUserAuthority`]. `verify_replacement_possession`
//! is private in the SDK (`src/identity.rs:593`) and is deliberately *not*
//! re-implemented here; it is reached only through the two public entries above.
//!
//! # Why the binding lives elsewhere
//!
//! The SDK verifies that *some* subject's roster accepted *some* device. It
//! cannot know which replacement the local person asked for, which source device
//! it replaces, or which operation it performs. That comparison is
//! `licoup_endpoint_core::replacement`, whose vocabulary has no dependencies at
//! all, and the platform adapter that composes both sides is
//! `licoup_native::domain::mobile_relay::endpoint_ports`. This crate may not
//! reach either of them: the lane's direction is
//! `platform adapter → protocol bindings → fixed SDK`
//! (`tests/dependency_direction.rs:22-27`). Keeping the SDK delegation here and
//! the binding there is what makes that direction hold.
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
    admit_protected_authority_payload,
};
use licoarc::provider::RustCryptoProvider;
use serde_json::Value;

use crate::VerifiedProtocolLine;

/// One device identity the caller holds keys for, in the shape the SDK verifies.
///
/// The SDK matches a roster entry on `endpointIdentityRef` **and**
/// `identityStateDigest`, then verifies that entry's possession proof against
/// these keys (`src/identity.rs:254-269`). Supplying the wrong digest or the
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
/// `protocolLineId` — belong to the SDK (`src/identity.rs:169-207`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPredecessor {
    authority: AcceptedUserAuthority,
}

impl ReplacementPredecessor {
    /// Takes an accepted authority the caller already holds.
    #[must_use]
    pub const fn new(authority: AcceptedUserAuthority) -> Self {
        Self { authority }
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
/// device (`src/identity.rs:359-404`).
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
    /// (`src/identity.rs:129-311`, `:351-406`).
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
        .map(|authority| VerifiedReplacementAuthority { authority })
        .map_err(|_cause: crate::Error| ReplacementAdmissionRefusal::VerificationRefused)
    }
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
    //! (`licoarc-rust src/conformance/executor.rs:465-630`, `:1724-1772`). None
    //! of it is a second verifier: every assertion below is made about what
    //! `admit_protected_authority_payload` decided.
    //!
    //! The artifact-dependent cases are `#[ignore]`, exactly as
    //! `tests/endpoint_consumer.rs` does, so an absent authorized bundle is
    //! reported as not run instead of passing silently.

    use std::{env, fs};

    use licoarc::identity::{
        self, AcceptedUserAuthority, authority_signature_input, replacement_possession_input,
        validate_user_authority_state,
    };
    use licoarc::provider::{Provider, RustCryptoProvider};
    use serde_json::{Value, json};

    use super::{
        ReplacementAdmission, ReplacementAdmissionRefusal, ReplacementEndpointKeys,
        ReplacementPredecessor, ReplacementSession, SdkReplacementAuthority,
    };
    use crate::version::ACCEPTED_PROTOCOL_LINE_ID;

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

    /// Mirrors the SDK's own `authority_pair`
    /// (`src/conformance/executor.rs:521-549`).
    fn pair(provider: &impl Provider, purpose: &'static str, marker: u8) -> Pair {
        let ed25519_seed = [marker; 32];
        let ml_dsa_65_seed = [marker.wrapping_add(1); 32];
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
    /// (`src/conformance/executor.rs:551-566`). The digest covers the signature
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

    /// The SDK's own two-pass signing recipe (`src/conformance/executor.rs:590-601`).
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

    /// The SDK's own successor skeleton (`src/conformance/executor.rs:603-630`).
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
    /// the SDK refuses any other (`src/identity.rs:142-144`).
    struct Fixture {
        genesis: Value,
        accepted: AcceptedUserAuthority,
        line_id: [u8; 32],
        keys: Vec<ReplacementEndpointKeys>,
        endpoint_identity_ref: [u8; 32],
        identity_state_digest: [u8; 32],
    }

    fn fixture(provider: &impl Provider) -> Fixture {
        let management = pair(provider, "management", 10);
        let recovery = pair(provider, "recovery", 20);
        let device = pair(provider, "management", 40);
        let line_id = ACCEPTED_PROTOCOL_LINE_ID;
        let endpoint_identity_ref = provider.sha256(b"synthetic-replacement:endpoint");
        let identity_state_digest = provider.sha256(b"synthetic-replacement:endpoint-state");
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
            "authorizedDevices": [{
                "endpointIdentityRef": hex(&endpoint_identity_ref),
                "identityStateDigest": hex(&identity_state_digest),
                "deviceStatus": "active",
                "admittedAuthorityEpoch": 0,
                "possessionProof": placeholder_signatures(&device, "device-possession")
            }],
            "authoritySignatures": placeholder_signatures(&management, "authority-genesis")
        });
        let possession_input =
            identity::device_possession_input(&genesis, &genesis["authorizedDevices"][0])
                .expect("device possession input");
        genesis["authorizedDevices"][0]["possessionProof"] = Value::Array(signatures(
            provider,
            &device,
            &possession_input,
            "device-possession",
        ));
        sign_state(provider, &mut genesis, &management, "authority-genesis")
            .expect("genesis signature");
        let accepted = validate_user_authority_state(
            provider,
            &genesis,
            None,
            line_id,
            &[endpoint_keys(
                &device,
                &endpoint_identity_ref,
                &identity_state_digest,
            )],
        )
        .expect("genesis authority");
        Fixture {
            genesis,
            accepted,
            line_id,
            keys: vec![ReplacementEndpointKeys {
                endpoint_identity_ref: hex(&endpoint_identity_ref),
                identity_state_digest: hex(&identity_state_digest),
                ed25519_key_id: hex(&device.ed25519_key_id),
                ed25519_public: hex(&device.ed25519_public),
                ml_dsa_65_key_id: hex(&device.ml_dsa_65_key_id),
                ml_dsa_65_public: hex(&device.ml_dsa_65_public),
            }],
            endpoint_identity_ref,
            identity_state_digest,
        }
    }

    /// The recovery-transition replacement the SDK's own suite builds
    /// (`src/conformance/executor.rs:1724-1772`). This is a *key* replacement:
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
                provider, &new_recovery, &proof_input, "recovery-possession-placeholder"
            ),
        });
        // The recovery axis did not change, so only the management axis carries a
        // proof. A signature field on the unchanged axis is `InvalidTransition`
        // (`src/identity.rs:633-635`).
        replaced["possessionProof"]
            .as_object_mut()
            .expect("possession proof object")
            .remove("recoverySignatures");
        sign_state(provider, &mut replaced, &recovery, "authority-recovery")
            .expect("recovery authority signature");
        replaced
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
    ///   cargo test -p licoup-protocol-bindings --lib -- --ignored --nocapture
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
        let verified = adapter
            .admit(&replaced, &admission(&fixture))
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

    /// An exact replay of the accepted state is refused rather than re-admitted.
    #[test]
    #[ignore = "requires LICOARC_AUTHORITY_BUNDLE and real ml-dsa-65 signing"]
    fn an_exact_replay_of_the_accepted_state_is_refused() {
        let provider = RustCryptoProvider;
        let fixture = fixture(&provider);
        let bytes = authority_bytes();
        let line = crate::AuthorityInput::new(&bytes)
            .admit()
            .expect("the fixed Candidate is admitted");
        let adapter = SdkReplacementAuthority::with_admitted_line(line);

        assert_eq!(
            adapter
                .admit(&fixture.genesis, &admission(&fixture))
                .expect_err("a replay of the accepted state admits nothing"),
            ReplacementAdmissionRefusal::VerificationRefused
        );
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
}
