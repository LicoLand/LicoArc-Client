//! The strict-profile asynchronous Station client.
//!
//! One [`StationClient`] owns one HTTPS/TLS-1.3/HTTP-2 reqwest client pinned
//! to one Station origin. The carrier profile is enforced by construction
//! rather than inspection: the TLS stack only offers TLS 1.3, ALPN only
//! offers `h2`, the scheme is HTTPS-only, redirects are off, requests are
//! POST with an exact Content-Length, and there is no early data,
//! renegotiation, query, fragment, transfer encoding, trailer, or content
//! coding anywhere in the stack.
//!
//! Outcome handling is the profile's own: the status classifies through the
//! SDK's `classify_status`, the body decodes through [`response`], and the
//! two must agree — a disagreement is a non-conforming Station answer.
//! `transient` and `ambiguous` outcomes retry with the *same* operation
//! identifier and the identical canonical request, which is what makes the
//! Station's idempotency window return the recorded result instead of running
//! a second operation. Retries are bounded; exhausting them reports
//! [`StationError::Uncertain`] so the caller re-drives the same committed
//! work later rather than inventing a different one.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use licoarc::provider::{DigestProvider, fixed_provider};
use licoarc::transport::{self, TransportOutcome};

use super::access::{
    AUTHORIZATION_HEADER, AccessError, AccessGrant, PROOF_COUNTER_HEADER, PROOF_ISSUED_AT_HEADER,
    PROOF_SIGNATURE_HEADER,
};
use super::control::{
    AffiliateRequest, ClaimRequest, ReserveRequest, RetrieveRequest, SettleRequest,
};
use super::response::{
    Affiliation, ClaimBatch, DecodeRefusal, FailureClass, ItemResult, Lease, StationReply,
    decode_affiliate, decode_claim, decode_reserve, decode_settle, decode_submit,
};
use super::token::{HandleToken, OperationId};

const CONTROL_MEDIA_TYPE: &str = "application/licoarc-transport+cbor";
const PACKET_MEDIA_TYPE: &str = "application/licoarc-protected-packet";
const OPERATION_ID_HEADER: &str = "licoarc-operation-id";
const MAX_PACKET_BYTES: usize = 524_288;
const MAX_CONTROL_BODY_BYTES: usize = 16_384;
const MAX_CLAIM_RESPONSE_BYTES: usize = 33_554_432;
const MAX_RETRY_AFTER_MS: u64 = 60_000;

/// Client-side tuning for the fixed profile.
///
/// The bounds themselves are protocol constants; only the attempt budget and
/// local retry pacing are configuration.
#[derive(Clone, Debug)]
pub struct CarrierConfig {
    /// `https://host[:port]` of the Station listener, optionally with a fixed
    /// path prefix. Query and fragment are refused.
    pub origin: String,
    /// Total attempts per logical operation, including the first send. The
    /// protocol's own settlement-attempt bound (8) is the default.
    pub max_attempts: u32,
    /// Transport-level liveness bound for one attempt. It bounds a single
    /// HTTP exchange only; it never cancels a logical operation, which is
    /// retried under the same operation identifier.
    pub request_timeout: Duration,
    /// Connect-phase liveness bound.
    pub connect_timeout: Duration,
    /// Delay before re-driving an ambiguous attempt when the Station named no
    /// hint.
    pub ambiguous_retry_delay: Duration,
    /// Floor delay for a transient outcome that carried no `retryAfterMs`.
    pub transient_floor_delay: Duration,
    /// Extra trust roots for a locally operated Station (self-signed
    /// development certificates). Production listeners validate against the
    /// system verifier.
    pub extra_root_certificates: Vec<reqwest::Certificate>,
    /// Credentials file of one BadTower access grant. When set, every
    /// request attempt carries the `bta2` capability and a freshly numbered
    /// Ed25519 proof; the monotonic counter persists through that file.
    /// Absent means the bare Station profile for unauthenticated listeners.
    pub access_credentials: Option<PathBuf>,
}

impl Default for CarrierConfig {
    fn default() -> Self {
        Self {
            origin: String::new(),
            max_attempts: 8,
            request_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(15),
            ambiguous_retry_delay: Duration::from_millis(250),
            transient_floor_delay: Duration::from_millis(500),
            extra_root_certificates: Vec::new(),
            access_credentials: None,
        }
    }
}

/// Everything one logical operation can end in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StationError {
    /// The unchanged request is terminally refused.
    Rejected { failure_class: Option<FailureClass> },
    /// The Station answered outside the profile: an unmapped status, a wrong
    /// media type, a body outside the closed grammar, or a body outcome
    /// disagreeing with the status class.
    Nonconforming,
    /// The outcome is unknown after the bounded retries: the operation may
    /// or may not have committed. The caller re-drives the same request
    /// later under the same operation identifier.
    Uncertain,
    /// The client could not encode its own control record.
    InvalidControl,
    /// The configured origin is not a usable HTTPS base.
    InvalidOrigin,
    /// The access credentials could not be loaded, persisted, or used to
    /// prove a request.
    Access(String),
}

impl core::fmt::Display for StationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected { failure_class } => {
                write!(formatter, "station rejected operation ({failure_class:?})")
            }
            Self::Nonconforming => formatter.write_str("non-conforming station response"),
            Self::Uncertain => formatter.write_str("operation outcome uncertain after retries"),
            Self::InvalidControl => formatter.write_str("invalid transport control record"),
            Self::InvalidOrigin => formatter.write_str("invalid station origin"),
            Self::Access(cause) => write!(formatter, "access credentials: {cause}"),
        }
    }
}

impl std::error::Error for StationError {}

/// The accepted payload of AFFILIATE.
pub type AffiliateAccepted = Affiliation;
/// The accepted payload of RESERVE.
pub type ReserveAccepted = Lease;
/// The accepted payload of CLAIM.
pub type ClaimAccepted = ClaimBatch;
/// One operation's classified result.
pub type OperationOutcome = TransportOutcome;

/// The derivation material for a content-stable operation id: the exact
/// request target followed by the exact canonical request body. Binding the
/// target keeps the same bytes submitted to two different handles from
/// colliding under one identifier.
fn operation_material(path: &str, body: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(path.len() + body.len());
    material.extend_from_slice(path.as_bytes());
    material.extend_from_slice(body);
    material
}

/// One strict-profile asynchronous client pinned to one Station origin.
pub struct StationClient {
    http: reqwest::Client,
    origin: String,
    config: CarrierConfig,
    access: Option<Mutex<AccessGrant>>,
}

impl StationClient {
    /// Builds the pinned HTTP/2-over-TLS-1.3 client for one Station origin.
    ///
    /// The origin must be `https://`, carry no query or fragment, and is kept
    /// verbatim so a path prefix survives: `{origin}/v1/...` is the request
    /// target.
    pub fn new(config: CarrierConfig) -> Result<Self, StationError> {
        let origin = config.origin.trim_end_matches('/');
        if !origin.starts_with("https://") || origin.contains('?') || origin.contains('#') {
            return Err(StationError::InvalidOrigin);
        }
        let mut builder = reqwest::Client::builder()
            // The profile by construction: TLS 1.3 only, h2 only, HTTPS only,
            // no redirects, no default headers beyond what each call sets.
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(reqwest::header::HeaderMap::new())
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .tls_backend_rustls();
        for certificate in &config.extra_root_certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let http = builder.build().map_err(|_| StationError::InvalidOrigin)?;
        let access = config
            .access_credentials
            .as_deref()
            .map(|path| {
                AccessGrant::load(path)
                    .map(Mutex::new)
                    .map_err(|error| StationError::Access(error.to_string()))
            })
            .transpose()?;
        Ok(Self {
            http,
            origin: origin.to_owned(),
            config,
            access,
        })
    }

    /// Exchanges one `bti2` invitation for a device grant at this origin and
    /// persists it to `store`. The returned grant is also installed on this
    /// client when `store` is this client's configured credentials path.
    pub async fn exchange_invitation(
        &self,
        invitation: &str,
        store: PathBuf,
    ) -> Result<AccessGrant, StationError> {
        super::access::exchange(&self.http, &self.origin, invitation, &store)
            .await
            .map_err(|error: AccessError| StationError::Access(error.to_string()))
    }

    /// AFFILIATE: binds one opaque affiliation commitment to the Station
    /// descriptor for the storage window.
    pub async fn affiliate(
        &self,
        request: &AffiliateRequest,
    ) -> Result<AffiliateAccepted, StationError> {
        let body = request.encode().map_err(|_| StationError::InvalidControl)?;
        let operation_id = OperationId::derive(b"affiliate", &body);
        self.run(
            "/v1/affiliate",
            body,
            CONTROL_MEDIA_TYPE,
            operation_id,
            MAX_CONTROL_BODY_BYTES,
            decode_affiliate,
        )
        .await
    }

    /// RESERVE: allocates one delivery handle of the requested class under a
    /// live affiliation.
    ///
    /// Like claim, each call is a fresh logical operation — two reserves with
    /// the same request allocate two different handles, not one replayed
    /// lease. The operation id therefore binds fresh entropy; retries inside
    /// one call still replay under it.
    pub async fn reserve(&self, request: &ReserveRequest) -> Result<ReserveAccepted, StationError> {
        let body = request.encode().map_err(|_| StationError::InvalidControl)?;
        let mut material = operation_material("/v1/reserve", &body);
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| StationError::InvalidControl)?;
        material.extend_from_slice(&nonce);
        let operation_id = OperationId::derive(b"reserve", &material);
        self.run(
            "/v1/reserve",
            body,
            CONTROL_MEDIA_TYPE,
            operation_id,
            MAX_CONTROL_BODY_BYTES,
            decode_reserve,
        )
        .await
    }

    /// SUBMIT: delivers one opaque protected packet to one handle.
    ///
    /// The operation id is content-derived from the exact request target and
    /// packet, so a re-driven send of the same committed packet to the same
    /// handle always names the same identifier — exactly what the idempotency
    /// contract requires.
    pub async fn submit(&self, handle: HandleToken, packet: &[u8]) -> Result<(), StationError> {
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(StationError::InvalidControl);
        }
        let path = handle.path("submit");
        let operation_id = OperationId::derive(b"submit", &operation_material(&path, packet));
        self.run(
            &path,
            packet.to_vec(),
            PACKET_MEDIA_TYPE,
            operation_id,
            MAX_CONTROL_BODY_BYTES,
            decode_submit,
        )
        .await
    }

    /// RETRIEVE: reads one item of a live claim back as the raw packet.
    ///
    /// An accepted answer carries the raw protected packet, not a control
    /// map; a declined answer carries the shared decline grammar.
    pub async fn retrieve(
        &self,
        handle: HandleToken,
        request: &RetrieveRequest,
    ) -> Result<Vec<u8>, StationError> {
        let body = request.encode().map_err(|_| StationError::InvalidControl)?;
        let path = handle.path("retrieve");
        let operation_id = OperationId::derive(b"retrieve", &operation_material(&path, &body));
        self.run(
            &path,
            body,
            CONTROL_MEDIA_TYPE,
            operation_id,
            MAX_PACKET_BYTES,
            |bytes| Ok(StationReply::Accepted(bytes.to_vec())),
        )
        .await
    }

    /// CLAIM: takes the next bounded batch of items for one handle.
    ///
    /// A claim is a fresh logical operation every time it is called: two
    /// polls with the same `max_items` are two different claims, not retries
    /// of one. The operation id therefore binds fresh entropy on top of the
    /// canonical request — retries inside one call still replay under it,
    /// while a later call must not replay the recorded batch of an earlier
    /// claim.
    pub async fn claim(
        &self,
        handle: HandleToken,
        request: &ClaimRequest,
    ) -> Result<ClaimAccepted, StationError> {
        let body = request.encode().map_err(|_| StationError::InvalidControl)?;
        let path = handle.path("claim");
        let mut material = operation_material(&path, &body);
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| StationError::InvalidControl)?;
        material.extend_from_slice(&nonce);
        let operation_id = OperationId::derive(b"claim", &material);
        self.run(
            &path,
            body,
            CONTROL_MEDIA_TYPE,
            operation_id,
            MAX_CLAIM_RESPONSE_BYTES,
            decode_claim,
        )
        .await
    }

    /// SETTLE: atomically completes or releases items of a live claim.
    pub async fn settle(
        &self,
        handle: HandleToken,
        request: &SettleRequest,
    ) -> Result<Vec<ItemResult>, StationError> {
        let body = request.encode().map_err(|_| StationError::InvalidControl)?;
        let path = handle.path("settle");
        let operation_id = OperationId::derive(b"settle", &operation_material(&path, &body));
        self.run(
            &path,
            body,
            CONTROL_MEDIA_TYPE,
            operation_id,
            MAX_CONTROL_BODY_BYTES,
            decode_settle,
        )
        .await
    }

    /// One bounded retry loop over the identical canonical request.
    ///
    /// Every attempt carries the same operation identifier: under the
    /// profile that is what makes a retried ambiguous or transient outcome
    /// return the recorded result instead of running a second operation.
    async fn run<T>(
        &self,
        path: &str,
        body: Vec<u8>,
        media_type: &'static str,
        operation_id: OperationId,
        response_cap: usize,
        decode: impl Fn(&[u8]) -> Result<StationReply<T>, DecodeRefusal>,
    ) -> Result<T, StationError> {
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            match self
                .post(path, &body, operation_id, media_type, response_cap)
                .await
            {
                Attempt::Response {
                    status_outcome,
                    bytes,
                } => {
                    let reply = decode(&bytes).map_err(|_| StationError::Nonconforming)?;
                    if reply.outcome() != status_outcome {
                        return Err(StationError::Nonconforming);
                    }
                    match reply {
                        StationReply::Accepted(payload) => return Ok(payload),
                        StationReply::Declined {
                            outcome,
                            failure_class,
                            retry_after_ms,
                        } => match outcome {
                            TransportOutcome::Rejected => {
                                return Err(StationError::Rejected { failure_class });
                            }
                            TransportOutcome::Transient => {
                                self.pace(retry_after_ms, true).await;
                            }
                            TransportOutcome::Ambiguous => {
                                self.pace(retry_after_ms, false).await;
                            }
                            TransportOutcome::Accepted => {
                                return Err(StationError::Nonconforming);
                            }
                        },
                    }
                }
                Attempt::Retry => self.pace(None, false).await,
                Attempt::Failed(error) => return Err(error),
            }
            if attempt >= self.config.max_attempts {
                return Err(StationError::Uncertain);
            }
        }
    }

    /// One attempt of the canonical request.
    async fn post(
        &self,
        path: &str,
        body: &[u8],
        operation_id: OperationId,
        media_type: &'static str,
        response_cap: usize,
    ) -> Attempt {
        let url = format!("{}{path}", self.origin);
        let mut request = self
            .http
            .post(&url)
            .header(OPERATION_ID_HEADER, operation_id.as_header())
            .header(reqwest::header::CONTENT_TYPE, media_type);
        if let Some(access) = &self.access {
            let (token, proof) = {
                let mut grant = match access.lock() {
                    Ok(grant) => grant,
                    Err(_) => return Attempt::Failed(StationError::Access("poisoned".to_owned())),
                };
                let body_digest = fixed_provider().sha256(body);
                let proof = match grant.prove(
                    path,
                    media_type,
                    body.len() as u64,
                    &operation_id,
                    &body_digest,
                ) {
                    Ok(proof) => proof,
                    Err(error) => {
                        return Attempt::Failed(StationError::Access(error.to_string()));
                    }
                };
                (grant.token().to_owned(), proof)
            };
            request = request
                .header(AUTHORIZATION_HEADER, format!("Bearer {token}"))
                .header(PROOF_ISSUED_AT_HEADER, proof.issued_at.to_string())
                .header(PROOF_COUNTER_HEADER, proof.counter.to_string())
                .header(PROOF_SIGNATURE_HEADER, proof.signature);
        }
        let mut response = match request.body(body.to_vec()).send().await {
            Ok(response) => response,
            // A transport failure leaves the outcome unknown: retrying the
            // same operation id is what makes a possibly-committed attempt
            // return its recorded response.
            Err(_) => return Attempt::Retry,
        };
        let status_outcome = match transport::classify_status(response.status().as_u16()) {
            Ok(outcome) => outcome,
            Err(_) => return Attempt::Failed(StationError::Nonconforming),
        };
        // An accepted answer carries the op's own media type; every decline
        // carries the control grammar (the Station emits the shared decline
        // shape for non-accepted outcomes, including RETRIEVE).
        let expected_media = if status_outcome == TransportOutcome::Accepted {
            if media_type == PACKET_MEDIA_TYPE {
                CONTROL_MEDIA_TYPE
            } else {
                media_type
            }
        } else {
            CONTROL_MEDIA_TYPE
        };
        let expected_media =
            if path.ends_with("/retrieve") && status_outcome == TransportOutcome::Accepted {
                PACKET_MEDIA_TYPE
            } else {
                expected_media
            };
        let media_ok = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some(expected_media);
        if !media_ok {
            return Attempt::Failed(StationError::Nonconforming);
        }
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() + chunk.len() > response_cap {
                        return Attempt::Failed(StationError::Nonconforming);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return Attempt::Retry,
            }
        }
        if media_type == PACKET_MEDIA_TYPE && bytes.is_empty() {
            return Attempt::Failed(StationError::Nonconforming);
        }
        Attempt::Response {
            status_outcome,
            bytes,
        }
    }

    async fn pace(&self, retry_after_ms: Option<u64>, transient: bool) {
        let delay = retry_after_ms.map_or_else(
            || {
                if transient {
                    self.config.transient_floor_delay
                } else {
                    self.config.ambiguous_retry_delay
                }
            },
            |ms| Duration::from_millis(ms.min(MAX_RETRY_AFTER_MS)),
        );
        tokio::time::sleep(delay).await;
    }
}

/// The outcome of one HTTP attempt.
enum Attempt {
    /// A bounded body arrived under a classifiable status.
    Response {
        status_outcome: TransportOutcome,
        bytes: Vec<u8>,
    },
    /// The exchange failed before a conforming answer; outcome is unknown.
    Retry,
    /// A terminal local or conformance failure.
    Failed(StationError),
}
