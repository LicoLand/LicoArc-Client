//! The Lico Arc HTTPS transport carrier over a BadTower-compatible Station.
//!
//! The wire contract is the LicoArc `licoarc.https-transport.v1` Candidate
//! profile: HTTP/2 over TLS 1.3 only, POST, deterministic-CBOR control
//! records, one raw protected packet for SUBMIT and for an accepted RETRIEVE,
//! and the fixed status-to-outcome classification. This crate does not define
//! that contract; request validation and outcome classification are delegated
//! to the pinned `licoarc` SDK (`licoarc::transport`), and response grammars
//! are the closed maps of the same profile source.
//!
//! What this module owns:
//!
//! * [`HandleToken`] and [`OperationId`]: the opaque wire tokens and their
//!   canonical textual forms;
//! * [`control`]: typed control requests encoded as canonical CBOR and checked
//!   by the SDK before they leave the client;
//! * [`response`]: strict canonical-CBOR decoders for the closed response
//!   grammar (the SDK's own decoder is intentionally bounded below the claim
//!   response size, so responses are decoded by a dedicated reader);
//! * [`StationClient`]: the asynchronous strict-profile HTTP client;
//! * [`SubmitCarrier`]: a blocking [`crate::Transport`] port adapter that owns
//!   its own I/O runtime, so synchronous SDK dispatch drives real network
//!   sends.
//!
//! Station answers are untrusted transport hints by design: nothing here
//! promotes an accepted outcome, a signature, or a timestamp into endpoint
//! evidence.

mod access;
mod blocking;
mod client;
mod control;
mod response;
mod token;

pub use access::{AccessError, AccessGrant, AccessProof};
pub use blocking::SubmitCarrier;
pub use client::{
    AffiliateAccepted, CarrierConfig, ClaimAccepted, OperationOutcome, ReserveAccepted,
    StationClient, StationError,
};
pub use control::{
    AffiliateRequest, ClaimRequest, HandleClass, ReserveRequest, RetrieveRequest, SettleAction,
    SettleRequest, Settlement, TRANSPORT_PROFILE_DIGEST,
};
pub use response::{
    Affiliation, ClaimBatch, ClaimedItem, FailureClass, ItemResult, Lease, SettleOutcome,
};
pub use token::{HandleToken, OperationId};

/// Maximum claim response bytes admitted by the profile
/// (`spec/v1/transport/bounds.json`).
pub const MAX_CLAIM_RESPONSE_BYTES: usize = 33_554_432;

/// Maximum `retryAfterMs` a station may name.
pub const MAX_RETRY_AFTER_MS: u64 = 60_000;
