//! Endpoint-session composition: identity, pairing envelopes, and drives.
//!
//! The carrier slice delivers raw packets to one handle; this layer composes
//! the SDK's protocol primitives into the end-to-end pairing flow two CLI
//! processes exchange over that carrier:
//!
//! 1. The responder mints a [`LocalIdentity`], stages one [`PrekeyBundle`]
//!    inside custody, and publishes a [`PairingOffer`] out of band
//!    (`identity + prekey + bootstrap handle + authority digest`).
//! 2. The initiator resolves the responder identity through its own
//!    [`StaticTrust`] view, builds a [`FirstPacket`], and submits it inside a
//!    [`PairingSubmission`] that also carries its reply handle.
//! 3. The responder authenticates the packet with the SDK, derives a session,
//!    and returns a [`PairingReply`] (`SessionAccept + session handle`) to the
//!    initiator's reply handle. The initiator verifies the accept and records
//!    the responder's session handle.
//!
//! `FirstPacket` has no return-address field, so both envelopes are
//! caller-facing control records (canonical CBOR) that travel *inside* the
//! station payload, not beside it — the transport stays protocol-neutral.
//!
//! All cryptographic facts, wire validation, and session semantics belong to
//! the SDK; this module only assembles caller-owned ports and custody.

mod clock;
mod drive;
mod envelope;
mod identity;
mod offer;
mod state;
mod trust;

pub use clock::SystemClock;
pub use drive::{InitiatorDrive, ResponderDrive};
pub use envelope::{EnvelopeRefusal, PairingReply, PairingSubmission};
pub use identity::{LocalIdentity, MintRefusal, load_peer_identity};
pub use offer::{OfferRefusal, PairingOffer};
pub use state::FileState;
pub use trust::StaticTrust;
