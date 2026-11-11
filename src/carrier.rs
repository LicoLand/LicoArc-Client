//! The Lico Arc mailbox transport carrier over a BadTower-compatible Station.
//!
//! The wire contract is the LicoArc `licoarc.mailbox-transport.v1` Candidate
//! profile: a TLS 1.3 WebSocket with the `licoarc.mailbox.v1` subprotocol,
//! deterministic-CBOR frames, at-least-once delivery until ACK, and permanent
//! mailbox storage until ACK or revocation. This crate does not define that
//! contract; frame encoding and bounds are the pinned `licoarc` SDK's
//! (`licoarc::transport`).
//!
//! What this module owns:
//!
//! * [`HandleToken`]: the 32-byte mailbox handle (`mailboxId ‖ tag`) and its
//!   canonical textual form;
//! * [`Credentials`]: the on-disk admission record (Station URL, `btm1`
//!   token, device Ed25519 seed, learned mailbox id);
//! * [`MailboxClient`]: the asynchronous mailbox connection — handshake,
//!   multiplexed SEND/RESULT, DELIVER/ACK, DRAINED, keepalive;
//! * [`SubmitCarrier`]: a blocking [`crate::Transport`] port adapter that owns
//!   its own I/O runtime, so synchronous SDK dispatch drives real sends.
//!
//! Station answers are untrusted transport hints by design: nothing here
//! promotes an accepted outcome, a signature, or a timestamp into endpoint
//! evidence.

mod blocking;
mod connection;
mod credentials;
mod token;

pub use blocking::SubmitCarrier;
pub use connection::{Event, MailboxClient, SUBPROTOCOL, StationError};
pub use credentials::{Credentials, CredentialsError};
pub use token::{HandleToken, TokenRefusal};
