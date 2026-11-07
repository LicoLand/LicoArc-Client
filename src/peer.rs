//! Inbound mapping for one verified peer unit at the native endpoint boundary.
//!
//! The mobile relay domain owns the actual platform adapters; this module is
//! its inbound bridge. Protocol decisions stay with the pinned SDK and arrive
//! only as one [`VerifiedUnit`] value produced by the SDK boundary (see
//! [`verified`]), so a value of this module's [`PeerMessage`] always names a
//! unit an SDK verification entry actually produced.
//!
//! Three boundaries are load-bearing:
//!
//! * Provenance is explicit and separated. The verified author, the verified
//!   device, and the carriage forwarder are three different values in
//!   [`PeerOrigin`]; a station or relay hop is carriage only and can never be
//!   read as an author, a device, or trust.
//! * A station's own report is a read-only [`StationHint`]. It is recorded as
//!   such and can never become delivery, admission, read, or acceptance
//!   evidence (`docs/protocols/licoarc-station-adapter.md`: a station
//!   acknowledgement is not endpoint evidence).
//! * Duplicate suppression and causal placement use stable identities only:
//!   the SDK's own replay identity for one protected unit, and the peer's
//!   logical message id for a re-protected resend. Local arrival order stays
//!   local; it is never rewritten into the peer's author order.

mod intake;
mod message;
mod provenance;
mod station;
mod verified;

pub use intake::{DEFAULT_INTAKE_WINDOW, DedupeOutcome, IntakeLedger};
pub use message::{MAX_PEER_PARTS, MAX_PEER_TEXT_BYTES, PeerMessage, PeerMessageBody, PeerPart};
pub use provenance::{
    MAX_STATION_ID_BYTES, MessageForwarder, PeerAuthor, PeerDevice, PeerOrigin, StationRef,
};
pub use station::StationHint;
pub use verified::{VerifiedDevice, VerifiedUnit};

/// One refused mapping at this boundary.
///
/// These are shape refusals only. They never decide protocol outcomes, and none
/// of them can manufacture or destroy permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerUnitRefusal {
    /// The facts describe an accepted handshake rather than one committed
    /// protected record, so there is no message unit to map.
    NotARecord,
    /// A message must carry at least one part.
    EmptyMessage,
    /// The part count bound was exceeded.
    TooManyParts,
    /// A text part is empty.
    EmptyText,
    /// A text part exceeds [`MAX_PEER_TEXT_BYTES`].
    TextTooLarge,
    /// A text part contains a NUL byte.
    NulByte,
    /// A command part must be a JSON object so the single-owner command decoder
    /// can read it.
    CommandNotObject,
    /// A forwarder label is empty, over-long, or carries a NUL byte.
    StationIdentityInvalid,
}

impl PeerUnitRefusal {
    /// Stable class of this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotARecord => "peer_unit_not_a_record",
            Self::EmptyMessage => "peer_unit_empty",
            Self::TooManyParts => "peer_unit_parts_exceeded",
            Self::EmptyText => "peer_text_empty",
            Self::TextTooLarge => "peer_text_exceeded",
            Self::NulByte => "peer_text_invalid",
            Self::CommandNotObject => "peer_command_invalid",
            Self::StationIdentityInvalid => "peer_station_invalid",
        }
    }
}

impl core::fmt::Display for PeerUnitRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PeerUnitRefusal {}
