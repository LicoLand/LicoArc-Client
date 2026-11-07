//! The mapped peer message: verified provenance plus the peer's own content.
//!
//! The content schema is the client's, not raw wire: the caller decodes the
//! SDK-verified plaintext into these parts, and this module only bounds and
//! carries them. Nothing here interprets text, and no part ever supplies an
//! author, a permission, or an order.

use super::{MessageForwarder, PeerOrigin, PeerUnitRefusal, StationHint, VerifiedUnit};

/// Largest number of parts accepted in one peer message.
pub const MAX_PEER_PARTS: usize = 64;

/// Largest natural text part accepted, in bytes.
pub const MAX_PEER_TEXT_BYTES: usize = 256 * 1024;

/// One part of a mapped peer message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerPart {
    /// Natural peer text, carried verbatim. No marker, prefix, or envelope is
    /// added: ordinary agent prose stays ordinary prose.
    Text(String),
    /// One explicit structured command request. It is carried and offered to the
    /// single-owner authorization entry; it is never executed by this boundary.
    Command(serde_json::Value),
}

impl PeerPart {
    /// One bounded, non-empty natural text part.
    pub fn text(content: impl Into<String>) -> Result<Self, PeerUnitRefusal> {
        let content = content.into();
        if content.is_empty() {
            return Err(PeerUnitRefusal::EmptyText);
        }
        if content.len() > MAX_PEER_TEXT_BYTES {
            return Err(PeerUnitRefusal::TextTooLarge);
        }
        if content.contains('\0') {
            return Err(PeerUnitRefusal::NulByte);
        }
        Ok(Self::Text(content))
    }

    /// One command request, bounded to the object shape the command decoder
    /// reads.
    pub fn command(request: serde_json::Value) -> Result<Self, PeerUnitRefusal> {
        if !request.is_object() {
            return Err(PeerUnitRefusal::CommandNotObject);
        }
        Ok(Self::Command(request))
    }
}

/// The peer's own content of one message unit.
///
/// `logical_id` is the peer's stable identity of the logical message; a
/// re-protected resend of the same message carries the same id, which is what
/// makes duplicate suppression possible without trusting arrival order.
/// `relates_to` names the peer's logical message this one answers, when it
/// answers one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMessageBody {
    logical_id: [u8; 16],
    relates_to: Option<[u8; 16]>,
    parts: Vec<PeerPart>,
}

impl PeerMessageBody {
    /// Validates and carries one decoded peer body.
    pub fn new(
        logical_id: [u8; 16],
        relates_to: Option<[u8; 16]>,
        parts: Vec<PeerPart>,
    ) -> Result<Self, PeerUnitRefusal> {
        if parts.is_empty() {
            return Err(PeerUnitRefusal::EmptyMessage);
        }
        if parts.len() > MAX_PEER_PARTS {
            return Err(PeerUnitRefusal::TooManyParts);
        }
        Ok(Self {
            logical_id,
            relates_to,
            parts,
        })
    }

    #[must_use]
    pub const fn logical_id(&self) -> [u8; 16] {
        self.logical_id
    }

    #[must_use]
    pub const fn relates_to(&self) -> Option<[u8; 16]> {
        self.relates_to
    }

    #[must_use]
    pub fn parts(&self) -> &[PeerPart] {
        &self.parts
    }
}

/// One verified peer message, ready for conversation admission.
///
/// The only constructor takes the SDK-verified unit of a committed protected
/// record, so the origin and the replay identity cannot be supplied by a
/// message body or by a caller's claim. `RecordKey` is the SDK boundary's own
/// replay identity; this boundary only compares it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMessage<RecordKey> {
    origin: PeerOrigin,
    replay_identity: RecordKey,
    body: PeerMessageBody,
    station: Option<StationHint>,
}

impl<RecordKey> PeerMessage<RecordKey> {
    /// Maps one SDK-verified unit and the caller's decoded body.
    ///
    /// Refuses handshake-level values: a message unit is one committed
    /// protected record, and only the SDK's `receive_record` produces that
    /// replay identity.
    pub fn of_verified(
        unit: &impl VerifiedUnit<RecordKey = RecordKey>,
        forwarder: MessageForwarder,
        body: PeerMessageBody,
    ) -> Result<Self, PeerUnitRefusal> {
        let replay_identity = unit.verified_record().ok_or(PeerUnitRefusal::NotARecord)?;
        Ok(Self {
            origin: PeerOrigin::of_verified(unit, forwarder),
            replay_identity,
            body,
            station: None,
        })
    }

    /// Attaches the station's read-only report for this unit.
    #[must_use]
    pub fn with_station_hint(mut self, hint: StationHint) -> Self {
        self.station = Some(hint);
        self
    }

    #[must_use]
    pub const fn origin(&self) -> &PeerOrigin {
        &self.origin
    }

    #[must_use]
    pub const fn replay_identity(&self) -> &RecordKey {
        &self.replay_identity
    }

    #[must_use]
    pub const fn logical_id(&self) -> [u8; 16] {
        self.body.logical_id()
    }

    #[must_use]
    pub const fn relates_to(&self) -> Option<[u8; 16]> {
        self.body.relates_to()
    }

    #[must_use]
    pub fn parts(&self) -> &[PeerPart] {
        self.body.parts()
    }

    #[must_use]
    pub const fn station(&self) -> Option<StationHint> {
        self.station
    }
}
