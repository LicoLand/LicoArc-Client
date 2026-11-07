//! Explicit provenance: verified author, verified device, carriage forwarder.
//!
//! The author and the device come from the SDK-verified facts of the unit. The
//! forwarder is caller-supplied carriage context and is deliberately a third,
//! separate value: a forwarding station is an untrusted relay, so it must never
//! be substituted for either verified identity.

use super::{PeerUnitRefusal, VerifiedUnit};

/// Largest accepted station label, matching the bounded station configuration.
pub const MAX_STATION_ID_BYTES: usize = 128;

/// The verified author of one inbound unit.
///
/// The digest is the user-authority state digest the accepted session bound;
/// it is an identity reference, never a permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAuthor {
    user_authority_state_digest: [u8; 32],
}

impl PeerAuthor {
    /// Reads the author fact of the verified unit.
    ///
    /// Only an SDK-verified [`VerifiedUnit`] value can be passed here.
    #[must_use]
    pub fn of_verified(unit: &impl VerifiedUnit) -> Self {
        Self {
            user_authority_state_digest: unit.verified_author(),
        }
    }

    #[must_use]
    pub const fn user_authority_state_digest(self) -> [u8; 32] {
        self.user_authority_state_digest
    }
}

/// The verified device of one inbound unit.
///
/// Every field is the SDK's own identity reference, not a local display value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerDevice {
    identity_state_digest: [u8; 32],
    ed25519_key_id: [u8; 32],
    ml_dsa_65_key_id: [u8; 32],
}

impl PeerDevice {
    /// Reads the device fact of the verified unit.
    ///
    /// Only an SDK-verified [`VerifiedUnit`] value can be passed here.
    #[must_use]
    pub fn of_verified(unit: &impl VerifiedUnit) -> Self {
        let device = unit.verified_device();
        Self {
            identity_state_digest: device.identity_state_digest(),
            ed25519_key_id: device.ed25519_key_id(),
            ml_dsa_65_key_id: device.ml_dsa_65_key_id(),
        }
    }

    #[must_use]
    pub const fn identity_state_digest(self) -> [u8; 32] {
        self.identity_state_digest
    }

    #[must_use]
    pub const fn ed25519_key_id(self) -> [u8; 32] {
        self.ed25519_key_id
    }

    #[must_use]
    pub const fn ml_dsa_65_key_id(self) -> [u8; 32] {
        self.ml_dsa_65_key_id
    }
}

/// One validated carriage label of an untrusted relay or station hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StationRef(String);

impl StationRef {
    /// Bounded, NUL-free station label; anything else is refused.
    pub fn new(station_id: &str) -> Result<Self, PeerUnitRefusal> {
        let valid = !station_id.is_empty()
            && station_id.len() <= MAX_STATION_ID_BYTES
            && !station_id.contains('\0');
        if !valid {
            return Err(PeerUnitRefusal::StationIdentityInvalid);
        }
        Ok(Self(station_id.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How one inbound unit reached this client.
///
/// Direct carriage has no intermediary. A station hop is carriage only: it
/// changes no author, device, permission, or delivery fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageForwarder {
    Direct,
    Station(StationRef),
}

/// The complete, explicit provenance of one inbound unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerOrigin {
    author: PeerAuthor,
    device: PeerDevice,
    forwarder: MessageForwarder,
}

impl PeerOrigin {
    /// Reads the verified author and device from the unit's facts and pairs them
    /// with the caller's carriage context.
    #[must_use]
    pub fn of_verified(unit: &impl VerifiedUnit, forwarder: MessageForwarder) -> Self {
        Self {
            author: PeerAuthor::of_verified(unit),
            device: PeerDevice::of_verified(unit),
            forwarder,
        }
    }

    #[must_use]
    pub const fn author(&self) -> PeerAuthor {
        self.author
    }

    #[must_use]
    pub const fn device(&self) -> PeerDevice {
        self.device
    }

    #[must_use]
    pub const fn forwarder(&self) -> &MessageForwarder {
        &self.forwarder
    }

    /// Whether a station or relay hop carried this unit.
    #[must_use]
    pub const fn is_station_forwarded(&self) -> bool {
        matches!(self.forwarder, MessageForwarder::Station(_))
    }
}
