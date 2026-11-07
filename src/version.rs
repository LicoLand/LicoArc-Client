//! The protocol version this client accepts, and what it does with one it does not.
//!
//! The version of a LicoArc Protocol Line is not a single number. The pinned SDK
//! exposes four fields that together identify the exact accepted Line, and every
//! one of them is part of the acceptance:
//!
//! * `wire_id` — `VerifiedProtocolLine::wire_id`, `licoarc-rust/src/artifact/mod.rs:104-107`
//! * `generation` — `VerifiedProtocolLine::generation`, `src/artifact/mod.rs:109-112`
//! * `protocol_line_id` — `VerifiedProtocolLine::protocol_line_id`, `src/artifact/mod.rs:119-122`
//! * `protection_profile_id` — `VerifiedProtocolLine::protection_profile_id`, `src/artifact/mod.rs:124-127`
//!
//! This client accepts exactly one Line identity, frozen in [`AcceptedVersion::fixed`]
//! from the same fixed Candidate the SDK verifies. A Line that does not match is
//! refused **for that call only**: the refusal is a value returned by the call,
//! the client keeps no mutable state about it, and every other call with an
//! accepted version keeps working.
//!
//! The SDK itself is the ultimate authority on the bytes: this contract never
//! admits or verifies an artifact, it only declares which already-verified
//! identity this build is willing to use, and it also covers the persisted
//! version record a caller restores after a restart.

use core::fmt;

use licoarc::artifact::VerifiedProtocolLine;

/// The one wire identity this client accepts.
pub const ACCEPTED_WIRE_ID: &str = "licoarc.protocol-line.v1";
/// The one Line generation this client accepts.
pub const ACCEPTED_GENERATION: u64 = 1;
/// The fixed Candidate Line identity (`src/artifact/mod.rs:40`), as bytes.
pub const ACCEPTED_PROTOCOL_LINE_ID: [u8; 32] = [
    0xc0, 0xb6, 0x4d, 0x71, 0x86, 0x5c, 0xe9, 0x72, 0xa9, 0x44, 0xdb, 0x3d, 0x31, 0xa1, 0x8c, 0xb0,
    0x33, 0x95, 0x30, 0x0f, 0x3e, 0xd0, 0x06, 0xc2, 0x1e, 0x64, 0x42, 0x91, 0x78, 0xc2, 0x3a, 0x08,
];
/// The fixed Candidate protection profile (`src/artifact/mod.rs:41-42`), as bytes.
pub const ACCEPTED_PROTECTION_PROFILE_ID: [u8; 32] = [
    0x4b, 0x7d, 0x57, 0x5f, 0x39, 0x78, 0x62, 0xf9, 0x03, 0x1e, 0x44, 0xb7, 0x16, 0x92, 0x1e, 0x86,
    0xc4, 0x10, 0xb5, 0xfa, 0xcf, 0x37, 0x9b, 0xde, 0x21, 0x95, 0x59, 0x22, 0xb0, 0xd5, 0x8a, 0x17,
];

/// The complete version identity of one Protocol Line.
///
/// It is built either from a Line the SDK already verified
/// ([`ProtocolVersion::of`]) or from the version record a caller persisted
/// earlier ([`ProtocolVersion::restored`]), so a restored record is checked
/// against the same acceptance as a live one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolVersion {
    wire_id: String,
    generation: u64,
    protocol_line_id: [u8; 32],
    protection_profile_id: [u8; 32],
}

impl ProtocolVersion {
    /// Reads the version identity out of an SDK-verified Protocol Line.
    #[must_use]
    pub fn of(line: &VerifiedProtocolLine) -> Self {
        Self {
            wire_id: line.wire_id().to_owned(),
            generation: line.generation(),
            protocol_line_id: *line.protocol_line_id(),
            protection_profile_id: *line.protection_profile_id(),
        }
    }

    /// Rebuilds the version record a caller persisted for an accepted session.
    #[must_use]
    pub fn restored(
        wire_id: &str,
        generation: u64,
        protocol_line_id: [u8; 32],
        protection_profile_id: [u8; 32],
    ) -> Self {
        Self {
            wire_id: wire_id.to_owned(),
            generation,
            protocol_line_id,
            protection_profile_id,
        }
    }

    #[must_use]
    pub fn wire_id(&self) -> &str {
        &self.wire_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The protocol line id a caller binds inbound protocol state to.
    ///
    /// The SDK checks it too: a user authority state naming another line is
    /// refused with `AuthorizationFailed`
    /// (`src/identity.rs:145-147`).
    #[must_use]
    pub const fn protocol_line_id(&self) -> [u8; 32] {
        self.protocol_line_id
    }

    #[must_use]
    pub const fn protection_profile_id(&self) -> [u8; 32] {
        self.protection_profile_id
    }
}

/// The single Line identity this build of the client accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedVersion {
    wire_id: &'static str,
    generation: u64,
    protocol_line_id: [u8; 32],
    protection_profile_id: [u8; 32],
}

impl AcceptedVersion {
    /// The frozen acceptance: the fixed Candidate integrated by this build.
    #[must_use]
    pub const fn fixed() -> Self {
        Self {
            wire_id: ACCEPTED_WIRE_ID,
            generation: ACCEPTED_GENERATION,
            protocol_line_id: ACCEPTED_PROTOCOL_LINE_ID,
            protection_profile_id: ACCEPTED_PROTECTION_PROFILE_ID,
        }
    }

    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        self.wire_id
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn protocol_line_id(self) -> [u8; 32] {
        self.protocol_line_id
    }

    #[must_use]
    pub const fn protection_profile_id(self) -> [u8; 32] {
        self.protection_profile_id
    }

    /// Accepts one version, or refuses that call.
    ///
    /// Every mismatching field is reported, so the caller learns which part of
    /// the version it does not support instead of a bare failure.
    pub fn check(self, version: &ProtocolVersion) -> Result<(), VersionRefusal> {
        if version.wire_id != self.wire_id {
            return Err(VersionRefusal::WireId {
                accepted: self.wire_id,
            });
        }
        if version.generation != self.generation {
            return Err(VersionRefusal::Generation {
                accepted: self.generation,
            });
        }
        if version.protocol_line_id != self.protocol_line_id {
            return Err(VersionRefusal::ProtocolLine);
        }
        if version.protection_profile_id != self.protection_profile_id {
            return Err(VersionRefusal::ProtectionProfile);
        }
        Ok(())
    }
}

impl Default for AcceptedVersion {
    fn default() -> Self {
        Self::fixed()
    }
}

/// One refused version, naming the field that does not match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionRefusal {
    WireId { accepted: &'static str },
    Generation { accepted: u64 },
    ProtocolLine,
    ProtectionProfile,
}

impl VersionRefusal {
    /// Stable code reported to the client for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WireId { .. } => "unsupported_wire_id",
            Self::Generation { .. } => "unsupported_generation",
            Self::ProtocolLine => "unsupported_protocol_line",
            Self::ProtectionProfile => "unsupported_protection_profile",
        }
    }
}

impl fmt::Display for VersionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireId { accepted } => {
                write!(formatter, "{}: {accepted}", self.code())
            }
            Self::Generation { accepted } => {
                write!(formatter, "{}: {accepted}", self.code())
            }
            Self::ProtocolLine | Self::ProtectionProfile => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for VersionRefusal {}

#[cfg(test)]
mod tests {
    use super::{
        ACCEPTED_GENERATION, ACCEPTED_PROTECTION_PROFILE_ID, ACCEPTED_PROTOCOL_LINE_ID,
        ACCEPTED_WIRE_ID, AcceptedVersion, ProtocolVersion, VersionRefusal,
    };

    fn accepted() -> ProtocolVersion {
        ProtocolVersion::restored(
            ACCEPTED_WIRE_ID,
            ACCEPTED_GENERATION,
            ACCEPTED_PROTOCOL_LINE_ID,
            ACCEPTED_PROTECTION_PROFILE_ID,
        )
    }

    #[test]
    fn the_accepted_version_is_accepted() {
        assert_eq!(AcceptedVersion::fixed().check(&accepted()), Ok(()));
        assert_eq!(AcceptedVersion::default(), AcceptedVersion::fixed());
    }

    #[test]
    fn each_mismatching_field_is_named_in_its_own_refusal() {
        let refused = |version: ProtocolVersion| {
            AcceptedVersion::fixed()
                .check(&version)
                .expect_err("this version is not accepted")
        };

        let other_wire = ProtocolVersion::restored(
            "licoarc.protocol-line.v2",
            ACCEPTED_GENERATION,
            ACCEPTED_PROTOCOL_LINE_ID,
            ACCEPTED_PROTECTION_PROFILE_ID,
        );
        assert_eq!(
            refused(other_wire),
            VersionRefusal::WireId {
                accepted: ACCEPTED_WIRE_ID
            }
        );

        assert_eq!(
            refused(ProtocolVersion::restored(
                ACCEPTED_WIRE_ID,
                2,
                ACCEPTED_PROTOCOL_LINE_ID,
                ACCEPTED_PROTECTION_PROFILE_ID,
            )),
            VersionRefusal::Generation {
                accepted: ACCEPTED_GENERATION
            }
        );

        let mut line = ACCEPTED_PROTOCOL_LINE_ID;
        line[0] ^= 1;
        assert_eq!(
            refused(ProtocolVersion::restored(
                ACCEPTED_WIRE_ID,
                ACCEPTED_GENERATION,
                line,
                ACCEPTED_PROTECTION_PROFILE_ID,
            )),
            VersionRefusal::ProtocolLine
        );

        let mut profile = ACCEPTED_PROTECTION_PROFILE_ID;
        profile[0] ^= 1;
        assert_eq!(
            refused(ProtocolVersion::restored(
                ACCEPTED_WIRE_ID,
                ACCEPTED_GENERATION,
                ACCEPTED_PROTOCOL_LINE_ID,
                profile,
            )),
            VersionRefusal::ProtectionProfile
        );
    }

    #[test]
    fn a_refused_version_refuses_that_call_only() {
        let acceptance = AcceptedVersion::fixed();
        for version in [
            ProtocolVersion::restored("other", 9, [0; 32], [0; 32]),
            ProtocolVersion::restored(ACCEPTED_WIRE_ID, 9, [0; 32], [0; 32]),
            ProtocolVersion::restored(ACCEPTED_WIRE_ID, ACCEPTED_GENERATION, [0; 32], [0; 32]),
            ProtocolVersion::restored(
                ACCEPTED_WIRE_ID,
                ACCEPTED_GENERATION,
                ACCEPTED_PROTOCOL_LINE_ID,
                [0; 32],
            ),
        ] {
            assert!(acceptance.check(&version).is_err());
            // The refusal left no trace: the very next accepted call succeeds.
            assert_eq!(acceptance.check(&accepted()), Ok(()));
        }
    }

    #[test]
    fn refusal_codes_are_stable_and_carry_no_payload() {
        assert_eq!(
            VersionRefusal::WireId {
                accepted: ACCEPTED_WIRE_ID
            }
            .code(),
            "unsupported_wire_id"
        );
        assert_eq!(
            VersionRefusal::Generation {
                accepted: ACCEPTED_GENERATION
            }
            .code(),
            "unsupported_generation"
        );
        assert_eq!(
            VersionRefusal::ProtocolLine.code(),
            "unsupported_protocol_line"
        );
        assert_eq!(
            VersionRefusal::ProtectionProfile.code(),
            "unsupported_protection_profile"
        );
        assert_eq!(
            VersionRefusal::Generation { accepted: 1 }.to_string(),
            "unsupported_generation: 1"
        );
    }
}
