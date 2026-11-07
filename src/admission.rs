//! Admission of one explicitly supplied Protocol Line authority artifact.
//!
//! Protocol definition, line identity, source closure, and every algorithm
//! belong to LicoArc and its Rust SDK. This crate owns only the caller-side
//! boundary: it hands the caller's exact bytes to the SDK and accepts only what
//! the SDK verifies as the fixed Candidate. There is no second parser, no
//! project-level digest gate, and no line that LicoUp can mint, patch, or
//! extrapolate on its own.

use core::fmt;

use licoarc::artifact::{AuthorityBundle, VerifiedProtocolLine};
use licoarc::error::Error;

/// Stable code reported for every refused authority artifact.
pub const AUTHORIZATION_REQUIRED: &str = "authorization_required";

/// One explicitly supplied, read-only authority artifact.
///
/// The bytes are the caller's fixed input. They are never fetched, synthesized,
/// or modified here, and an empty or oversized input is refused like any other
/// input that is not the fixed Candidate.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityInput<'a> {
    bytes: &'a [u8],
}

impl<'a> AuthorityInput<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Admit the fixed Candidate, or refuse with [`AUTHORIZATION_REQUIRED`].
    ///
    /// The SDK decides this: it checks the artifact version, wire identity,
    /// generation, Candidate lifecycle, complete definition, session
    /// eligibility, absent publication eligibility, source closure, and content
    /// address. Any other input — unknown, incomplete, mutated, or a different
    /// line — is refused here, before LicoUp writes or sends anything.
    pub fn admit(self) -> Result<VerifiedProtocolLine, AdmissionRefusal> {
        AuthorityBundle::new(self.bytes)
            .admit()
            .map_err(AdmissionRefusal::new)
    }
}

/// Refused authority artifact.
///
/// One stable LicoUp code, plus the SDK's bounded cause. It never carries input
/// bytes, payloads, secrets, or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionRefusal {
    cause: Error,
}

impl AdmissionRefusal {
    const fn new(cause: Error) -> Self {
        Self { cause }
    }

    /// Stable LicoUp code for every refused artifact.
    #[must_use]
    pub const fn code(self) -> &'static str {
        AUTHORIZATION_REQUIRED
    }

    /// Bounded SDK error that refused the artifact.
    #[must_use]
    pub const fn cause(self) -> Error {
        self.cause
    }
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", AUTHORIZATION_REQUIRED, self.cause)
    }
}

impl std::error::Error for AdmissionRefusal {}
