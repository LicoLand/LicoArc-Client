//! What a recovery situation means for an established result and for admission.
//!
//! A disconnect, a lost transport, a verified revocation, or a caller-owned
//! restart must never be collapsed into one "session is dead" decision. The
//! pinned SDK distinguishes the cases itself; this module only classifies them
//! into the next legal client action, citing the SDK behaviour each rule
//! mirrors (`licoarc-rust` at revision
//! `244ce7186cac1690c18f091dbe02df36a0860ef4`).
//!
//! Two rules apply to every case:
//!
//! * An already-established, already-authenticated result is never re-derived
//!   from a local sequence. Its reconciliation exit is to re-drive exactly the
//!   committed work the protocol layer already identified
//!   (`Endpoint::retry_record`, `src/endpoint/mod.rs:956-970`); a second fresh
//!   packet for one session is refused (`src/endpoint/mod.rs:908-914`).
//! * A refused call is refused alone. The SDK refuses a version, a payload, or a
//!   generation per call, so the established result and every other accepted
//!   call stay usable.

use crate::ports::{Revision, TransportOutcome};

/// One observed recovery situation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    /// The transport went away while the protocol session stayed authenticated.
    /// `pending_work` is whether a committed item is still outstanding.
    TransportDisconnected { pending_work: bool },
    /// One transport attempt ended with the SDK's own classification
    /// (`src/transport.rs:222-229`). `Ambiguous` is the 504 case: the attempt
    /// may or may not have been accepted.
    TransportAttempt(TransportOutcome),
    /// A verified authority roster revoked this device, or could not re-admit
    /// it. `established_result_authenticated` is whether a result was already
    /// authenticated for it before the revocation.
    RosterRevocation {
        established_result_authenticated: bool,
    },
    /// The protocol session was deleted. `Deleted` is absorbing: every later
    /// operation on it is refused (`src/endpoint/mod.rs:1195-1198`).
    SessionDeleted,
    /// A caller-owned restart saw a persisted generation that is not the
    /// current one (`validate_restart`, `src/state/mod.rs:545-556`;
    /// `Endpoint::restart`, `src/endpoint/mod.rs:1240-1253`).
    GenerationRestart {
        persisted: Revision,
        current: Revision,
    },
}

/// The next legal client action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRecovery {
    /// The established result stands and nothing is outstanding.
    Continue,
    /// The established result stands and exactly the already-committed pending
    /// item must be re-driven.
    RedrivePending,
    /// Refuse this call only. Nothing established is destroyed, and no other
    /// accepted call is affected.
    RefuseCallOnly,
    /// The established result can no longer be used. A new admission is needed.
    NewAdmission,
}

impl SessionRecovery {
    /// Whether the established result is still usable afterwards.
    #[must_use]
    pub const fn keeps_established_result(self) -> bool {
        !matches!(self, Self::NewAdmission)
    }

    /// Whether a new admission is the only way forward.
    #[must_use]
    pub const fn requires_new_admission(self) -> bool {
        matches!(self, Self::NewAdmission)
    }
}

impl RecoveryEvent {
    /// Classifies the observed event into the next legal client action.
    #[must_use]
    pub fn recovery(self) -> SessionRecovery {
        match self {
            Self::TransportDisconnected { pending_work } => {
                if pending_work {
                    SessionRecovery::RedrivePending
                } else {
                    SessionRecovery::Continue
                }
            }
            Self::TransportAttempt(TransportOutcome::Accepted) => SessionRecovery::Continue,
            // A definite refusal belongs to this call. The session state was
            // committed before the attempt, so the established result stands.
            Self::TransportAttempt(TransportOutcome::Rejected) => SessionRecovery::RefuseCallOnly,
            // Transient and ambiguous both re-drive the same committed packet:
            // the outcome is unknown, and a fresh packet would be a second unit.
            Self::TransportAttempt(TransportOutcome::Transient)
            | Self::TransportAttempt(TransportOutcome::Ambiguous) => {
                SessionRecovery::RedrivePending
            }
            // A revocation governs new admissions. An entry that was already
            // accepted stays as it was and is skipped by the roster check
            // (`src/identity.rs:255-263`), while a new payload from a device that
            // is no longer active is refused (`src/identity.rs:380-397`).
            Self::RosterRevocation {
                established_result_authenticated,
            } => {
                if established_result_authenticated {
                    SessionRecovery::Continue
                } else {
                    SessionRecovery::NewAdmission
                }
            }
            Self::SessionDeleted => SessionRecovery::NewAdmission,
            // A rolled-back store cannot be trusted at all; a future generation
            // is refused and destroys nothing.
            Self::GenerationRestart { persisted, current } => {
                if persisted < current {
                    SessionRecovery::NewAdmission
                } else if persisted > current {
                    SessionRecovery::RefuseCallOnly
                } else {
                    SessionRecovery::Continue
                }
            }
        }
    }
}
