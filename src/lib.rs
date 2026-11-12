//! Standalone Lico Arc endpoint client boundary.
//!
//! This crate composes the pinned `licoarc` SDK with caller-owned ports into a
//! runnable endpoint client: admission, port contracts, SDK adapters, verified
//! peer intake, a BadTower station carrier, and an async runtime.
//!
//! The Protocol Line, its definitions, and all cryptography stay with LicoArc
//! and the LicoArc Rust SDK; this crate decides no protocol outcome of its
//! own. Secret custody, persistence, trust, timing, and effects remain
//! caller-owned through [`ports`].
//!
//! * [`admission`] accepts an explicitly supplied authority artifact, or
//!   refuses it fail-closed before any persistent write, network I/O, or
//!   effect;
//! * [`version`] freezes the one Protocol Line version this client accepts;
//! * [`inbound`] runs the SDK's own verification entries and records what they
//!   verified as an explicit [`inbound::TrustFacts`] value;
//! * [`adapters`] is the one composition point between caller ports and SDK
//!   traits;
//! * [`peer`] maps verified SDK units into peer-facing messages without
//!   promoting station hints into endpoint evidence.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod admission;
pub mod authority;
pub mod carrier;
pub mod cli;
pub mod durable_obligation;
pub mod inbound;
pub mod peer;
pub mod ports;
pub mod providers;
pub mod recovery;
pub mod replacement;
pub mod replacement_admission;
pub mod runtime;
pub mod session;
pub mod version;

pub use adapters::{
    AdmittedProtocolWork, AtomicStateAdapter, ClockAdapter, CustodyHandles, KeyCustodyAdapter,
    PacketCarrierAdapter, ProtocolAdmissionRefusal, ProtocolPorts, ProtocolWorkSetup,
    ReplacementRequest, admit_replacement, admit_replacement_with_authority,
};
pub use admission::{AUTHORIZATION_REQUIRED, AdmissionRefusal, AuthorityInput};
pub use authority::{
    AuthenticationRequirement, ClientSession, ClientSessionState, ConfirmationRequirement,
    OperationPolicy,
};
pub use carrier::{
    Credentials, CredentialsError, Event, HandleToken, MailboxClient, SUBPROTOCOL, StationError,
    SubmitCarrier, TokenRefusal,
};
pub use durable_obligation::{
    AdmittedObligation, DEFAULT_PRE_ADMISSION_BUDGET_BYTES,
    DEFAULT_PRE_ADMISSION_RETENTION_SECONDS, DURABLE_OBLIGATION_SCHEMA, DeliveryOutcome,
    DurableObligationRecord, ObligationId, ObligationLedger, ObligationLimits, PreAdmissionRefusal,
    Settled, SettlementRefusal, SweepOutcome,
};
pub use inbound::{
    AuthorFact, DeviceFact, EndpointConsumer, InboundRefusal, InboundSession, PermissionFact,
    ReplayIdentity, TrustFacts, UserRead,
};
pub use ports::{
    AtomicState, Clock, CustodyHandle, CustodyLifecycle, CustodyPurpose, KeyCustody, KeyMutation,
    MAX_SAFE_INTEGER, PendingId, PendingItem, PendingPayload, PortFailure, Revision, StateCommit,
    Transport, TransportOutcome, Versioned,
};
pub use providers::{CustodyRefusal, FileCustody, MemoryState};
pub use recovery::{RecoveryEvent, SessionRecovery};
pub use replacement::{
    AcceptedReplacement, AuthoritySource, ReplacementAuthority, ReplacementAuthorityRefusal,
    ReplacementBinding, ReplacementCredentials, ReplacementOperation, ReplacementPossession,
};
pub use replacement_admission::{
    ReplacementAdmission, ReplacementAdmissionRefusal, ReplacementEndpointKeys,
    ReplacementPredecessor, ReplacementSession, SdkReplacementAuthority,
    VerifiedReplacementAuthority,
};
pub use runtime::{
    DrainReport, EndpointSink, FreshPrivate, LoopExit, NoFreshPrivate, PacketSink, PendingWork,
    Received, ReconnectPolicy, Refused, SessionSink, Spool, Verdict, drain_pending, receive_loop,
};
pub use session::{
    EnvelopeRefusal, FileState, InitiatorDrive, LocalIdentity, MintRefusal, OfferRefusal,
    PairingOffer, PairingReply, PairingSubmission, ResponderDrive, StaticTrust, SystemClock,
    load_peer_identity,
};
pub use version::{
    ACCEPTED_GENERATION, ACCEPTED_PROTECTION_PROFILE_ID, ACCEPTED_PROTOCOL_LINE_ID,
    ACCEPTED_WIRE_ID, AcceptedVersion, ProtocolVersion, VersionRefusal,
};

/// Fixed-revision SDK traits and state used by the endpoint adapters.
/// Caller port contracts remain SDK-free; adapters consume the same pinned
/// boundary.
pub use licoarc::{endpoint, identity, provider, reliable, state};

pub use licoarc::artifact::{AuthorityBundle, VerifiedProtocolLine};
pub use licoarc::error::{Error, ErrorCode, Stage};

#[cfg(test)]
mod tests;
