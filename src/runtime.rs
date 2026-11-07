//! The asynchronous client runtime: handle lifecycle and inbox/outbox pumps.
//!
//! The runtime is thin on purpose. The SDK owns protocol truth; the carrier
//! owns the wire; the caller owns the endpoint ports. What this module adds
//! is the *drive* between them:
//!
//! * [`Mailbox`] runs one inbound lane — CLAIM a bounded batch, hand every
//!   claimed packet to a caller-owned [`PacketSink`], then SETTLE each item
//!   with the sink's own verdict (complete what was consumed, release what
//!   was not). Retrieval re-reads one item of a live claim.
//! * [`Carrier`] is the minimal handle-bound lane surface the pump needs; it
//!   is implemented by [`HandleCarrier`] over [`StationClient`] and is easy to
//!   fake in tests.
//!
//! Station answers remain transport hints: a settled item proves only that
//! the Station accepted the settlement, never that an endpoint consumed it.

mod drain;
mod mailbox;
mod poll;
mod sink;

pub use drain::{DrainReport, PendingWork, drain_pending};
pub use mailbox::{Carrier, ConsumeVerdict, HandleCarrier, Mailbox, PacketSink, PumpReport};
pub use poll::{PollPace, PollReport, poll_loop};
pub use sink::{EndpointSink, FreshPrivate, NoFreshPrivate, Received, Refused, SessionSink};
