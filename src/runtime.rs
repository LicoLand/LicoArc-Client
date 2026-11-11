//! The asynchronous client runtime: mailbox receive lane and pending drains.
//!
//! The runtime is thin on purpose. The SDK owns protocol truth; the carrier
//! owns the wire; the caller owns the endpoint ports. What this module adds
//! is the *drive* between them:
//!
//! * [`receive_loop`] runs one inbound lane — DELIVER frames feed a
//!   caller-owned [`PacketSink`], each verdict ACKs the delivery; connection
//!   loss reconnects with bounded backoff.
//! * [`Spool`] is the durable local inbox: deliveries land on disk before
//!   the ACK, and session processing consumes them after.
//! * [`drain_pending`] re-drives committed pending work (packets, plaintext).
//!
//! Station answers remain transport hints: an ACK proves only that the
//! Station may delete the stored packet, never that an endpoint consumed it.

mod drain;
mod mailbox;
mod sink;
mod spool;

pub use drain::{DrainReport, PendingWork, drain_pending};
pub use mailbox::{LoopExit, PacketSink, Verdict, receive_loop};
pub use sink::{EndpointSink, FreshPrivate, NoFreshPrivate, Received, Refused, SessionSink};
pub use spool::Spool;
