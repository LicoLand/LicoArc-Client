//! Blocking [`Transport`] port adapter over the asynchronous mailbox client.
//!
//! The SDK's packet boundary is synchronous: `dispatch_pending` calls
//! `PacketCarrier::send` from inside the protocol drive. The carrier is
//! asynchronous, so this adapter owns one dedicated current-thread I/O
//! runtime and blocks the protocol thread on one submit exchange.

use std::sync::Arc;

use crate::ports::{PortFailure, Transport, TransportOutcome};

use super::connection::{MailboxClient, StationError};
use super::token::HandleToken;

/// One outbound delivery lane: a mailbox client plus one peer handle.
///
/// Construct it outside a Tokio context; it must not be used from inside
/// another runtime's worker, because `block_on` cannot nest.
pub struct SubmitCarrier {
    client: Arc<MailboxClient>,
    handle: HandleToken,
    runtime: Option<tokio::runtime::Runtime>,
}

impl SubmitCarrier {
    /// Binds one live mailbox client to one peer handle.
    ///
    /// The client's I/O task must run on a multi-threaded runtime that
    /// outlives it (see [`MailboxClient::connect`]). A client connected on a
    /// current-thread runtime only advances its I/O task while that
    /// runtime's `block_on` runs, and `submit`'s private `block_on` would
    /// wait on a RESULT that can never arrive — so this constructor refuses
    /// such a client with [`std::io::ErrorKind::Unsupported`] instead of
    /// deadlocking.
    pub fn new(client: Arc<MailboxClient>, handle: HandleToken) -> Result<Self, std::io::Error> {
        if client.is_current_thread_runtime() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "mailbox client connected on a current-thread runtime;                  SubmitCarrier needs the connection's I/O task on a                  multi-threaded runtime that outlives the client",
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            client,
            handle,
            runtime: Some(runtime),
        })
    }

    /// The bound peer handle.
    #[must_use]
    pub const fn handle(&self) -> HandleToken {
        self.handle
    }
}

impl Transport for SubmitCarrier {
    fn submit(&mut self, packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
        match self
            .runtime
            .as_ref()
            .expect("submit after drop")
            .block_on(self.client.send(self.handle, packet))
        {
            Ok(()) => Ok(TransportOutcome::Accepted),
            Err(error) => map_error(error),
        }
    }
}

/// Maps the station exchange onto the port contract. `Ok` reports the
/// outcome a `submit` must return; `Err` reports a port failure.
fn map_error(error: StationError) -> Result<TransportOutcome, PortFailure> {
    match error {
        StationError::Rejected { .. } => Ok(TransportOutcome::Rejected),
        StationError::Transient { .. } => Ok(TransportOutcome::Transient),
        StationError::Ambiguous => Ok(TransportOutcome::Ambiguous),
        StationError::Superseded
        | StationError::Revoked
        | StationError::DeviceMismatch
        | StationError::Refused
        | StationError::Protocol
        | StationError::Io(_) => Err(PortFailure::Unavailable),
    }
}

impl Drop for SubmitCarrier {
    fn drop(&mut self) {
        // `Runtime::drop` panics inside an async context; the background
        // shutdown does not block, so it is safe wherever the caller
        // releases the carrier.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
