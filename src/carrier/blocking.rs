//! Blocking [`Transport`] port adapter over the asynchronous Station client.
//!
//! The SDK's packet boundary is synchronous: `dispatch_pending` calls
//! `PacketCarrier::send` from inside the protocol drive. The carrier is
//! asynchronous, so this adapter owns one dedicated current-thread I/O
//! runtime and blocks the protocol thread on one bounded submit exchange.
//! The submit loop itself is the profile's own bounded same-identifier retry,
//! so a block here never turns into an unbounded wait.

use std::sync::Arc;

use crate::ports::{PortFailure, Transport, TransportOutcome};

use super::client::{StationClient, StationError};
use super::token::HandleToken;

/// One outbound delivery lane: a Station client plus one peer handle.
///
/// Construct it outside a Tokio context; it must not be used from inside
/// another runtime's worker, because `block_on` cannot nest.
pub struct SubmitCarrier {
    client: Arc<StationClient>,
    handle: HandleToken,
    runtime: tokio::runtime::Runtime,
}

impl SubmitCarrier {
    /// Binds one shared Station client to one peer handle with its own I/O
    /// runtime.
    pub fn new(client: Arc<StationClient>, handle: HandleToken) -> Result<Self, PortFailure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PortFailure::Unavailable)?;
        Ok(Self {
            client,
            handle,
            runtime,
        })
    }
}

impl Transport for SubmitCarrier {
    fn submit(&mut self, packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
        let client = self.client.clone();
        let handle = self.handle;
        let result = self
            .runtime
            .block_on(async move { client.submit(handle, packet).await });
        match result {
            Ok(()) => Ok(TransportOutcome::Accepted),
            // A definitive refusal is the rejected outcome, never a success.
            Err(StationError::Rejected { .. }) => Ok(TransportOutcome::Rejected),
            // After the bounded retry loop the outcome is unknown: the
            // operation may or may not have committed. That is the ambiguous
            // outcome, and the already-committed pending item stays durable
            // for the next re-drive.
            Err(StationError::Uncertain | StationError::Nonconforming) => {
                Ok(TransportOutcome::Ambiguous)
            }
            // The packet never left the client: the failure is definite, not
            // uncertain.
            Err(
                StationError::InvalidControl
                | StationError::InvalidOrigin
                | StationError::Access(_),
            ) => Err(PortFailure::Unavailable),
        }
    }
}
