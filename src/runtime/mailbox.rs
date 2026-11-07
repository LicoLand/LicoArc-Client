//! One inbound lane: claim → consume → settle.
//!
//! The pump is deliberately mechanical. It asks the Station for at most
//! `max_items`, offers each claimed packet to the caller's [`PacketSink`]
//! exactly once, and settles every item with the verdict the sink actually
//! produced — complete for consumed, release for refused. A claim that
//! returns nothing yields no settle call at all: there is nothing to settle.
//!
//! Settle-item outcomes are reported back, not enforced: `StaleClaim` and
//! `AttemptLimit` are station-side facts the caller may observe through
//! [`PumpReport`], and they still leave the endpoint-side facts exactly
//! where the sink put them.

use std::future::Future;
use std::sync::Arc;

use crate::carrier::{
    ClaimAccepted, ClaimRequest, HandleToken, ItemResult, RetrieveRequest, SettleAction,
    SettleRequest, Settlement, StationClient, StationError,
};

/// The minimal handle-bound lane the pump needs.
///
/// `StationClient` supplies it through [`HandleCarrier`]; tests substitute an
/// in-memory lane to exercise the pump deterministically.
pub trait Carrier {
    /// Delivers one opaque packet to the bound handle.
    fn submit(&self, packet: &[u8]) -> impl Future<Output = Result<(), StationError>> + Send;
    /// Claims the next bounded batch from the bound handle.
    fn claim(
        &self,
        max_items: u64,
    ) -> impl Future<Output = Result<ClaimAccepted, StationError>> + Send;
    /// Reads one item of a live claim back.
    fn retrieve(
        &self,
        request: &RetrieveRequest,
    ) -> impl Future<Output = Result<Vec<u8>, StationError>> + Send;
    /// Atomically completes or releases the listed claim items.
    fn settle(
        &self,
        request: SettleRequest,
    ) -> impl Future<Output = Result<Vec<ItemResult>, StationError>> + Send;
}

/// A [`Carrier`] that forwards every op to one handle on one station client.
#[derive(Clone)]
pub struct HandleCarrier {
    client: Arc<StationClient>,
    handle: HandleToken,
}

impl HandleCarrier {
    #[must_use]
    pub const fn new(client: Arc<StationClient>, handle: HandleToken) -> Self {
        Self { client, handle }
    }

    #[must_use]
    pub const fn handle(&self) -> HandleToken {
        self.handle
    }
}

impl Carrier for HandleCarrier {
    async fn submit(&self, packet: &[u8]) -> Result<(), StationError> {
        self.client.submit(self.handle, packet).await
    }

    async fn claim(&self, max_items: u64) -> Result<ClaimAccepted, StationError> {
        self.client
            .claim(self.handle, &ClaimRequest { max_items })
            .await
    }

    async fn retrieve(&self, request: &RetrieveRequest) -> Result<Vec<u8>, StationError> {
        self.client.retrieve(self.handle, request).await
    }

    async fn settle(&self, request: SettleRequest) -> Result<Vec<ItemResult>, StationError> {
        self.client.settle(self.handle, &request).await
    }
}

/// What the endpoint side did with one claimed packet.
///
/// The pump turns it into the settlement action with the same name;
/// `Release` hands the item back to the Station for a later claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeVerdict {
    /// The packet was durably consumed; delete the item.
    Complete,
    /// The packet was not consumed; make it claimable again.
    Release,
}

/// The caller-owned packet consumer: exactly one verdict per packet.
pub trait PacketSink {
    /// Called once per claimed packet, in claim order.
    fn accept(&mut self, packet: &[u8]) -> ConsumeVerdict;
}

/// What one pump pass did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PumpReport {
    /// Items the Station handed over in the claim.
    pub claimed: usize,
    /// Settlements the sink asked for (`Complete` + `Release`).
    pub settled: usize,
    /// Per-item station outcomes, in settlement order.
    pub results: Vec<ItemResult>,
}

/// One inbound lane over one handle.
pub struct Mailbox<C> {
    carrier: C,
    max_items: u64,
}

impl<C: Carrier> Mailbox<C> {
    /// Binds the lane with the per-claim item bound (`1..=64`).
    #[must_use]
    pub const fn new(carrier: C, max_items: u64) -> Self {
        Self { carrier, max_items }
    }

    /// One claim→consume→settle pass.
    ///
    /// Every item the claim returned is offered to `sink` once, in order, and
    /// every item is settled with its verdict — a released item is not a
    /// failure, it is the item made claimable again. A declined claim or
    /// settle surfaces as the station error verbatim.
    pub async fn pump(&self, sink: &mut impl PacketSink) -> Result<PumpReport, StationError> {
        let batch = self.carrier.claim(self.max_items).await?;
        let mut report = PumpReport {
            claimed: batch.items.len(),
            ..PumpReport::default()
        };
        if batch.items.is_empty() {
            return Ok(report);
        }
        let mut settlements = Vec::with_capacity(batch.items.len());
        for item in &batch.items {
            let action = match sink.accept(&item.packet) {
                ConsumeVerdict::Complete => SettleAction::Complete,
                ConsumeVerdict::Release => SettleAction::Release,
            };
            settlements.push(Settlement {
                item_id: item.item_id,
                action,
            });
        }
        let results = self
            .carrier
            .settle(SettleRequest {
                claim_id: batch.claim_id,
                claim_epoch: batch.claim_epoch,
                settlements,
            })
            .await?;
        report.settled = results.len();
        report.results = results;
        Ok(report)
    }

    /// Re-reads one item of a live claim (e.g. a packet the consumer lost
    /// before it could settle).
    pub async fn retrieve(&self, request: &RetrieveRequest) -> Result<Vec<u8>, StationError> {
        self.carrier.retrieve(request).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::{Carrier, ConsumeVerdict, HandleCarrier, Mailbox, PacketSink, PumpReport};
    use crate::carrier::{
        ClaimBatch, ClaimedItem, ItemResult, RetrieveRequest, SettleOutcome, SettleRequest,
        StationError,
    };

    /// One scripted lane: claims yield queued batches, settles record the
    /// request, retrieves yield queued packets.
    struct FakeLane {
        claims: Mutex<VecDeque<Result<ClaimBatch, StationError>>>,
        retrieves: Mutex<VecDeque<Result<Vec<u8>, StationError>>>,
        settles: Mutex<Vec<Result<Vec<ItemResult>, StationError>>>,
        settled_requests: Mutex<Vec<SettleRequest>>,
        submitted: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeLane {
        fn new() -> Self {
            Self {
                claims: Mutex::new(VecDeque::new()),
                retrieves: Mutex::new(VecDeque::new()),
                settles: Mutex::new(Vec::new()),
                settled_requests: Mutex::new(Vec::new()),
                submitted: Mutex::new(Vec::new()),
            }
        }
    }

    impl Carrier for FakeLane {
        async fn submit(&self, packet: &[u8]) -> Result<(), StationError> {
            self.submitted.lock().unwrap().push(packet.to_vec());
            Ok(())
        }

        async fn claim(&self, _max_items: u64) -> Result<ClaimBatch, StationError> {
            self.claims
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted claim")
        }

        async fn retrieve(&self, _request: &RetrieveRequest) -> Result<Vec<u8>, StationError> {
            self.retrieves
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted retrieve")
        }

        async fn settle(&self, request: SettleRequest) -> Result<Vec<ItemResult>, StationError> {
            self.settled_requests.lock().unwrap().push(request);
            self.settles.lock().unwrap().remove(0)
        }
    }

    struct Verdicts(VecDeque<ConsumeVerdict>);

    impl PacketSink for Verdicts {
        fn accept(&mut self, _packet: &[u8]) -> ConsumeVerdict {
            self.0.pop_front().expect("scripted verdict")
        }
    }

    fn batch(items: &[[u8; 32]], claim_id: u8, epoch: u64) -> ClaimBatch {
        ClaimBatch {
            claim_id: [claim_id; 32],
            claim_epoch: epoch,
            items: items
                .iter()
                .enumerate()
                .map(|(index, id)| ClaimedItem {
                    item_id: *id,
                    packet: vec![index as u8],
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn empty_claim_settles_nothing() {
        let lane = FakeLane::new();
        lane.claims.lock().unwrap().push_back(Ok(batch(&[], 0, 0)));
        let mailbox = Mailbox::new(lane, 8);
        let mut sink = Verdicts(VecDeque::new());
        let report = mailbox.pump(&mut sink).await.unwrap();
        assert_eq!(report, PumpReport::default());
        assert!(mailbox.carrier.settled_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_item_is_settled_with_the_sink_verdict() {
        let lane = FakeLane::new();
        let items = [[1; 32], [2; 32], [3; 32]];
        lane.claims
            .lock()
            .unwrap()
            .push_back(Ok(batch(&items, 9, 2)));
        lane.settles.lock().unwrap().push(Ok(vec![
            ItemResult {
                item_id: [1; 32],
                outcome: SettleOutcome::Completed,
            },
            ItemResult {
                item_id: [2; 32],
                outcome: SettleOutcome::Released,
            },
            ItemResult {
                item_id: [3; 32],
                outcome: SettleOutcome::Completed,
            },
        ]));
        let mailbox = Mailbox::new(lane, 8);
        let mut sink = Verdicts(VecDeque::from([
            ConsumeVerdict::Complete,
            ConsumeVerdict::Release,
            ConsumeVerdict::Complete,
        ]));
        let report = mailbox.pump(&mut sink).await.unwrap();
        assert_eq!(report.claimed, 3);
        assert_eq!(report.settled, 3);
        let request = mailbox.carrier.settled_requests.lock().unwrap()[0].clone();
        assert_eq!(request.claim_id, [9; 32]);
        assert_eq!(request.claim_epoch, 2);
        assert_eq!(request.settlements.len(), 3);
        assert_eq!(request.settlements[0].action as u64, 0);
        assert_eq!(request.settlements[1].action as u64, 1);
        assert_eq!(request.settlements[2].action as u64, 0);
    }

    #[tokio::test]
    async fn a_declined_claim_surfaces_and_settles_nothing() {
        let lane = FakeLane::new();
        lane.claims
            .lock()
            .unwrap()
            .push_back(Err(StationError::Rejected {
                failure_class: None,
            }));
        let mailbox = Mailbox::new(lane, 8);
        let mut sink = Verdicts(VecDeque::new());
        assert!(mailbox.pump(&mut sink).await.is_err());
        assert!(mailbox.carrier.settled_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_carrier_forwards_the_bound_handle() {
        let handle = crate::carrier::HandleToken::from_bytes([7; 32]);
        let carrier = HandleCarrier {
            client: std::sync::Arc::new(
                crate::carrier::StationClient::new(crate::carrier::CarrierConfig {
                    origin: "https://station.example".to_owned(),
                    ..Default::default()
                })
                .unwrap(),
            ),
            handle,
        };
        assert_eq!(carrier.handle(), handle);
    }
}
