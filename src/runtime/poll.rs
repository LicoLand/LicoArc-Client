//! The inbound poll loop: paced [`Mailbox::pump`] passes until stopped.
//!
//! One pass claims a bounded batch, offers every packet to the caller's
//! [`PacketSink`] exactly once, and settles it with the produced verdict. The
//! loop adds only scheduling: it waits `pace` between passes, survives
//! uncertain station outcomes by trying again next pass, and ends on the
//! caller's stop signal or on a definite station refusal. It never decides
//! packet verdicts and never retries inside a pass — settlement is the
//! station's bounded claim window, not a client retry.

use std::time::Duration;

use crate::carrier::StationError;

use super::mailbox::{Carrier, Mailbox, PacketSink, PumpReport};

/// The cadence between pump passes. The profile's own claim window bounds
/// the station side; this bounds only how often the client asks.
#[derive(Clone, Copy, Debug)]
pub struct PollPace {
    /// Idle wait after a pass that claimed nothing.
    pub idle: Duration,
    /// Wait after a pass that claimed at least one item: the next batch may
    /// already be waiting, so the pace is the caller's, typically shorter.
    pub active: Duration,
}

impl PollPace {
    /// One poll a second while idle, immediate follow-up after a live pass.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            idle: Duration::from_secs(1),
            active: Duration::ZERO,
        }
    }
}

/// What the loop did before it stopped.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollReport {
    /// Completed pump passes.
    pub passes: u64,
    /// Total items claimed across all passes.
    pub claimed: u64,
}

/// Pumps one lane until `stop` resolves or the station refuses the lane.
///
/// An uncertain pass (the station may or may not have settled) is not a loop
/// failure: the claim window makes the items claimable again, so the loop
/// waits `idle` and re-drives the same lane. A definite refusal —
/// `Rejected`, `Nonconforming`, `InvalidControl`, `InvalidOrigin` — ends the
/// loop with the station's own error.
///
/// `observe` sees each completed pass verbatim (claimed/settled/results), so
/// a daemon can log or meter without the loop inventing counters of its own.
///
/// # Errors
///
/// Returns the first definite [`StationError`] verbatim.
pub async fn poll_loop<C, S>(
    mailbox: &Mailbox<C>,
    sink: &mut S,
    pace: PollPace,
    stop: impl core::future::Future<Output = ()>,
    mut observe: impl FnMut(&PumpReport),
) -> Result<PollReport, StationError>
where
    C: Carrier,
    S: PacketSink,
{
    let mut stop = core::pin::pin!(stop);
    let mut report = PollReport::default();
    loop {
        let report_pass = tokio::select! {
            () = &mut stop => return Ok(report),
            pass = mailbox.pump(sink) => pass,
        };
        let claimed = match report_pass {
            Ok(pass) => {
                observe(&pass);
                pass.claimed
            }
            Err(StationError::Uncertain) => 0,
            Err(error) => return Err(error),
        };
        report.passes += 1;
        report.claimed += claimed as u64;
        let wait = if claimed == 0 { pace.idle } else { pace.active };
        tokio::select! {
            () = &mut stop => return Ok(report),
            () = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::{PollPace, poll_loop};
    use crate::carrier::{
        ClaimBatch, ClaimedItem, ItemResult, RetrieveRequest, SettleRequest, StationError,
    };
    use crate::runtime::mailbox::{Carrier, ConsumeVerdict, Mailbox, PacketSink};

    struct FakeLane {
        claims: Mutex<VecDeque<Result<ClaimBatch, StationError>>>,
    }

    impl Carrier for FakeLane {
        async fn submit(&self, _packet: &[u8]) -> Result<(), StationError> {
            Ok(())
        }

        async fn claim(&self, _max_items: u64) -> Result<ClaimBatch, StationError> {
            self.claims.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(ClaimBatch {
                    claim_id: [0; 32],
                    claim_epoch: 0,
                    items: vec![],
                })
            })
        }

        async fn retrieve(&self, _request: &RetrieveRequest) -> Result<Vec<u8>, StationError> {
            Err(StationError::Rejected {
                failure_class: None,
            })
        }

        async fn settle(&self, _request: SettleRequest) -> Result<Vec<ItemResult>, StationError> {
            Ok(vec![])
        }
    }

    struct TakeAll;

    impl PacketSink for TakeAll {
        fn accept(&mut self, _packet: &[u8]) -> ConsumeVerdict {
            ConsumeVerdict::Complete
        }
    }

    fn batch(packet_count: usize) -> ClaimBatch {
        ClaimBatch {
            claim_id: [1; 32],
            claim_epoch: 1,
            items: (0..packet_count)
                .map(|index| ClaimedItem {
                    item_id: [index as u8; 32],
                    packet: vec![],
                })
                .collect(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_paces_and_stops() {
        let lane = FakeLane {
            claims: Mutex::new(VecDeque::new()),
        };
        lane.claims.lock().unwrap().push_back(Ok(batch(2)));
        let mailbox = Mailbox::new(lane, 8);
        let mut sink = TakeAll;
        let pace = PollPace {
            idle: Duration::from_secs(30),
            active: Duration::ZERO,
        };
        let report = poll_loop(
            &mailbox,
            &mut sink,
            pace,
            async {
                tokio::time::sleep(Duration::from_secs(61)).await;
            },
            |_| {},
        )
        .await
        .unwrap();
        // 61 idle seconds at 30s pace: the live pass plus two empty passes.
        assert!(report.claimed >= 2 && report.passes >= 2, "{report:?}");
    }

    #[tokio::test]
    async fn a_definite_refusal_ends_the_loop() {
        let lane = FakeLane {
            claims: Mutex::new(VecDeque::new()),
        };
        lane.claims
            .lock()
            .unwrap()
            .push_back(Err(StationError::Rejected {
                failure_class: None,
            }));
        let mailbox = Mailbox::new(lane, 8);
        let mut sink = TakeAll;
        let result = poll_loop(
            &mailbox,
            &mut sink,
            PollPace::standard(),
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(StationError::Rejected { .. })));
    }
}
