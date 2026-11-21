//! The receive loop: connect, deliver every DELIVER to the caller's sink,
//! ACK after the sink's verdict, reconnect on ordinary connection loss.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::watch;

use crate::carrier::{Credentials, Event, HandleToken, MailboxClient, StationError};

/// What the endpoint side did with one delivered packet.
///
/// `Done` covers both "consumed" and "permanently refused": the station must
/// not keep a packet the endpoint will never accept, so both complete the
/// delivery and ACK. `Defer` is a local transient failure (e.g. disk full):
/// the packet stays stored on the Station and the loop stops with an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The packet is durably resolved; ACK it.
    Done,
    /// Local transient failure; leave the packet stored and stop.
    Defer,
}

/// The caller-owned packet consumer: exactly one verdict per delivery.
pub trait PacketSink {
    /// Called once per delivered packet, in delivery order, with the
    /// Station's own delivery sequence.
    fn accept(&mut self, sequence: u64, handle: HandleToken, packet: &[u8]) -> Verdict;
}

/// Why the loop ended.
#[derive(Debug)]
pub enum LoopExit {
    /// A graceful stop was requested.
    Stopped,
    /// A terminal station or sink failure ended the lane.
    Failed(StationError),
}

/// How [`receive_loop`] paces reconnects after ordinary connection loss.
///
/// Reconnect timing is an operational parameter: callers supply the cadence
/// their environment needs, and [`Default`] preserves the values shipped in
/// 0.2.0 — 250 ms initial, doubling to a 60 s cap, with up to +50 % uniform
/// jitter on top.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    /// The delay before the first retry after a lost connection, and the
    /// delay the cadence resets to after a successful connect.
    pub initial: Duration,
    /// The factor the delay grows by after each lost attempt. `0` and `1`
    /// both keep it fixed at `initial`.
    pub multiplier: u32,
    /// The longest unjittered delay between attempts.
    pub cap: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            multiplier: 2,
            cap: Duration::from_millis(60_000),
        }
    }
}

/// Runs one mailbox receive loop until `stop` or a terminal error.
///
/// Ordinary connection loss retries forever with jittered exponential
/// backoff paced by `policy` — the only timers the contract allows are the
/// keepalive cadence and this backoff. Superseded, Revoked, DeviceMismatch,
/// and Refused are terminal: another client owns the mailbox or access
/// ended, and the loop must never fight for it.
pub async fn receive_loop<S: PacketSink>(
    credentials: &Credentials,
    extra_roots: &[PathBuf],
    sink: &mut S,
    mut stop: watch::Receiver<bool>,
    policy: ReconnectPolicy,
) -> LoopExit {
    let mut backoff = Backoff::new(policy);
    loop {
        if *stop.borrow() {
            return LoopExit::Stopped;
        }
        match MailboxClient::connect(credentials, extra_roots).await {
            Err(
                error @ (StationError::Superseded
                | StationError::Revoked
                | StationError::DeviceMismatch
                | StationError::Refused),
            ) => {
                return LoopExit::Failed(error);
            }
            Err(_) => {}
            Ok(mut client) => {
                backoff.reset();
                match drive(&mut client, sink, &mut stop).await {
                    DriveOutcome::Stopped => return LoopExit::Stopped,
                    DriveOutcome::Fatal(error) => return LoopExit::Failed(error),
                    DriveOutcome::Lost => {}
                }
            }
        }
        let wait = jittered(backoff.wait_ms());
        if let WaitOutcome::Stopped = paced_wait(wait, &mut stop).await {
            return LoopExit::Stopped;
        }
    }
}

enum DriveOutcome {
    Stopped,
    Lost,
    Fatal(StationError),
}

async fn drive<S: PacketSink>(
    client: &mut MailboxClient,
    sink: &mut S,
    stop: &mut watch::Receiver<bool>,
) -> DriveOutcome {
    loop {
        let event = tokio::select! {
            event = client.next() => event,
            _ = stop.changed() => return DriveOutcome::Stopped,
        };
        match event {
            Err(
                error @ (StationError::Superseded
                | StationError::Revoked
                | StationError::DeviceMismatch
                | StationError::Refused),
            ) => {
                return DriveOutcome::Fatal(error);
            }
            Err(_) => return DriveOutcome::Lost,
            Ok(Event::Drained) => {}
            Ok(Event::Deliver {
                sequence,
                handle,
                packet,
            }) => match sink.accept(sequence, handle, &packet) {
                Verdict::Done => {
                    if client.ack(sequence).await.is_err() {
                        return DriveOutcome::Lost;
                    }
                }
                Verdict::Defer => {
                    return DriveOutcome::Fatal(StationError::Transient {
                        failure: licoarc::transport::FailureClass::InternalUnavailable,
                        retry_after: None,
                    });
                }
            },
        }
    }
}

/// The longest single timer [`paced_wait`] asks the platform to hold.
///
/// The CLI accepts the full positive u64 millisecond range, so a selected
/// wait can exceed any timer's `Instant` range: Tokio substitutes a nearer
/// deadline when the addition overflows, which would silently shorten an
/// accepted delay. One day is schedulable everywhere, so the wait is slept
/// in chunks of at most this size — and the stop signal is answered at each
/// boundary instead of after the whole delay.
const MAX_SCHEDULABLE_WAIT: Duration = Duration::from_secs(86_400);

/// How one reconnect wait ended.
#[derive(Debug, Eq, PartialEq)]
enum WaitOutcome {
    /// The wait elapsed — or was cut short by a stop edge that already
    /// cleared, which the loop treats like an elapsed wait either way.
    Waited,
    /// A graceful stop was requested during the wait.
    Stopped,
}

/// Waits `wait` in chunks every platform timer can hold.
///
/// A single `tokio::time::sleep` would hand the whole duration to one timer
/// entry; splitting it keeps the full accepted range correct on platforms
/// whose `Instant` cannot express the deadline.
async fn paced_wait(mut remaining: Duration, stop: &mut watch::Receiver<bool>) -> WaitOutcome {
    while !remaining.is_zero() {
        let chunk = remaining.min(MAX_SCHEDULABLE_WAIT);
        tokio::select! {
            () = tokio::time::sleep(chunk) => remaining -= chunk,
            _ = stop.changed() => {
                if *stop.borrow() {
                    return WaitOutcome::Stopped;
                }
                return WaitOutcome::Waited;
            }
        }
    }
    WaitOutcome::Waited
}

/// The unjittered cadence [`receive_loop`] walks after each lost attempt:
/// `initial`, grown by `multiplier` per loss, never beyond `cap`, and back
/// to `initial` after a successful connect.
struct Backoff {
    initial_ms: u64,
    next_ms: u64,
    multiplier: u64,
    cap_ms: u64,
}

impl Backoff {
    fn new(policy: ReconnectPolicy) -> Self {
        let cap_ms = u64::try_from(policy.cap.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let initial_ms = u64::try_from(policy.initial.as_millis())
            .unwrap_or(u64::MAX)
            .min(cap_ms)
            .max(1);
        Self {
            initial_ms,
            next_ms: initial_ms,
            multiplier: u64::from(policy.multiplier.max(1)),
            cap_ms,
        }
    }

    /// The unjittered wait after this loss; the next loss waits longer.
    fn wait_ms(&mut self) -> u64 {
        let wait = self.next_ms;
        self.next_ms = self
            .next_ms
            .saturating_mul(self.multiplier)
            .min(self.cap_ms);
        wait
    }

    /// A successful connect restarts the cadence at `initial`.
    fn reset(&mut self) {
        self.next_ms = self.initial_ms;
    }
}

fn jittered(base_ms: u64) -> Duration {
    let mut extra = [0_u8; 8];
    getrandom::fill(&mut extra).unwrap_or_default();
    let jitter = u64::from_be_bytes(extra) % (base_ms / 2 + 1);
    // The CLI accepts the full positive u64 range, so the addition must not
    // overflow: base and jitter are added as Durations, which can always hold
    // their sum (two u64 millisecond counts stay far below Duration::MAX).
    Duration::from_millis(base_ms) + Duration::from_millis(jitter)
}

#[cfg(test)]
mod tests {
    use super::{
        Backoff, MAX_SCHEDULABLE_WAIT, ReconnectPolicy, WaitOutcome, jittered, paced_wait,
    };
    use std::time::Duration;
    use tokio::sync::watch;

    /// The loop must select exactly `initial`, then `initial * multiplier^k`
    /// clamped at `cap` — never beyond it. A cadence that let the cap slip
    /// (e.g. one that settled at 2×cap) would select different delays here
    /// even where coarse socket-gap windows could not tell it apart.
    #[test]
    fn the_progression_reaches_the_cap_and_holds_it() {
        let mut backoff = Backoff::new(ReconnectPolicy {
            initial: Duration::from_millis(100),
            multiplier: 4,
            cap: Duration::from_millis(200),
        });
        let waits = (0..6).map(|_| backoff.wait_ms()).collect::<Vec<_>>();
        assert_eq!(waits, [100, 200, 200, 200, 200, 200]);
    }

    /// A successful connect restarts the cadence at `initial`, not at the
    /// grown value the losses had reached.
    #[test]
    fn a_successful_connect_resets_the_progression() {
        let mut backoff = Backoff::new(ReconnectPolicy {
            initial: Duration::from_millis(40),
            multiplier: 4,
            cap: Duration::from_millis(500),
        });
        assert_eq!(backoff.wait_ms(), 40);
        assert_eq!(backoff.wait_ms(), 160);
        assert_eq!(backoff.wait_ms(), 500);
        backoff.reset();
        assert_eq!(backoff.wait_ms(), 40);
        assert_eq!(backoff.wait_ms(), 160);
    }

    /// Jitter can only stretch the selected wait by up to +50 %.
    #[test]
    fn jitter_stays_within_half_the_base() {
        for _ in 0..256 {
            let wait = jittered(200);
            assert!(wait >= Duration::from_millis(200));
            assert!(wait <= Duration::from_millis(300));
        }
    }

    /// The CLI accepts the full positive u64 millisecond range. At the
    /// accepted upper bound the jittered wait is still selected correctly:
    /// it stays in `[base, base + base/2]` and never panics or wraps short.
    #[test]
    fn jitter_at_the_largest_accepted_base_never_overflows() {
        let base = Duration::from_millis(u64::MAX);
        for _ in 0..64 {
            let wait = jittered(u64::MAX);
            assert!(wait >= base);
            assert!(wait <= base + Duration::from_millis(u64::MAX / 2));
        }
    }

    /// A wait inside any platform timer's range still elapses on its own.
    #[tokio::test(start_paused = true)]
    async fn a_schedulable_wait_elapses() {
        let (_sender, mut stop) = watch::channel(false);
        let wait =
            tokio::spawn(async move { paced_wait(Duration::from_millis(50), &mut stop).await });
        tokio::time::advance(Duration::from_millis(60)).await;
        assert_eq!(
            wait.await.expect("the wait task completes"),
            WaitOutcome::Waited
        );
    }

    /// The largest wait the accepted range can select is past every platform
    /// timer's `Instant` range — where a single `sleep` would be silently
    /// shortened to a nearer deadline. Chunked scheduling proves the whole
    /// wait is held: several full chunks leave it pending, and `stop` still
    /// ends it.
    #[tokio::test(start_paused = true)]
    async fn a_wait_past_the_timers_range_stays_pending_and_stops() {
        let (sender, mut stop) = watch::channel(false);
        let wait = Duration::from_millis(u64::MAX) + Duration::from_millis(u64::MAX / 2);
        let waiter = tokio::spawn(async move { paced_wait(wait, &mut stop).await });
        tokio::task::yield_now().await;

        for _ in 0..4 {
            tokio::time::advance(MAX_SCHEDULABLE_WAIT).await;
            tokio::task::yield_now().await;
        }
        assert!(
            !waiter.is_finished(),
            "a u64::MAX-scale wait must not be shortened to a nearer deadline"
        );

        sender.send(true).expect("the stop channel is open");
        assert_eq!(
            waiter.await.expect("the wait task completes"),
            WaitOutcome::Stopped
        );
    }
}
