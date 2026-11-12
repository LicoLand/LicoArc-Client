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
    let cap_ms = u64::try_from(policy.cap.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let multiplier = u64::from(policy.multiplier.max(1));
    let initial_ms = u64::try_from(policy.initial.as_millis())
        .unwrap_or(u64::MAX)
        .min(cap_ms)
        .max(1);
    let mut backoff_ms = initial_ms;
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
                backoff_ms = initial_ms;
                match drive(&mut client, sink, &mut stop).await {
                    DriveOutcome::Stopped => return LoopExit::Stopped,
                    DriveOutcome::Fatal(error) => return LoopExit::Failed(error),
                    DriveOutcome::Lost => {}
                }
            }
        }
        let wait = jittered(backoff_ms);
        backoff_ms = backoff_ms.saturating_mul(multiplier).min(cap_ms);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.changed() => {
                if *stop.borrow() {
                    return LoopExit::Stopped;
                }
            }
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

fn jittered(base_ms: u64) -> Duration {
    let mut extra = [0_u8; 8];
    getrandom::fill(&mut extra).unwrap_or_default();
    let jitter = u64::from_be_bytes(extra) % (base_ms / 2 + 1);
    Duration::from_millis(base_ms + jitter)
}
