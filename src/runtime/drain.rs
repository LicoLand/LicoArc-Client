//! One outbox pass: deliver every durable pending item exactly once.
//!
//! The SDK owns the semantics (`drive_pending`, `release_plaintext` in
//! `src/state/mod.rs`): a packet or application effect settles only after the
//! caller-owned boundary reports success, and a plaintext settles only after
//! the caller-owned receiver releases it. This pass adds no retry of its own —
//! every item is attempted once, in the store's own order, and the items the
//! boundary did not accept stay durably pending for the next pass. A
//! transport that was uncertain whether the packet landed is exactly the case
//! that must re-drive the same committed item, which is what the next pass
//! does.

use licoarc::endpoint::{Endpoint, EndpointState, Role};
use licoarc::error::Error;
use licoarc::provider::Provider;
use licoarc::state::{
    ApplicationEffects, AtomicState, KeyCustody, PacketCarrier, PendingId, PendingItem,
    PendingKind, PlaintextReceiver,
};

/// The narrow pending-work surface the drain needs.
///
/// [`Endpoint`] supplies it for every role and port set; anything else — a
/// lane that drives several endpoints' stores, a test double — can supply the
/// same contract without impersonating an endpoint.
pub trait PendingWork {
    /// The store's current durable items, in its own order.
    fn pending(&self) -> Result<Vec<PendingItem>, Error>;
    /// One committed carrier or effect attempt; settles the item only after
    /// the boundary reports success.
    fn dispatch<T: PacketCarrier, E: ApplicationEffects>(
        &mut self,
        id: PendingId,
        carrier: &mut T,
        effects: &mut E,
    ) -> Result<(), Error>;
    /// Releases one committed plaintext; settles the item only after the
    /// caller-owned receiver succeeds.
    fn release<L: PlaintextReceiver>(
        &mut self,
        id: PendingId,
        receiver: &mut L,
    ) -> Result<(), Error>;
}

impl<R, P, C, S> PendingWork for Endpoint<R, P, C, S>
where
    R: Role,
    P: Provider,
    C: KeyCustody,
    S: AtomicState<EndpointState>,
{
    fn pending(&self) -> Result<Vec<PendingItem>, Error> {
        self.pending_items()
    }

    fn dispatch<T: PacketCarrier, E: ApplicationEffects>(
        &mut self,
        id: PendingId,
        carrier: &mut T,
        effects: &mut E,
    ) -> Result<(), Error> {
        self.dispatch_pending(id, carrier, effects)
    }

    fn release<L: PlaintextReceiver>(
        &mut self,
        id: PendingId,
        receiver: &mut L,
    ) -> Result<(), Error> {
        self.release_pending_plaintext(id, receiver)
    }
}

/// What one drain pass did, in the store's own item order.
#[derive(Debug, Default)]
pub struct DrainReport {
    /// Pending ids the carrier or effect boundary settled.
    pub settled: Vec<PendingId>,
    /// Pending ids the plaintext receiver released.
    pub released: Vec<PendingId>,
    /// Pending ids the boundary refused this pass, with the exact error.
    pub failed: Vec<(PendingId, Error)>,
}

impl DrainReport {
    /// Total items that completed this pass.
    #[must_use]
    pub fn completed(&self) -> usize {
        self.settled.len() + self.released.len()
    }
}

/// Attempts every durable pending item once.
///
/// Packet and effect items go through `dispatch`; plaintext items go through
/// `release`. One item's failure never cancels the others — it is recorded and
/// the pass continues. The only error that ends the pass itself is the store
/// refusing to enumerate its own pending work.
///
/// The pass is synchronous because the SDK's pending boundary is synchronous;
/// a blocking [`crate::carrier::SubmitCarrier`] supplies the transport side.
///
/// # Errors
///
/// Returns the store's enumeration error verbatim. Per-item boundary errors
/// are reported in [`DrainReport::failed`] instead.
pub fn drain_pending<T, E, L>(
    work: &mut impl PendingWork,
    carrier: &mut T,
    effects: &mut E,
    plaintext: &mut L,
) -> Result<DrainReport, Error>
where
    T: PacketCarrier,
    E: ApplicationEffects,
    L: PlaintextReceiver,
{
    let items = work.pending()?;
    let mut report = DrainReport::default();
    for item in items {
        let id = item.id();
        let result = match item.kind() {
            PendingKind::Plaintext(_) => work.release(id, plaintext),
            PendingKind::Packet(_) | PendingKind::Effect(_) => work.dispatch(id, carrier, effects),
        };
        match result {
            Ok(()) => {
                if matches!(item.kind(), PendingKind::Plaintext(_)) {
                    report.released.push(id);
                } else {
                    report.settled.push(id);
                }
            }
            Err(error) => report.failed.push((id, error)),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use licoarc::error::{ErrorCode, Stage};
    use licoarc::state::PendingItem;

    use super::{DrainReport, PendingWork, drain_pending};
    use licoarc::error::Error;
    use licoarc::state::{
        ApplicationEffects, PacketCarrier, PendingId, PendingItem as Item, PlaintextReceiver,
    };

    struct Scripted {
        items: Vec<Item>,
        dispatched: Vec<PendingId>,
        released: Vec<PendingId>,
        refuse: Vec<PendingId>,
    }

    impl PendingWork for Scripted {
        fn pending(&self) -> Result<Vec<Item>, Error> {
            Ok(self.items.clone())
        }

        fn dispatch<T: PacketCarrier, E: ApplicationEffects>(
            &mut self,
            id: PendingId,
            _carrier: &mut T,
            _effects: &mut E,
        ) -> Result<(), Error> {
            self.dispatched.push(id);
            if self.refuse.contains(&id) {
                return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
            }
            Ok(())
        }

        fn release<L: PlaintextReceiver>(
            &mut self,
            id: PendingId,
            _receiver: &mut L,
        ) -> Result<(), Error> {
            self.released.push(id);
            if self.refuse.contains(&id) {
                return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
            }
            Ok(())
        }
    }

    struct Sink;

    impl PacketCarrier for Sink {
        fn send(&mut self, _packet: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }

    impl ApplicationEffects for Sink {
        fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }

    impl PlaintextReceiver for Sink {
        fn release(&mut self, _plaintext: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }

    fn item(token: u128, kind: fn(PendingId, Vec<u8>) -> Result<Item, Error>) -> Item {
        kind(PendingId::from_token(token), vec![token as u8]).unwrap()
    }

    #[test]
    fn packet_and_effect_dispatch_plaintext_releases() {
        let packet = item(1, Item::packet);
        let effect = item(2, Item::effect);
        let text = item(3, Item::plaintext);
        let mut work = Scripted {
            items: vec![packet.clone(), effect.clone(), text.clone()],
            dispatched: vec![],
            released: vec![],
            refuse: vec![],
        };
        let mut carrier = Sink;
        let mut effects = Sink;
        let mut texts = Sink;
        let report = drain_pending(&mut work, &mut carrier, &mut effects, &mut texts).unwrap();
        assert_eq!(work.dispatched, vec![packet.id(), effect.id()]);
        assert_eq!(work.released, vec![text.id()]);
        assert_eq!(report.completed(), 3);
        assert!(report.failed.is_empty());
    }

    #[test]
    fn one_refusal_never_cancels_the_rest() {
        let first = item(1, Item::packet);
        let refused = item(2, Item::packet);
        let third = item(3, Item::plaintext);
        let mut work = Scripted {
            items: vec![first.clone(), refused.clone(), third.clone()],
            dispatched: vec![],
            released: vec![],
            refuse: vec![refused.id()],
        };
        let mut carrier = Sink;
        let mut effects = Sink;
        let mut texts = Sink;
        let report = drain_pending(&mut work, &mut carrier, &mut effects, &mut texts).unwrap();
        assert_eq!(report.settled, vec![first.id()]);
        assert_eq!(report.released, vec![third.id()]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, refused.id());
    }

    #[test]
    fn enumeration_failure_ends_the_pass() {
        struct Empty;
        impl PendingWork for Empty {
            fn pending(&self) -> Result<Vec<PendingItem>, Error> {
                Err(Error::terminal(ErrorCode::Conflict, Stage::Commit))
            }
            fn dispatch<T: PacketCarrier, E: ApplicationEffects>(
                &mut self,
                _id: PendingId,
                _c: &mut T,
                _e: &mut E,
            ) -> Result<(), Error> {
                Ok(())
            }
            fn release<L: PlaintextReceiver>(
                &mut self,
                _id: PendingId,
                _r: &mut L,
            ) -> Result<(), Error> {
                Ok(())
            }
        }
        let mut work = Empty;
        let mut carrier = Sink;
        let mut effects = Sink;
        let mut texts = Sink;
        let err = drain_pending(&mut work, &mut carrier, &mut effects, &mut texts).unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        let report = DrainReport::default();
        assert_eq!(report.completed(), 0);
    }
}
