//! The coupled in-memory [`AtomicState`] for the standalone CLI.
//!
//! `MemoryState` holds the live `Versioned` snapshot and applies every commit
//! old-or-new: the revision is checked, the custody mutations are applied and
//! persisted through the coupled [`FileCustody`], and only then does the
//! snapshot advance exactly once. A refused mutation or a stale expected
//! revision changes nothing.
//!
//! Crash durability is not this type's job: an `EndpointState` has exactly one
//! durable codec, the SDK's sealed `Endpoint::checkpoint`/`Endpoint::resume`
//! pair, and the caller persists those bytes after each successful operation.
//! The store itself is the live value the protocol mutates; the checkpoint
//! file is its last published image.

use std::cell::RefCell;
use std::rc::Rc;

use crate::ports::{AtomicState, PortFailure, Revision, StateCommit, Versioned};

use super::fs::FileCustody;

/// One `Versioned` snapshot plus the custody it is coupled to.
///
/// `S` is the protocol snapshot (`EndpointState` for a real endpoint); `I` is
/// the committed pending item the protocol layer owns.
pub struct MemoryState<S, I, P> {
    current: Rc<RefCell<Versioned<S, I>>>,
    custody: FileCustody<P>,
}

impl<S, I, P> MemoryState<S, I, P>
where
    S: Clone,
    I: Clone + PartialEq,
{
    /// A store at revision zero holding `state` and no committed work.
    #[must_use]
    pub fn initial(state: S, custody: FileCustody<P>) -> Self {
        Self {
            current: Rc::new(RefCell::new(Versioned::initial(state))),
            custody,
        }
    }

    /// A store presenting one already-committed snapshot — for example, a
    /// checkpoint `EndpointRestore::into_versioned` produced on resume.
    #[must_use]
    pub fn restored(current: Versioned<S, I>, custody: FileCustody<P>) -> Self {
        Self {
            current: Rc::new(RefCell::new(current)),
            custody,
        }
    }

    /// The coupled custody backend, for the adapter's own custody view.
    #[must_use]
    pub const fn custody(&self) -> &FileCustody<P> {
        &self.custody
    }
}

impl<S, I, P> Clone for MemoryState<S, I, P> {
    fn clone(&self) -> Self {
        Self {
            current: Rc::clone(&self.current),
            custody: self.custody.clone(),
        }
    }
}

impl<S, I, P> AtomicState for MemoryState<S, I, P>
where
    S: Clone,
    I: Clone + PartialEq,
{
    type Snapshot = S;
    type Pending = I;

    fn load(&self) -> Result<Versioned<S, I>, PortFailure> {
        Ok(self.current.borrow().clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: StateCommit<S, I>,
    ) -> Result<Revision, PortFailure> {
        if expected != self.current.borrow().revision() {
            return Err(PortFailure::Conflict);
        }
        // Refuse the overflow before touching custody: a revision that cannot
        // publish must not leave adopted secrets behind.
        expected.successor()?;
        self.custody.apply_mutations(commit.key_mutations())?;
        let next = commit.into_versioned(expected)?;
        let revision = next.revision();
        *self.current.borrow_mut() = next;
        Ok(revision)
    }

    fn settle(&mut self, revision: Revision, pending: &I) -> Result<Revision, PortFailure> {
        let mut current = self.current.borrow_mut();
        if revision != current.revision() {
            return Err(PortFailure::Conflict);
        }
        let mut remaining = current.pending().to_vec();
        let Some(index) = remaining.iter().position(|item| item == pending) else {
            return Err(PortFailure::Unavailable);
        };
        remaining.remove(index);
        let commit = StateCommit::new(current.state().clone(), Vec::new(), remaining);
        *current = commit.into_versioned(revision)?;
        Ok(current.revision())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use licoarc::provider::fixed_provider;

    use super::MemoryState;
    use crate::ports::{
        AtomicState, CustodyPurpose, PendingId, PendingItem, PortFailure, Revision, StateCommit,
    };
    use crate::providers::FileCustody;

    struct Dir(PathBuf);

    impl Dir {
        fn fresh() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "licoarc-client-mem-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store() -> (
        Dir,
        MemoryState<u64, PendingItem, impl licoarc::provider::Provider>,
    ) {
        let dir = Dir::fresh();
        let custody = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        (dir, MemoryState::initial(7_u64, custody))
    }

    #[test]
    fn compare_and_swap_advances_once_or_not_at_all() {
        let (_dir, mut store) = store();
        let item = PendingItem::packet(PendingId::from_token(1), vec![9]);
        let commit = StateCommit::new(8_u64, Vec::new(), vec![item.clone()]);
        assert_eq!(
            store
                .compare_and_swap(Revision::initial(), commit)
                .unwrap()
                .value(),
            1
        );
        // A stale expected revision refuses and changes nothing.
        let stale = StateCommit::new(9_u64, Vec::new(), Vec::new());
        assert_eq!(
            store.compare_and_swap(Revision::initial(), stale),
            Err(PortFailure::Conflict)
        );
        assert_eq!(store.load().unwrap().revision().value(), 1);
        assert_eq!(store.load().unwrap().pending(), &[item]);
    }

    #[test]
    fn settle_removes_only_the_named_item() {
        let (_dir, mut store) = store();
        let keep = PendingItem::packet(PendingId::from_token(1), vec![1]);
        let gone = PendingItem::effect(PendingId::from_token(2), vec![2]);
        let commit = StateCommit::new(1_u64, Vec::new(), vec![keep.clone(), gone.clone()]);
        store.compare_and_swap(Revision::initial(), commit).unwrap();
        let revision = Revision::from_value(1);
        // A foreign item is not settled by name.
        let foreign = PendingItem::packet(PendingId::from_token(99), vec![0]);
        assert_eq!(
            store.settle(revision, &foreign),
            Err(PortFailure::Unavailable)
        );
        let next = store.settle(revision, &gone).unwrap();
        assert_eq!(next.value(), 2);
        assert_eq!(store.load().unwrap().pending(), &[keep]);
    }

    #[test]
    fn a_commit_applies_its_custody_mutations() {
        let (dir, mut store) = store();
        // Staging goes through a clone of the store's own coupled custody, so
        // the same table — never a second view of the file — sees the object.
        let mut custody = store.custody().clone();
        let staged = custody.stage(CustodyPurpose::X25519Private).unwrap();
        let commit = StateCommit::new(
            2_u64,
            vec![crate::ports::KeyMutation::Adopt(staged)],
            Vec::new(),
        );
        store.compare_and_swap(Revision::initial(), commit).unwrap();
        // The adoption persisted with the snapshot: reopening the same index
        // sees the object as Adopted, so a second adoption is refused.
        let mut reopened = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        assert!(
            reopened
                .apply_mutations(&[crate::ports::KeyMutation::Adopt(staged)])
                .is_err()
        );
        assert_eq!(store.load().unwrap().revision().value(), 1);
    }
}
