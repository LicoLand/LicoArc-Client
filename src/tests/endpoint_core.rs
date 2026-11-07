use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::ports::{
    AtomicState, CustodyHandle, CustodyLifecycle, CustodyPurpose, KeyCustody, KeyMutation,
    PendingId, PendingItem, PortFailure, Revision, StateCommit, Transport,
};
use crate::recovery::{RecoveryEvent, SessionRecovery};
use crate::{
    ClientSession, ClientSessionState, ConfirmationRequirement, OperationPolicy, TransportOutcome,
};

#[test]
fn device_unlocked_session_is_the_ordinary_default() {
    let session = ClientSession::device_unlocked();
    assert_eq!(session.state(), ClientSessionState::DeviceUnlocked);
    assert!(session.allows_ordinary_interaction());
}

#[test]
fn ordinary_direct_policy_requires_no_review() {
    let policy = OperationPolicy::ordinary_direct();
    assert_eq!(policy.confirmation, ConfirmationRequirement::None);
    assert!(!policy.requires_fresh_user_presence());
}

/// One custody object: which purpose it serves and whether it is tentative.
#[derive(Clone, Copy)]
struct Object {
    purpose: CustodyPurpose,
    lifecycle: CustodyLifecycle,
}

/// The coupled custody/state backend a real adapter provides. It is one
/// table on purpose: a handle and the state that references it are adopted
/// in the same transaction.
#[derive(Clone, Default)]
struct Coupled {
    objects: BTreeMap<u128, Object>,
}

impl Coupled {
    fn insert(&mut self, token: u128, purpose: CustodyPurpose, lifecycle: CustodyLifecycle) {
        self.objects.insert(token, Object { purpose, lifecycle });
    }

    fn require(
        &self,
        handle: CustodyHandle,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<u128, PortFailure> {
        let object = self
            .objects
            .get(&handle.custody_token())
            .filter(|object| object.purpose == purpose && object.lifecycle == lifecycle)
            .filter(|_| handle.purpose() == purpose && handle.lifecycle() == lifecycle);
        object
            .map(|_| handle.custody_token())
            .ok_or(PortFailure::Unavailable)
    }

    fn abort(&mut self, handle: CustodyHandle, purpose: CustodyPurpose) {
        if let Ok(token) = self.require(handle, purpose, CustodyLifecycle::Staged) {
            self.objects.remove(&token);
        }
    }

    fn apply(&mut self, mutation: KeyMutation) -> Result<(), PortFailure> {
        match mutation {
            KeyMutation::Adopt(handle) => {
                let adoptable = matches!(
                    handle.purpose(),
                    CustodyPurpose::X25519Private | CustodyPurpose::MlKem768Private
                );
                if !adoptable {
                    return Err(PortFailure::Unavailable);
                }
                let token = self.require(handle, handle.purpose(), CustodyLifecycle::Staged)?;
                self.objects.insert(
                    token,
                    Object {
                        purpose: handle.purpose(),
                        lifecycle: CustodyLifecycle::Adopted,
                    },
                );
                Ok(())
            }
            KeyMutation::Delete(handle) => {
                let deletable = matches!(
                    handle.purpose(),
                    CustodyPurpose::X25519Private
                        | CustodyPurpose::MlKem768Private
                        | CustodyPurpose::MlKemEncapsulationEntropy
                );
                if !deletable {
                    return Err(PortFailure::Unavailable);
                }
                let token = self.require(handle, handle.purpose(), CustodyLifecycle::Adopted)?;
                self.objects.remove(&token);
                Ok(())
            }
        }
    }
}

#[derive(Clone)]
struct CoupledCustody {
    table: Rc<RefCell<Coupled>>,
}

impl KeyCustody for CoupledCustody {
    fn ed25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        let token = self.table.borrow().require(
            handle,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        )?;
        Ok(token_public(token))
    }

    fn ed25519_sign(&self, handle: CustodyHandle, message: &[u8]) -> Result<[u8; 64], PortFailure> {
        let token = self.table.borrow().require(
            handle,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        )?;
        let mut signature = [0_u8; 64];
        signature[0] = token as u8;
        signature[1] = message.len() as u8;
        Ok(signature)
    }

    fn ml_dsa_65_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        self.table
            .borrow()
            .require(
                handle,
                CustodyPurpose::MlDsa65Signing,
                CustodyLifecycle::Adopted,
            )
            .map(|token| token_public(token).to_vec())
    }

    fn ml_dsa_65_sign(
        &self,
        handle: CustodyHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, PortFailure> {
        let token = self.table.borrow().require(
            handle,
            CustodyPurpose::MlDsa65Signing,
            CustodyLifecycle::Adopted,
        )?;
        Ok(vec![token as u8, message.len() as u8])
    }

    fn x25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        self.x25519(handle, &[0; 32])
    }

    fn x25519(&self, handle: CustodyHandle, public: &[u8; 32]) -> Result<[u8; 32], PortFailure> {
        let token = self.table.borrow().require(
            handle,
            CustodyPurpose::X25519Private,
            handle.lifecycle(),
        )?;
        let mut shared = *public;
        shared[31] ^= token as u8;
        Ok(shared)
    }

    fn ml_kem_768_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        self.table
            .borrow()
            .require(handle, CustodyPurpose::MlKem768Private, handle.lifecycle())
            .map(|token| token_public(token).to_vec())
    }

    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: CustodyHandle,
    ) -> Result<(Vec<u8>, [u8; 32]), PortFailure> {
        let token = self.table.borrow().require(
            entropy,
            CustodyPurpose::MlKemEncapsulationEntropy,
            CustodyLifecycle::Adopted,
        )?;
        Ok((public.to_vec(), token_public(token)))
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: CustodyHandle,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], PortFailure> {
        let token = self.table.borrow().require(
            handle,
            CustodyPurpose::MlKem768Private,
            handle.lifecycle(),
        )?;
        let mut shared = [0_u8; 32];
        shared[0] = token as u8;
        shared[1] = ciphertext.len() as u8;
        Ok(shared)
    }

    fn abort_x25519(&mut self, staged: CustodyHandle) {
        self.table
            .borrow_mut()
            .abort(staged, CustodyPurpose::X25519Private);
    }

    fn abort_ml_kem_768(&mut self, staged: CustodyHandle) {
        self.table
            .borrow_mut()
            .abort(staged, CustodyPurpose::MlKem768Private);
    }
}

fn token_public(token: u128) -> [u8; 32] {
    let mut public = [0_u8; 32];
    public[0] = token as u8;
    public
}

/// The durable half of the same backend: one snapshot, one coupled table.
struct CoupledStore {
    current: crate::Versioned<u64, PendingItem>,
    table: Rc<RefCell<Coupled>>,
}

impl AtomicState for CoupledStore {
    type Snapshot = u64;
    type Pending = PendingItem;

    fn load(&self) -> Result<crate::Versioned<u64, PendingItem>, PortFailure> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: StateCommit<u64, PendingItem>,
    ) -> Result<Revision, PortFailure> {
        if expected != self.current.revision() {
            return Err(PortFailure::Conflict);
        }
        // Validate the entire tentative transaction before publishing either
        // half. A later mutation or revision failure must change nothing.
        let mut table = self.table.borrow_mut();
        let mut next_table = table.clone();
        for mutation in commit.key_mutations() {
            next_table.apply(*mutation)?;
        }
        let next = commit.into_versioned(expected)?;
        *table = next_table;
        self.current = next;
        Ok(self.current.revision())
    }

    fn settle(
        &mut self,
        revision: Revision,
        pending: &PendingItem,
    ) -> Result<Revision, PortFailure> {
        if revision != self.current.revision() {
            return Err(PortFailure::Conflict);
        }
        let mut remaining = self.current.pending().to_vec();
        let Some(index) = remaining.iter().position(|item| item.id() == pending.id()) else {
            return Err(PortFailure::Unavailable);
        };
        remaining.remove(index);
        let commit = StateCommit::new(*self.current.state(), Vec::new(), remaining);
        self.current = commit.into_versioned(revision)?;
        Ok(self.current.revision())
    }
}

fn coupled() -> (CoupledCustody, CoupledStore, Rc<RefCell<Coupled>>) {
    let table = Rc::new(RefCell::new(Coupled::default()));
    (
        CoupledCustody {
            table: Rc::clone(&table),
        },
        CoupledStore {
            current: crate::Versioned::initial(0),
            table: Rc::clone(&table),
        },
        table,
    )
}

#[test]
fn custody_refuses_absent_cross_purpose_and_unstaged_handles() {
    let (mut custody, _, table) = coupled();
    table.borrow_mut().insert(
        11,
        CustodyPurpose::Ed25519Signing,
        CustodyLifecycle::Adopted,
    );
    table
        .borrow_mut()
        .insert(21, CustodyPurpose::X25519Private, CustodyLifecycle::Staged);

    assert_eq!(
        custody.ed25519_public(CustodyHandle::adopted(404, CustodyPurpose::Ed25519Signing)),
        Err(PortFailure::Unavailable)
    );
    assert_eq!(
        custody.ed25519_public(CustodyHandle::adopted(21, CustodyPurpose::Ed25519Signing)),
        Err(PortFailure::Unavailable),
        "a token may not be re-labelled with another purpose"
    );
    assert_eq!(
        custody.x25519_public(CustodyHandle::adopted(21, CustodyPurpose::X25519Private)),
        Err(PortFailure::Unavailable),
        "a staged object cannot serve an adopted operation"
    );
    assert!(
        custody
            .x25519_public(CustodyHandle::staged(21, CustodyPurpose::X25519Private))
            .is_ok()
    );

    custody.abort_x25519(CustodyHandle::staged(21, CustodyPurpose::X25519Private));
    assert!(
        !table.borrow().objects.contains_key(&21),
        "an aborted tentative object is unreachable"
    );
}

#[test]
fn a_commit_is_old_or_new_and_carries_its_custody_mutations() {
    let (_custody, mut store, table) = coupled();
    table
        .borrow_mut()
        .insert(31, CustodyPurpose::X25519Private, CustodyLifecycle::Staged);
    table.borrow_mut().insert(
        32,
        CustodyPurpose::MlKemEncapsulationEntropy,
        CustodyLifecycle::Adopted,
    );

    let mut commit = StateCommit::new(
        7,
        vec![
            KeyMutation::Adopt(CustodyHandle::staged(31, CustodyPurpose::X25519Private)),
            KeyMutation::Delete(CustodyHandle::adopted(
                32,
                CustodyPurpose::MlKemEncapsulationEntropy,
            )),
        ],
        vec![PendingItem::packet(PendingId::from_token(1), vec![1, 2, 3])],
    );
    assert_eq!(
        store.compare_and_swap(Revision::initial().successor().unwrap(), commit.clone()),
        Err(PortFailure::Conflict)
    );
    assert_eq!(store.load().unwrap().revision(), Revision::initial());
    assert!(
        table.borrow().objects.contains_key(&31),
        "a refused commit applies no mutation"
    );

    assert_eq!(
        store.compare_and_swap(Revision::initial(), commit.clone()),
        Ok(Revision::initial().successor().unwrap())
    );
    {
        let applied = table.borrow();
        assert_eq!(
            applied.objects.get(&31).map(|object| object.lifecycle),
            Some(CustodyLifecycle::Adopted)
        );
        assert!(!applied.objects.contains_key(&32));
    }
    let loaded = store.load().unwrap();
    assert_eq!(loaded.state(), &7);
    assert_eq!(loaded.revision().value(), 1);
    assert_eq!(loaded.pending().len(), 1);

    commit = StateCommit::new(
        8,
        vec![KeyMutation::Adopt(CustodyHandle::staged(
            31,
            CustodyPurpose::X25519Private,
        ))],
        Vec::new(),
    );
    assert_eq!(
        store.compare_and_swap(Revision::initial().successor().unwrap(), commit),
        Err(PortFailure::Unavailable),
        "an adopted object cannot be adopted again"
    );
    assert_eq!(store.load().unwrap().revision().value(), 1);

    let committed = PendingItem::packet(PendingId::from_token(1), vec![1, 2, 3]);
    assert_eq!(
        store.settle(Revision::initial().successor().unwrap(), &committed),
        Ok(Revision::initial()
            .successor()
            .unwrap()
            .successor()
            .unwrap())
    );
    assert!(store.load().unwrap().pending().is_empty());
    assert_eq!(
        store.settle(Revision::initial().successor().unwrap(), &committed),
        Err(PortFailure::Conflict)
    );
}

#[test]
fn a_late_custody_failure_leaves_the_complete_commit_unapplied() {
    let (_custody, mut store, table) = coupled();
    table
        .borrow_mut()
        .insert(31, CustodyPurpose::X25519Private, CustodyLifecycle::Staged);
    table.borrow_mut().insert(
        32,
        CustodyPurpose::MlKemEncapsulationEntropy,
        CustodyLifecycle::Adopted,
    );
    let before = store.load().unwrap();
    let commit = StateCommit::new(
        7,
        vec![
            KeyMutation::Adopt(CustodyHandle::staged(31, CustodyPurpose::X25519Private)),
            KeyMutation::Delete(CustodyHandle::adopted(
                32,
                CustodyPurpose::MlKemEncapsulationEntropy,
            )),
            KeyMutation::Delete(CustodyHandle::adopted(404, CustodyPurpose::X25519Private)),
        ],
        vec![PendingItem::packet(PendingId::from_token(1), vec![1, 2, 3])],
    );

    assert_eq!(
        store.compare_and_swap(before.revision(), commit),
        Err(PortFailure::Unavailable)
    );
    assert_eq!(store.load().unwrap(), before);
    let unchanged = table.borrow();
    assert_eq!(
        unchanged.objects.get(&31).map(|object| object.lifecycle),
        Some(CustodyLifecycle::Staged),
        "a later refusal must roll back the earlier adoption"
    );
    assert_eq!(
        unchanged.objects.get(&32).map(|object| object.lifecycle),
        Some(CustodyLifecycle::Adopted),
        "a later refusal must roll back the earlier deletion"
    );
}

#[test]
fn abort_checks_the_stored_purpose_and_lifecycle() {
    let (mut custody, _store, table) = coupled();
    for (token, purpose, lifecycle) in [
        (1, CustodyPurpose::X25519Private, CustodyLifecycle::Adopted),
        (2, CustodyPurpose::MlKem768Private, CustodyLifecycle::Staged),
        (3, CustodyPurpose::X25519Private, CustodyLifecycle::Staged),
        (
            4,
            CustodyPurpose::MlKem768Private,
            CustodyLifecycle::Adopted,
        ),
    ] {
        table.borrow_mut().insert(token, purpose, lifecycle);
    }

    custody.abort_x25519(CustodyHandle::staged(1, CustodyPurpose::X25519Private));
    custody.abort_x25519(CustodyHandle::staged(2, CustodyPurpose::X25519Private));
    custody.abort_x25519(CustodyHandle::staged(3, CustodyPurpose::MlKem768Private));
    custody.abort_ml_kem_768(CustodyHandle::staged(4, CustodyPurpose::MlKem768Private));
    custody.abort_ml_kem_768(CustodyHandle::staged(3, CustodyPurpose::MlKem768Private));
    custody.abort_ml_kem_768(CustodyHandle::staged(2, CustodyPurpose::X25519Private));
    custody.abort_x25519(CustodyHandle::staged(404, CustodyPurpose::X25519Private));

    assert_eq!(table.borrow().objects.len(), 4);
    custody.abort_x25519(CustodyHandle::staged(3, CustodyPurpose::X25519Private));
    custody.abort_ml_kem_768(CustodyHandle::staged(2, CustodyPurpose::MlKem768Private));
    let remaining = table.borrow();
    assert_eq!(
        remaining.objects.keys().copied().collect::<Vec<_>>(),
        vec![1, 4]
    );
}

#[test]
fn a_recovery_event_keeps_or_replaces_an_established_result() {
    assert_eq!(
        RecoveryEvent::TransportDisconnected { pending_work: true }.recovery(),
        SessionRecovery::RedrivePending
    );
    assert_eq!(
        RecoveryEvent::TransportDisconnected {
            pending_work: false
        }
        .recovery(),
        SessionRecovery::Continue
    );
    assert_eq!(
        RecoveryEvent::TransportAttempt(TransportOutcome::Accepted).recovery(),
        SessionRecovery::Continue
    );
    assert_eq!(
        RecoveryEvent::TransportAttempt(TransportOutcome::Rejected).recovery(),
        SessionRecovery::RefuseCallOnly
    );
    for outcome in [TransportOutcome::Transient, TransportOutcome::Ambiguous] {
        assert_eq!(
            RecoveryEvent::TransportAttempt(outcome).recovery(),
            SessionRecovery::RedrivePending,
            "{outcome:?} keeps the established result and re-drives the same item"
        );
    }
    assert_eq!(
        RecoveryEvent::RosterRevocation {
            established_result_authenticated: true
        }
        .recovery(),
        SessionRecovery::Continue
    );
    assert_eq!(
        RecoveryEvent::RosterRevocation {
            established_result_authenticated: false
        }
        .recovery(),
        SessionRecovery::NewAdmission
    );
    assert_eq!(
        RecoveryEvent::SessionDeleted.recovery(),
        SessionRecovery::NewAdmission
    );

    let current = Revision::initial().successor().unwrap();
    let restart =
        |persisted, current| RecoveryEvent::GenerationRestart { persisted, current }.recovery();
    assert_eq!(restart(current, current), SessionRecovery::Continue);
    assert_eq!(
        restart(Revision::initial(), current),
        SessionRecovery::NewAdmission
    );
    assert_eq!(
        restart(current.successor().unwrap(), current),
        SessionRecovery::RefuseCallOnly
    );
    for recovery in [
        SessionRecovery::Continue,
        SessionRecovery::RedrivePending,
        SessionRecovery::RefuseCallOnly,
    ] {
        assert!(recovery.keeps_established_result());
        assert!(!recovery.requires_new_admission());
    }
    assert!(!SessionRecovery::NewAdmission.keeps_established_result());
    assert!(SessionRecovery::NewAdmission.requires_new_admission());
}

#[test]
fn a_missing_transport_branch_only_refuses_calls() {
    struct Unavailable;
    impl Transport for Unavailable {
        fn submit(&mut self, _packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
            Err(PortFailure::Unavailable)
        }
    }
    let mut transport = Unavailable;
    assert_eq!(
        transport.submit(b"packet"),
        Err(PortFailure::Unavailable),
        "a blocked communication branch never becomes a lost established result"
    );
    assert_eq!(
        RecoveryEvent::TransportDisconnected { pending_work: true }.recovery(),
        SessionRecovery::RedrivePending
    );
}
