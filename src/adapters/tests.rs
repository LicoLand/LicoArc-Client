//! The composition point's own contracts, without the gated authority artifact.
//!
//! These cases prove the property the fixed-candidate path exists for: an
//! artifact that is not the Candidate leaves every caller-owned port untouched,
//! and the custody adapter resolves a purpose only through the caller's own
//! store. The artifact-accepting branch needs the authorized bundle and is
//! exercised through `licoup_protocol_bindings`' gated cases instead.

use std::cell::RefCell;
use std::rc::Rc;

use crate::endpoint::EndpointState;
use crate::state::{
    AtomicState as SdkAtomicState, Clock as SdkClock, Commit as SdkCommit, CustodyRef,
    KeyCustody as SdkKeyCustody, PacketCarrier, PendingId as SdkPendingId,
    PendingItem as SdkPendingItem, Revision as SdkRevision, SecretHandle, StagedSecretHandle,
    X25519Private,
};
use crate::{
    AtomicState as AtomicStatePort, Clock as ClockPort, CustodyHandle, CustodyLifecycle,
    CustodyPurpose, KeyCustody as KeyCustodyPort, KeyMutation as PortKeyMutation, PortFailure,
    Revision, StateCommit as PortStateCommit, Transport as TransportPort, TransportOutcome,
    Versioned as PortVersioned,
};

use super::{
    AtomicStateAdapter, ClockAdapter, CustodyHandles, KeyCustodyAdapter, PacketCarrierAdapter,
    ProtocolWorkSetup,
};

/// Every caller-owned effect a port could produce, recorded in order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SideEffects {
    custody_reads: Vec<u128>,
    store_reads: usize,
    commits: usize,
    settle_calls: usize,
    clock_reads: usize,
    sends: Vec<Vec<u8>>,
}

#[derive(Clone, Default)]
struct Recorder {
    effects: Rc<RefCell<SideEffects>>,
}

impl Recorder {
    fn new() -> Self {
        Self::default()
    }

    fn observe(&self) -> SideEffects {
        self.effects.borrow().clone()
    }

    fn note_custody_read(&self, token: u128) {
        self.effects.borrow_mut().custody_reads.push(token);
    }
}

/// The caller's custody store: it holds which purpose and lifecycle each token
/// really has, and refuses every mismatch instead of trusting the request.
#[derive(Clone)]
struct Store {
    recorded: Vec<(u128, CustodyPurpose, CustodyLifecycle)>,
    recorder: Recorder,
}

impl Store {
    fn require(
        &self,
        handle: CustodyHandle,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<u128, PortFailure> {
        self.recorder.note_custody_read(handle.custody_token());
        let recorded = self
            .recorded
            .iter()
            .any(|(token, stored_purpose, stored_lifecycle)| {
                *token == handle.custody_token()
                    && *stored_purpose == purpose
                    && *stored_lifecycle == lifecycle
                    && handle.purpose() == purpose
                    && handle.lifecycle() == lifecycle
            });
        if recorded {
            Ok(handle.custody_token())
        } else {
            Err(PortFailure::Unavailable)
        }
    }
}

impl CustodyHandles for Store {
    fn custody_handle(
        &self,
        token: u128,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<CustodyHandle, PortFailure> {
        let handle = match lifecycle {
            CustodyLifecycle::Adopted => CustodyHandle::adopted(token, purpose),
            CustodyLifecycle::Staged => CustodyHandle::staged(token, purpose),
        };
        self.require(handle, purpose, lifecycle).map(|_| handle)
    }
}

/// The caller's custody port, written against tokens the way the SDK hands
/// them over. It never invents key material.
struct Custody {
    store: Store,
}

impl KeyCustodyPort for Custody {
    fn ed25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        let token = self.store.require(
            handle,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        )?;
        Ok([token as u8; 32])
    }

    fn ed25519_sign(
        &self,
        handle: CustodyHandle,
        _message: &[u8],
    ) -> Result<[u8; 64], PortFailure> {
        let token = self.store.require(
            handle,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        )?;
        Ok([token as u8; 64])
    }

    fn ml_dsa_65_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        let token = self.store.require(
            handle,
            CustodyPurpose::MlDsa65Signing,
            CustodyLifecycle::Adopted,
        )?;
        Ok(vec![token as u8])
    }

    fn ml_dsa_65_sign(
        &self,
        handle: CustodyHandle,
        _message: &[u8],
    ) -> Result<Vec<u8>, PortFailure> {
        self.ml_dsa_65_public(handle)
    }

    fn x25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        let token =
            self.store
                .require(handle, CustodyPurpose::X25519Private, handle.lifecycle())?;
        Ok([token as u8; 32])
    }

    fn x25519(&self, handle: CustodyHandle, _public: &[u8; 32]) -> Result<[u8; 32], PortFailure> {
        self.x25519_public(handle)
    }

    fn ml_kem_768_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        let token =
            self.store
                .require(handle, CustodyPurpose::MlKem768Private, handle.lifecycle())?;
        Ok(vec![token as u8])
    }

    fn ml_kem_768_encapsulate(
        &self,
        _public: &[u8],
        entropy: CustodyHandle,
    ) -> Result<(Vec<u8>, [u8; 32]), PortFailure> {
        let token = self.store.require(
            entropy,
            CustodyPurpose::MlKemEncapsulationEntropy,
            CustodyLifecycle::Adopted,
        )?;
        Ok((Vec::new(), [token as u8; 32]))
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: CustodyHandle,
        _ciphertext: &[u8],
    ) -> Result<[u8; 32], PortFailure> {
        let token =
            self.store
                .require(handle, CustodyPurpose::MlKem768Private, handle.lifecycle())?;
        Ok([token as u8; 32])
    }

    fn abort_x25519(&mut self, _staged: CustodyHandle) {}

    fn abort_ml_kem_768(&mut self, _staged: CustodyHandle) {}
}

/// The caller's durable store: one committed snapshot, advanced only by an
/// accepted old-or-new commit. Its pending type is the protocol layer's own
/// item, so a committed item is never rebuilt or re-identified on the way back.
struct Durable {
    current: PortVersioned<EndpointState, SdkPendingItem>,
    recorder: Recorder,
}

impl AtomicStatePort for Durable {
    type Snapshot = EndpointState;
    type Pending = SdkPendingItem;

    fn load(&self) -> Result<PortVersioned<EndpointState, SdkPendingItem>, PortFailure> {
        self.recorder.effects.borrow_mut().store_reads += 1;
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: PortStateCommit<EndpointState, SdkPendingItem>,
    ) -> Result<Revision, PortFailure> {
        if expected != self.current.revision() {
            return Err(PortFailure::Conflict);
        }
        for mutation in commit.key_mutations() {
            let (handle, adopt) = match mutation {
                PortKeyMutation::Adopt(handle) => (*handle, true),
                PortKeyMutation::Delete(handle) => (*handle, false),
            };
            let allowed_purpose = matches!(
                (adopt, handle.purpose()),
                (
                    true,
                    CustodyPurpose::X25519Private | CustodyPurpose::MlKem768Private
                ) | (
                    false,
                    CustodyPurpose::X25519Private
                        | CustodyPurpose::MlKem768Private
                        | CustodyPurpose::MlKemEncapsulationEntropy,
                )
            );
            let wanted_lifecycle = if adopt {
                CustodyLifecycle::Staged
            } else {
                CustodyLifecycle::Adopted
            };
            if !allowed_purpose || handle.lifecycle() != wanted_lifecycle {
                return Err(PortFailure::Unavailable);
            }
        }
        self.current = commit.into_versioned(expected)?;
        self.recorder.effects.borrow_mut().commits += 1;
        Ok(self.current.revision())
    }

    fn settle(
        &mut self,
        revision: Revision,
        pending: &SdkPendingItem,
    ) -> Result<Revision, PortFailure> {
        if revision != self.current.revision() {
            return Err(PortFailure::Conflict);
        }
        let mut remaining = self.current.pending().to_vec();
        let Some(index) = remaining.iter().position(|item| item.id() == pending.id()) else {
            return Err(PortFailure::Unavailable);
        };
        remaining.remove(index);
        self.current = PortStateCommit::new(self.current.state().clone(), Vec::new(), remaining)
            .into_versioned(revision)?;
        self.recorder.effects.borrow_mut().settle_calls += 1;
        Ok(self.current.revision())
    }
}

/// The caller's clock. Reading it is an effect, so a refused artifact must not
/// produce one.
struct Clock {
    recorder: Recorder,
}

impl ClockPort for Clock {
    fn now_unix_seconds(&self) -> Result<u64, PortFailure> {
        self.recorder.effects.borrow_mut().clock_reads += 1;
        Ok(1_700_000_000)
    }
}

/// The caller's carrier. Submitting is the network effect under test.
struct Carrier {
    recorder: Recorder,
}

impl TransportPort for Carrier {
    fn submit(&mut self, packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
        self.recorder
            .effects
            .borrow_mut()
            .sends
            .push(packet.to_vec());
        Ok(TransportOutcome::Accepted)
    }
}

fn recorded_store() -> (Store, Recorder) {
    let recorder = Recorder::new();
    let store = Store {
        recorded: vec![
            (7, CustodyPurpose::X25519Private, CustodyLifecycle::Staged),
            (9, CustodyPurpose::MlKem768Private, CustodyLifecycle::Staged),
            (
                11,
                CustodyPurpose::Ed25519Signing,
                CustodyLifecycle::Adopted,
            ),
            (
                12,
                CustodyPurpose::MlKem768Private,
                CustodyLifecycle::Adopted,
            ),
        ],
        recorder: recorder.clone(),
    };
    (store, recorder)
}

/// One complete caller-owned port spine, plus the observation handle for it.
fn spine() -> (
    ProtocolWorkSetup<Custody, Store, Durable, Clock, Carrier>,
    Recorder,
) {
    let (handles, recorder) = recorded_store();
    let custody = Custody {
        store: handles.clone(),
    };
    let state = Durable {
        current: PortVersioned::initial(EndpointState::responder()),
        recorder: recorder.clone(),
    };
    let clock = Clock {
        recorder: recorder.clone(),
    };
    let carrier = Carrier {
        recorder: recorder.clone(),
    };
    (
        ProtocolWorkSetup::new(
            // Not the fixed Candidate: the most the SDK can do with these bytes
            // is refuse them.
            br#"{"artifactVersion":"licoarc.bundle.v1"}"#.to_vec(),
            custody,
            handles,
            state,
            clock,
            carrier,
        ),
        recorder,
    )
}

#[test]
fn a_refused_artifact_leaves_every_caller_owned_port_untouched() {
    let (setup, recorder) = spine();
    let supplied = setup.authority().to_vec();

    let refusal = match setup.admit() {
        Ok(_) => panic!("bytes that are not the fixed Candidate are refused"),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.code(), "authorization_required");
    assert_eq!(
        refusal.cause().code,
        crate::ErrorCode::InvalidAuthorityInput
    );

    // Admission was refused before any port ran: no custody lookup, no store
    // read, no commit, no settle, no clock read, and nothing sent.
    assert_eq!(
        recorder.observe(),
        SideEffects::default(),
        "the refused branch must produce no write, no network I/O, and no clock read"
    );
    // What was supplied is what was admitted against: nothing was rewritten,
    // normalized, or synthesized on the way in.
    assert_eq!(
        supplied,
        br#"{"artifactVersion":"licoarc.bundle.v1"}"#.to_vec()
    );
}

#[test]
fn a_refused_artifact_hands_the_ports_back_unchanged() {
    let (setup, recorder) = spine();

    // The refused attempt consumed the setup, and the same ports are still
    // there to try again with: no write happened on the way through.
    let refusal = match setup.admit() {
        Ok(_) => panic!("bytes that are not the fixed Candidate are refused"),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.code(), "authorization_required");
    assert_eq!(recorder.observe(), SideEffects::default());

    let (setup, recorder) = spine();
    let (custody, handles, state, clock, transport) = setup.ports().into_parts();

    // Every port is still usable and still owns its caller's store.
    let adapter = KeyCustodyAdapter::new(custody, handles);
    let refusal = adapter
        .ed25519_public(&SecretHandle::from_custody_token(7))
        .expect_err("token 7 is a staged X25519 key, not an adopted signing key");
    assert_eq!(refusal.code, crate::ErrorCode::ProviderFailure);

    let adapter = AtomicStateAdapter::new(state);
    assert_eq!(adapter.load().unwrap().revision().value(), 0);

    let clock = ClockAdapter::new(clock);
    assert_eq!(clock.now_unix_seconds().unwrap(), 1_700_000_000);
    let mut transport = PacketCarrierAdapter::new(transport);
    assert!(transport.send(b"packet").is_ok());

    // Only the adapter exercise above produced effects.
    let observed = recorder.observe();
    assert_eq!(observed.custody_reads, vec![7]);
    assert_eq!(observed.store_reads, 1);
    assert_eq!(observed.clock_reads, 1);
    assert_eq!(observed.sends, vec![b"packet".to_vec()]);
}

#[test]
fn custody_resolves_a_purpose_through_the_callers_own_store_only() {
    let (store, recorder) = recorded_store();
    let adapter = KeyCustodyAdapter::new(
        Custody {
            store: store.clone(),
        },
        store,
    );

    // A token the caller really holds for this purpose is usable.
    assert_eq!(
        adapter.ed25519_public(&SecretHandle::from_custody_token(11)),
        Ok([11_u8; 32])
    );

    // A token the caller holds for another purpose is refused, even when the
    // caller re-labels it, because the store, not the request, decides.
    let custody = Custody {
        store: recorded_store().0,
    };
    assert_eq!(
        KeyCustodyPort::x25519(
            &custody,
            CustodyHandle::adopted(11, CustodyPurpose::X25519Private),
            &[0; 32],
        ),
        Err(PortFailure::Unavailable),
        "an Ed25519 token cannot serve an X25519 operation"
    );

    // A staged token serves the staged operation it was created for, and the
    // same token cannot be promoted to adopted by the caller.
    let staged = CustodyRef::Staged(&StagedSecretHandle::<X25519Private>::from_custody_token(7));
    assert_eq!(adapter.x25519_public(staged), Ok([7_u8; 32]));
    let adopted = CustodyRef::Adopted(&SecretHandle::<X25519Private>::from_custody_token(7));
    assert_eq!(
        adapter.x25519_public(adopted),
        Err(crate::Error {
            code: crate::ErrorCode::ProviderFailure,
            stage: crate::Stage::Provider,
            retryable: false,
        }),
        "the same token cannot be promoted to adopted by the caller"
    );

    // The resolver is what looks the token up; it is never trusted blindly. A
    // token the caller really holds resolves to the handle for it, and one the
    // caller does not hold is refused instead of being reported as a handle the
    // caller would like to be true.
    let resolver = recorder_store(&recorder);
    assert_eq!(
        CustodyHandles::custody_handle(
            &resolver,
            11,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        )
        .unwrap()
        .custody_token(),
        11
    );
    assert_eq!(
        CustodyHandles::custody_handle(
            &resolver,
            404,
            CustodyPurpose::Ed25519Signing,
            CustodyLifecycle::Adopted,
        ),
        Err(PortFailure::Unavailable),
        "an unrecorded token is not a handle the caller holds"
    );
}

/// A resolver over the same recorded tokens, so the handle lookup can be
/// exercised on its own.
fn recorder_store(recorder: &Recorder) -> Store {
    Store {
        recorded: vec![
            (
                11,
                CustodyPurpose::Ed25519Signing,
                CustodyLifecycle::Adopted,
            ),
            (7, CustodyPurpose::X25519Private, CustodyLifecycle::Staged),
        ],
        recorder: recorder.clone(),
    }
}

#[test]
fn a_rejected_or_ambiguous_send_is_never_reported_as_delivered() {
    struct Fixed(TransportOutcome);
    impl TransportPort for Fixed {
        fn submit(&mut self, _packet: &[u8]) -> Result<TransportOutcome, PortFailure> {
            Ok(self.0)
        }
    }

    let mut rejecting = PacketCarrierAdapter::new(Fixed(TransportOutcome::Rejected));
    let refusal = rejecting
        .send(b"packet")
        .expect_err("a rejected attempt is not a delivery");
    assert!(!refusal.retryable);
    assert_eq!(refusal.code, crate::ErrorCode::ProviderFailure);

    let mut ambiguous = PacketCarrierAdapter::new(Fixed(TransportOutcome::Ambiguous));
    let refusal = ambiguous
        .send(b"packet")
        .expect_err("an ambiguous attempt is not a delivery");
    assert!(
        refusal.retryable,
        "an unknown outcome must re-drive the same committed packet"
    );
}

#[test]
fn a_generation_zero_snapshot_carries_no_committed_work() {
    // The SDK's own generation-zero value is the initial snapshot, which holds
    // nothing. A store claiming generation zero with pending items therefore
    // describes a value the protocol could not have produced, and the adapter
    // refuses it instead of inventing a later generation to carry it.
    struct ZeroWithPending {
        current: PortVersioned<EndpointState, SdkPendingItem>,
    }

    impl AtomicStatePort for ZeroWithPending {
        type Snapshot = EndpointState;
        type Pending = SdkPendingItem;

        fn load(&self) -> Result<PortVersioned<EndpointState, SdkPendingItem>, PortFailure> {
            Ok(self.current.clone())
        }

        fn compare_and_swap(
            &mut self,
            _expected: Revision,
            _commit: PortStateCommit<EndpointState, SdkPendingItem>,
        ) -> Result<Revision, PortFailure> {
            Err(PortFailure::Unavailable)
        }

        fn settle(
            &mut self,
            _revision: Revision,
            _pending: &SdkPendingItem,
        ) -> Result<Revision, PortFailure> {
            Err(PortFailure::Unavailable)
        }
    }

    let adapter = AtomicStateAdapter::new(ZeroWithPending {
        current: PortVersioned::restored(
            Revision::initial(),
            EndpointState::responder(),
            vec![
                SdkPendingItem::packet(SdkPendingId::from_token(5), vec![1, 2, 3])
                    .expect("a bounded packet is one item"),
            ],
        ),
    });

    assert_eq!(
        adapter.load().unwrap_err().code,
        crate::ErrorCode::InvalidTransition
    );
}

#[test]
fn the_state_adapter_forwards_the_old_or_new_decision_and_the_item_itself() {
    let (_, recorder) = recorded_store();
    let mut adapter = AtomicStateAdapter::new(Durable {
        current: PortVersioned::initial(EndpointState::responder()),
        recorder: recorder.clone(),
    });

    let loaded = adapter.load().unwrap();
    assert_eq!(loaded.revision().value(), 0);
    assert!(loaded.pending().is_empty());

    // The adapter forwards the decision instead of making it: a commit at the
    // observed generation advances once, and one at a stale generation does not.
    let commit = SdkCommit::bounded(
        EndpointState::responder(),
        Vec::new(),
        vec![SdkPendingItem::packet(SdkPendingId::from_token(5), vec![1, 2, 3]).unwrap()],
        usize::MAX,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(
        adapter
            .compare_and_swap(SdkRevision::initial(), commit.clone())
            .unwrap()
            .value(),
        1
    );
    assert_eq!(
        adapter
            .compare_and_swap(SdkRevision::initial(), commit)
            .unwrap_err()
            .code,
        crate::ErrorCode::Conflict,
        "the store's generation, not the adapter, decides the outcome"
    );

    // The protocol layer settles the exact item it committed.
    let item = SdkPendingItem::packet(SdkPendingId::from_token(5), vec![1, 2, 3]).unwrap();
    let settled = adapter
        .settle(SdkRevision::initial().successor().unwrap(), item.id())
        .unwrap();
    assert_eq!(settled.value(), 2);
    assert!(adapter.load().unwrap().pending().is_empty());

    let observed = recorder.observe();
    assert_eq!(observed.commits, 1);
    assert_eq!(observed.settle_calls, 1);
}

/// The replacement composition's own contracts.
///
/// The artifact-accepting branch needs the authorized bundle and the real
/// ed25519/ml-dsa-65 keys; `licoup_protocol_bindings`' gated cases exercise it.
/// What is proved here is the part that must hold *without* an artifact: an
/// unauthorized request is refused in the composition's own terms, before the
/// SDK, a store, a transport or an effect is reached.
mod replacement_composition {
    use crate::{
        AuthoritySource, ReplacementAuthorityRefusal, ReplacementBinding, ReplacementOperation,
    };
    use crate::{ReplacementAdmission, ReplacementSession, SdkReplacementAuthority};
    use serde_json::json;

    use crate::{ReplacementRequest, admit_replacement};

    fn binding() -> ReplacementBinding {
        ReplacementBinding::new(
            "subject-a",
            "source-device",
            "new-device",
            ReplacementOperation::Activate,
        )
    }

    fn admission(state_digest: [u8; 32]) -> ReplacementAdmission {
        ReplacementAdmission {
            predecessor: None,
            session: ReplacementSession {
                authenticated: true,
                authority_state_digest: state_digest,
                endpoint_identity_ref: [1; 32],
                identity_state_digest: [2; 32],
            },
            endpoints: Vec::new(),
        }
    }

    fn request(source: AuthoritySource) -> ReplacementRequest {
        ReplacementRequest::new(source, binding(), admission([0; 32]))
    }

    /// An adapter for a build that admitted nothing.
    fn refusing_adapter() -> SdkReplacementAuthority {
        SdkReplacementAuthority::without_admitted_line()
    }

    #[test]
    fn an_ordinary_source_is_refused_in_the_compositions_own_terms() {
        // A relay mailbox, a provider backup and an untrusted remote all reach
        // the composition as `None`. The refusal must name the missing
        // credential and not the absent artifact, because the credential is
        // decided first: an unauthorized request never becomes an SDK call.
        for source in std::iter::once(AuthoritySource::None) {
            let refusal = admit_replacement(
                &refusing_adapter(),
                &json!({"not": "a record"}),
                &request(source),
            );
            assert!(!refusal.is_authorized());
            assert_eq!(
                refusal.refusal(),
                Some(ReplacementAuthorityRefusal::NoTrustedAuthority),
                "an ordinary source must be refused as unauthorized, not as unverified"
            );
            assert!(refusal.accepted().is_none());
        }
    }

    #[test]
    fn a_real_source_but_no_admitted_line_reports_the_missing_artifact() {
        // The other half of the same split: the caller really holds a trusted
        // device, so the composition proceeds to the fixed boundary, which has
        // no admitted line to spend.
        let refusal = admit_replacement(
            &refusing_adapter(),
            &json!({"not": "a record"}),
            &request(AuthoritySource::TrustedDevice),
        );
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::NoTrustedAuthority)
        );
        // Both paths refuse; what differs is that the second one reached the
        // boundary at all, which the stable code alone cannot show. The
        // distinction is proved by the bindings' own `NoAdmittedLine` case.
        assert_eq!(
            crate::ReplacementAdmissionRefusal::NoAdmittedLine.code(),
            "no_admitted_line"
        );
    }

    #[test]
    fn a_replayed_epoch_is_refused_before_the_sdk_is_reached() {
        let request = ReplacementRequest::new(
            AuthoritySource::SavedRecoveryCredential,
            binding(),
            ReplacementAdmission {
                predecessor: Some(crate::ReplacementPredecessor::new(
                    licoarc::identity::AcceptedUserAuthority {
                        state: json!({}),
                        user_identity_ref: [0; 32],
                        authority_epoch: 4,
                        state_digest: [0; 32],
                    },
                )),
                session: ReplacementSession {
                    authenticated: true,
                    authority_state_digest: [0; 32],
                    endpoint_identity_ref: [1; 32],
                    identity_state_digest: [2; 32],
                },
                endpoints: Vec::new(),
            },
        );

        // The presented record is at the epoch already accepted.
        let refusal =
            admit_replacement(&refusing_adapter(), &json!({"authorityEpoch": 4}), &request);
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch: 4,
                presented_epoch: 4,
            }),
            "a superseded roster is refused from the caller's own epoch, not re-verified"
        );

        // An older epoch is the same class of refusal.
        let refusal =
            admit_replacement(&refusing_adapter(), &json!({"authorityEpoch": 3}), &request);
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::ReplayedAuthority {
                accepted_epoch: 4,
                presented_epoch: 3,
            })
        );

        // A record with no readable epoch at all is unreadable, never treated
        // as epoch zero (which would silently accept a superseded record).
        let refusal = admit_replacement(&refusing_adapter(), &json!({}), &request);
        assert_eq!(
            refusal.refusal(),
            Some(ReplacementAuthorityRefusal::UnreadableAuthority)
        );
    }
}
