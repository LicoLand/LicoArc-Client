//! Durable admitted obligations: outbound work this client owes once it has
//! admitted it.
//!
//! The protocol layer decides what an obligation *is*: the pinned SDK commits a
//! delivery unit together with the protocol snapshot, and the caller-owned ports
//! ([`crate::state::AtomicState`], mirrored for the adapter in
//! `licoup_endpoint_core::ports`) hand that same unit back when it is re-driven or
//! settled. This module owns the client-side question the ports leave open:
//! **which obligations may be discarded, and by what**.
//!
//! The rules are the ones the cross-device delivery boundary requires, and each is
//! falsifiable from this module's public surface:
//!
//! * **Admission is the irreversible step.** Nothing is owed before
//!   [`ObligationLedger::admit`], so a refused or abandoned attempt costs only its
//!   staged bytes, and pre-admission staging is bounded and refuses with
//!   backpressure instead of growing.
//! * **An admitted obligation is never discarded by elapsed time or retry count.**
//!   A rejected, transient or ambiguous delivery keeps its obligation and
//!   increments an attempt counter; only an accepted settlement removes it.
//!   `attempts` is reported, never a permit to drop owed material.
//! * **A budget sweep cannot discard owed material.** [`ObligationLedger::sweep`]
//!   reclaims only pre-admission staging and refuses while any admitted obligation
//!   is outstanding, so local space pressure cannot erase what this client owes.
//! * **Restart recovers the same obligations.** [`ObligationLedger::durable_record`]
//!   is the whole owed set; the ledger rebuilt from it re-drives exactly those
//!   deliveries, with their attempts and their generation intact.
//!
//! Nothing here performs protocol verification, chooses a transport outcome, or
//! classifies a relay response: it records the caller's own answer and keeps the
//! obligation until that answer is acceptance.

use serde::{Deserialize, Serialize};

/// One obligation identity. It is the protocol layer's own identity for the
/// committed delivery unit, carried through unchanged.
pub type ObligationId = u128;

/// The largest pre-admission staging this ledger holds by default.
pub const DEFAULT_PRE_ADMISSION_BUDGET_BYTES: usize = 1024 * 1024;

/// Retention of *unadmitted* staging. Admitted obligations have no such window.
pub const DEFAULT_PRE_ADMISSION_RETENTION_SECONDS: u64 = 300;

/// What one delivery attempt returned.
///
/// The vocabulary is the caller's classification of the transport attempt, and it
/// is deliberately not a protocol outcome: [`Self::Ambiguous`] means the attempt
/// may or may not have been accepted, which is exactly the case that must re-drive
/// the same already-committed obligation rather than a fresh one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// The peer accepted the delivery unit. The obligation is settled.
    Accepted,
    /// The peer definitely did not accept it.
    Rejected,
    /// The attempt failed in a way that may succeed later.
    Transient,
    /// The attempt may or may not have been accepted.
    Ambiguous,
}

impl DeliveryOutcome {
    /// Whether this outcome settles the obligation.
    #[must_use]
    pub const fn settles(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Why a staged obligation was refused before it was ever admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreAdmissionRefusal {
    /// The staging budget is exhausted. The caller must wait for a settlement or
    /// drop its own staging; the ledger grows for nobody.
    BudgetExhausted {
        budget_bytes: usize,
        staged_bytes: usize,
    },
    /// The identity is already admitted, so it cannot be staged again as if it
    /// were new.
    AlreadyAdmitted,
}

impl PreAdmissionRefusal {
    /// The stable reason a caller publishes.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "endpoint_pre_admission_budget_exhausted",
            Self::AlreadyAdmitted => "endpoint_obligation_already_admitted",
        }
    }
}

/// Why a settlement did not settle anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementRefusal {
    /// No admitted obligation carries this identity. An unadmitted attempt has
    /// nothing to settle, and a second settlement of the same identity must not
    /// remove somebody else's obligation.
    NotOwed,
}

impl SettlementRefusal {
    /// The stable reason a caller publishes.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        "endpoint_obligation_not_owed"
    }
}

/// One admitted obligation, in the protocol layer's own payload vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedObligation<Payload> {
    id: ObligationId,
    payload: Payload,
    /// The generation the admission committed at. It is the durable ordering of
    /// this obligation and moves for no other reason than a commit.
    admitted_generation: u64,
    /// How many delivery attempts have been made. It is reported, never a
    /// discard rule.
    attempts: u32,
}

impl<Payload> AdmittedObligation<Payload> {
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    #[must_use]
    pub const fn admitted_generation(&self) -> u64 {
        self.admitted_generation
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// One staged, not-yet-admitted delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreAdmissionEntry {
    id: ObligationId,
    bytes: usize,
    staged_at_unix_seconds: u64,
}

/// What one settlement did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Settled {
    /// The obligation is settled and no longer owed.
    Settled { attempts: u32 },
    /// The delivery did not succeed, so the obligation stays owed.
    StillOwed { attempts: u32 },
}

/// What one sweep reclaimed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SweepOutcome {
    /// Nothing was owed and no staging had outlived its window.
    NothingReclaimable,
    /// Only unadmitted staging was reclaimed. Owed material is untouched.
    ReclaimedStaging { entries: usize, bytes: usize },
    /// Owed material exists, so the sweep reclaimed nothing. `owed` names how
    /// many obligations are outstanding; `requests` names how many were asked
    /// about, which is what a caller reports to its own user.
    RefusedWhileOwed { owed: usize, requested: usize },
}

/// The durable projection of every obligation this client owes.
///
/// It is the whole persisted state of the ledger: rebuilding from this record
/// recovers the same obligations, with the same identities, payloads, attempts and
/// generation. Unadmitted staging is deliberately absent — it was never owed, and
/// persisting it would make a discarded attempt look like a promise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableObligationRecord<Payload> {
    schema: String,
    generation: u64,
    admitted: Vec<AdmittedObligation<Payload>>,
}

/// The schema of [`DurableObligationRecord`].
pub const DURABLE_OBLIGATION_SCHEMA: &str = "licoup.endpoint-obligations.v1";

impl<Payload: Clone> DurableObligationRecord<Payload> {
    /// The generation this record was written at.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The obligations this record owes.
    #[must_use]
    pub fn admitted(&self) -> &[AdmittedObligation<Payload>] {
        &self.admitted
    }

    /// Whether the record carries the schema this build writes.
    #[must_use]
    pub fn schema_matches(&self) -> bool {
        self.schema == DURABLE_OBLIGATION_SCHEMA
    }
}

/// What this ledger holds and what it refuses to hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObligationLimits {
    /// The largest total staging the ledger holds before admission.
    pub pre_admission_bytes: usize,
    /// How long unadmitted staging may live. It applies to staging only: an
    /// admitted obligation has no window.
    pub pre_admission_retention_seconds: u64,
}

impl Default for ObligationLimits {
    fn default() -> Self {
        Self {
            pre_admission_bytes: DEFAULT_PRE_ADMISSION_BUDGET_BYTES,
            pre_admission_retention_seconds: DEFAULT_PRE_ADMISSION_RETENTION_SECONDS,
        }
    }
}

/// The obligations one client owes, and the rule for discarding them.
#[derive(Clone, Debug)]
pub struct ObligationLedger<Payload> {
    limits: ObligationLimits,
    generation: u64,
    pre_admission: Vec<PreAdmissionEntry>,
    admitted: Vec<AdmittedObligation<Payload>>,
}

impl<Payload> Default for ObligationLedger<Payload> {
    fn default() -> Self {
        Self::new(ObligationLimits::default())
    }
}

impl<Payload> ObligationLedger<Payload> {
    /// An empty ledger under explicit limits.
    #[must_use]
    pub const fn new(limits: ObligationLimits) -> Self {
        Self {
            limits,
            generation: 0,
            pre_admission: Vec::new(),
            admitted: Vec::new(),
        }
    }

    #[must_use]
    pub const fn limits(&self) -> ObligationLimits {
        self.limits
    }

    /// The durable generation of the owed set.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The admitted obligations, in admission order.
    #[must_use]
    pub fn owed(&self) -> &[AdmittedObligation<Payload>] {
        &self.admitted
    }

    /// Whether any admitted obligation is outstanding.
    #[must_use]
    pub fn is_owed(&self) -> bool {
        !self.admitted.is_empty()
    }

    /// The total bytes currently staged before admission.
    #[must_use]
    pub fn staged_bytes(&self) -> usize {
        self.pre_admission.iter().map(|entry| entry.bytes).sum()
    }

    /// Whether one admitted obligation carries this identity.
    #[must_use]
    pub fn is_owed_id(&self, id: ObligationId) -> bool {
        self.admitted.iter().any(|obligation| obligation.id == id)
    }

    /// The admitted obligation with this identity.
    #[must_use]
    pub fn obligation(&self, id: ObligationId) -> Option<&AdmittedObligation<Payload>> {
        self.admitted.iter().find(|obligation| obligation.id == id)
    }
}

impl<Payload: Clone> ObligationLedger<Payload> {
    /// Stage one delivery before admission.
    ///
    /// The refusal happens here, before anything is admitted and before any
    /// effect: a caller that is refused has made no promise, and the ledger is
    /// unchanged.
    pub fn stage(
        &mut self,
        id: ObligationId,
        bytes: usize,
        now_unix_seconds: u64,
    ) -> Result<(), PreAdmissionRefusal> {
        if self.is_owed_id(id) {
            return Err(PreAdmissionRefusal::AlreadyAdmitted);
        }
        let staged = self.staged_bytes();
        if staged.saturating_add(bytes) > self.limits.pre_admission_bytes {
            return Err(PreAdmissionRefusal::BudgetExhausted {
                budget_bytes: self.limits.pre_admission_bytes,
                staged_bytes: staged,
            });
        }
        self.pre_admission.retain(|entry| entry.id != id);
        self.pre_admission.push(PreAdmissionEntry {
            id,
            bytes,
            staged_at_unix_seconds: now_unix_seconds,
        });
        Ok(())
    }

    /// Admit one staged delivery as a durable obligation.
    ///
    /// Admission requires that the delivery was staged: an identity that was never
    /// staged is refused rather than admitted implicitly, so the caller's own
    /// pre-admission decision stays the boundary it claims to be.
    pub fn admit(
        &mut self,
        id: ObligationId,
        payload: Payload,
    ) -> Result<&AdmittedObligation<Payload>, PreAdmissionRefusal> {
        if self.is_owed_id(id) {
            return Err(PreAdmissionRefusal::AlreadyAdmitted);
        }
        if !self.pre_admission.iter().any(|entry| entry.id == id) {
            return Err(PreAdmissionRefusal::AlreadyAdmitted);
        }
        self.pre_admission.retain(|entry| entry.id != id);
        self.generation += 1;
        self.admitted.push(AdmittedObligation {
            id,
            payload,
            admitted_generation: self.generation,
            attempts: 0,
        });
        Ok(self
            .admitted
            .last()
            .expect("the obligation was just admitted"))
    }

    /// Record one delivery attempt against an admitted obligation.
    ///
    /// Only an accepted outcome removes the obligation. Every other outcome keeps
    /// it and counts the attempt, so a delivery that failed for the tenth time is
    /// still owed exactly as the first failure was.
    pub fn settle(
        &mut self,
        id: ObligationId,
        outcome: DeliveryOutcome,
    ) -> Result<Settled, SettlementRefusal> {
        let Some(index) = self
            .admitted
            .iter()
            .position(|obligation| obligation.id == id)
        else {
            return Err(SettlementRefusal::NotOwed);
        };
        if !outcome.settles() {
            let obligation = &mut self.admitted[index];
            obligation.attempts = obligation.attempts.saturating_add(1);
            return Ok(Settled::StillOwed {
                attempts: obligation.attempts,
            });
        }
        let settled = self.admitted.remove(index);
        // Removing an obligation is itself a durable change: the generation moves
        // so a restarted client reads the settlement it already committed.
        self.generation += 1;
        Ok(Settled::Settled {
            attempts: settled.attempts,
        })
    }

    /// Reclaim what may be reclaimed, and refuse while anything is owed.
    ///
    /// `requested` is how many obligations the caller asked about — a diagnostic,
    /// not a limit: a sweep asked about one obligation still refuses while ten are
    /// owed, because the material it would discard is not the material it named.
    pub fn sweep(&mut self, now_unix_seconds: u64, requested: usize) -> SweepOutcome {
        if self.is_owed() {
            return SweepOutcome::RefusedWhileOwed {
                owed: self.admitted.len(),
                requested,
            };
        }
        let retention = self.limits.pre_admission_retention_seconds;
        let before = self.pre_admission.len();
        let mut bytes = 0;
        self.pre_admission.retain(|entry| {
            let expired =
                now_unix_seconds.saturating_sub(entry.staged_at_unix_seconds) >= retention;
            if expired {
                bytes += entry.bytes;
            }
            !expired
        });
        let entries = before - self.pre_admission.len();
        if entries == 0 {
            SweepOutcome::NothingReclaimable
        } else {
            SweepOutcome::ReclaimedStaging { entries, bytes }
        }
    }

    /// The durable projection of everything this client owes.
    #[must_use]
    pub fn durable_record(&self) -> DurableObligationRecord<Payload> {
        DurableObligationRecord {
            schema: DURABLE_OBLIGATION_SCHEMA.to_owned(),
            generation: self.generation,
            admitted: self.admitted.clone(),
        }
    }

    /// Recover the ledger a previous run committed.
    ///
    /// The recovered ledger owes exactly the recorded obligations, with their
    /// attempts and their generation; a record written by another schema is
    /// refused rather than read as this one.
    #[must_use]
    pub fn from_durable_record(record: DurableObligationRecord<Payload>) -> Option<Self> {
        if !record.schema_matches() {
            return None;
        }
        Some(Self {
            limits: ObligationLimits::default(),
            generation: record.generation,
            pre_admission: Vec::new(),
            admitted: record.admitted,
        })
    }

    /// Recover with explicit limits, so a caller keeps its own staging budget.
    #[must_use]
    pub fn from_durable_record_with_limits(
        record: DurableObligationRecord<Payload>,
        limits: ObligationLimits,
    ) -> Option<Self> {
        Self::from_durable_record(record).map(|mut ledger| {
            ledger.limits = limits;
            ledger
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DURABLE_OBLIGATION_SCHEMA, DeliveryOutcome, DurableObligationRecord, ObligationLedger,
        ObligationLimits, PreAdmissionRefusal, Settled, SettlementRefusal, SweepOutcome,
    };

    fn ledger() -> ObligationLedger<Vec<u8>> {
        ObligationLedger::new(ObligationLimits {
            pre_admission_bytes: 8,
            pre_admission_retention_seconds: 60,
        })
    }

    fn admitted(ledger: &mut ObligationLedger<Vec<u8>>, id: u128, at: u64) {
        ledger.stage(id, 1, at).expect("staging fits the budget");
        ledger
            .admit(id, vec![id as u8])
            .expect("a staged obligation is admissible");
    }

    #[test]
    fn an_admitted_obligation_survives_a_restart_and_is_still_owed() {
        let mut ledger = ledger();
        admitted(&mut ledger, 7, 0);
        assert!(ledger.settle(7, DeliveryOutcome::Rejected).is_ok());

        let recovered = ObligationLedger::from_durable_record(ledger.durable_record())
            .expect("this build's own record is recovered");

        assert!(recovered.is_owed());
        assert_eq!(recovered.owed().len(), 1);
        let obligation = recovered.obligation(7).expect("the same obligation");
        assert_eq!(obligation.payload(), &vec![7]);
        assert_eq!(obligation.attempts(), 1, "the failed attempt is remembered");
        assert_eq!(recovered.generation(), ledger.generation());
    }

    #[test]
    fn a_failed_or_ambiguous_delivery_stays_pending_and_only_counts_an_attempt() {
        let mut ledger = ledger();
        admitted(&mut ledger, 1, 0);

        for outcome in [
            DeliveryOutcome::Rejected,
            DeliveryOutcome::Transient,
            DeliveryOutcome::Ambiguous,
        ] {
            let settled = ledger.settle(1, outcome).expect("the obligation is owed");
            assert!(
                matches!(settled, Settled::StillOwed { .. }),
                "{outcome:?} must not settle an obligation"
            );
        }
        assert!(ledger.is_owed(), "one obligation is still owed");
        assert_eq!(ledger.obligation(1).unwrap().attempts(), 3);

        assert_eq!(
            ledger.settle(1, DeliveryOutcome::Accepted),
            Ok(Settled::Settled { attempts: 3 })
        );
        assert!(!ledger.is_owed(), "only acceptance settles");
    }

    #[test]
    fn logical_time_far_past_the_staging_window_does_not_expire_admitted_material() {
        let mut ledger = ledger();
        admitted(&mut ledger, 11, 0);

        // Ten years of logical time, and the sweep is asked about the obligation.
        let far_future = 60 * 60 * 24 * 365 * 10;
        assert_eq!(
            ledger.sweep(far_future, 1),
            SweepOutcome::RefusedWhileOwed {
                owed: 1,
                requested: 1
            }
        );
        assert_eq!(ledger.owed().len(), 1);
        assert_eq!(ledger.obligation(11).unwrap().attempts(), 0);
    }

    #[test]
    fn a_budget_sweep_cannot_discard_owed_material() {
        let mut ledger = ledger();
        admitted(&mut ledger, 1, 0);
        admitted(&mut ledger, 2, 0);
        // Staging exists too; an owed obligation makes the whole sweep refuse.
        ledger.stage(3, 1, 0).expect("staging fits the budget");

        assert_eq!(
            ledger.sweep(10_000, 3),
            SweepOutcome::RefusedWhileOwed {
                owed: 2,
                requested: 3
            }
        );
        assert_eq!(ledger.owed().len(), 2);
        assert_eq!(ledger.staged_bytes(), 1, "staging is untouched as well");

        // Once nothing is owed, only staging that outlived its window is reclaimed.
        ledger.settle(1, DeliveryOutcome::Accepted).expect("owed");
        ledger.settle(2, DeliveryOutcome::Accepted).expect("owed");
        assert_eq!(
            ledger.sweep(10_000, 1),
            SweepOutcome::ReclaimedStaging {
                entries: 1,
                bytes: 1
            }
        );
        assert!(!ledger.is_owed());
    }

    #[test]
    fn pre_admission_is_bounded_and_refused_before_any_admission() {
        let mut ledger = ledger();
        ledger
            .stage(1, 8, 0)
            .expect("the whole budget is available");

        assert_eq!(
            ledger.stage(2, 1, 0),
            Err(PreAdmissionRefusal::BudgetExhausted {
                budget_bytes: 8,
                staged_bytes: 8
            })
        );
        assert!(!ledger.is_owed(), "a refused staging owes nothing");
        assert_eq!(ledger.owed().len(), 0);
        assert_eq!(ledger.generation(), 0, "no commit happened");
    }

    #[test]
    fn admission_requires_staging_so_a_caller_cannot_admit_implicitly() {
        let mut ledger = ledger();

        assert_eq!(
            ledger.admit(1, vec![1]),
            Err(PreAdmissionRefusal::AlreadyAdmitted)
        );
        assert!(!ledger.is_owed());
        assert_eq!(ledger.generation(), 0);
    }

    #[test]
    fn a_second_settlement_of_one_identity_settles_nothing_else() {
        let mut ledger = ledger();
        admitted(&mut ledger, 1, 0);
        admitted(&mut ledger, 2, 0);

        assert_eq!(
            ledger.settle(1, DeliveryOutcome::Accepted),
            Ok(Settled::Settled { attempts: 0 })
        );
        assert_eq!(
            ledger.settle(1, DeliveryOutcome::Accepted),
            Err(SettlementRefusal::NotOwed),
            "a late duplicate settlement must not consume another obligation"
        );
        assert!(ledger.is_owed_id(2), "the unrelated obligation stays owed");
        assert_eq!(ledger.owed().len(), 1);
    }

    #[test]
    fn a_record_from_another_schema_is_refused_rather_than_read_as_this_one() {
        let mut ledger = ledger();
        admitted(&mut ledger, 5, 0);

        let mut record = ledger.durable_record();
        assert!(record.schema_matches());
        let foreign = DurableObligationRecord {
            schema: "licoup.endpoint-obligations.v0".to_owned(),
            ..record.clone()
        };
        assert!(ObligationLedger::from_durable_record(foreign).is_none());

        record.schema = DURABLE_OBLIGATION_SCHEMA.to_owned();
        let recovered = ObligationLedger::from_durable_record_with_limits(
            record,
            ObligationLimits {
                pre_admission_bytes: 1,
                pre_admission_retention_seconds: 1,
            },
        )
        .expect("the recovered ledger keeps its caller's limits");
        assert_eq!(recovered.limits().pre_admission_bytes, 1);
        assert!(recovered.is_owed());
        assert!(!recovered.owed().is_empty());
    }

    #[test]
    fn a_recovered_ledger_re_drives_the_same_obligations_rather_than_fresh_ones() {
        let mut ledger = ledger();
        admitted(&mut ledger, 42, 0);
        ledger.settle(42, DeliveryOutcome::Ambiguous).expect("owed");

        let mut recovered =
            ObligationLedger::from_durable_record(ledger.durable_record()).expect("recovered");
        let obligation = recovered.obligation(42).expect("the recorded obligation");
        assert_eq!(obligation.payload(), &vec![42]);
        assert_eq!(obligation.attempts(), 1);
        // Re-driving the same identity is what the attempts counter is for; it
        // neither creates a second obligation nor lets the first be discarded.
        assert_eq!(
            recovered.settle(42, DeliveryOutcome::Transient),
            Ok(Settled::StillOwed { attempts: 2 })
        );
        assert_eq!(recovered.owed().len(), 1);
    }
}
