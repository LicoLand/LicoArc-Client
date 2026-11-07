//! The durable endpoint state behind one drive.
//!
//! `FileState` couples the two halves of one endpoint's durability: the live
//! [`Versioned`] snapshot the protocol commits against (held by the coupled
//! [`MemoryState`]) and the last checkpoint the SDK sealed of it
//! (`dir/endpoint.checkpoint`). The checkpoint codec is the SDK's own —
//! `Endpoint::checkpoint` seals, [`decode_endpoint_checkpoint`] restores —
//! so this file stores bytes it cannot read and never invents a second state
//! format. The seal is authenticated under a caller-side integrity key kept
//! in `dir/endpoint.integrity`, so stored checkpoint bytes cannot be resealed
//! by whoever modified them.
//!
//! The ordering contract matches the SDK's: `compare_and_swap` commits to the
//! live value first, then the caller seals the new committed snapshot with
//! [`FileState::save`] before reporting the operation complete. A crash in
//! that window restores the previous complete snapshot, and the station's
//! claim window redelivers what the lost commit received — nothing is half
//! committed and nothing is invented.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use licoarc::artifact::VerifiedProtocolLine;
use licoarc::endpoint::{
    CheckpointIntegrityKey, Endpoint, EndpointCheckpoint, EndpointState, Role,
    decode_endpoint_checkpoint,
};
use licoarc::provider::Provider;
use licoarc::state::{AtomicState as SdkAtomicState, KeyCustody, PendingItem as SdkPendingItem};

use crate::ports::{AtomicState, PortFailure, Revision, StateCommit, Versioned};
use crate::providers::{FileCustody, MemoryState, fs::write_atomic};

/// The checkpoint file inside one endpoint directory.
const CHECKPOINT_FILE: &str = "endpoint.checkpoint";

/// The checkpoint integrity key inside one endpoint directory.
const INTEGRITY_FILE: &str = "endpoint.integrity";

/// The generation high-water mark inside one endpoint directory.
const GENERATION_FILE: &str = "endpoint.generation";

/// The endpoint-scope identifier inside one endpoint directory.
const SCOPE_FILE: &str = "endpoint.scope";

/// One endpoint's durable state: the live snapshot plus its sealed image.
///
/// `Clone` shares the same live snapshot — the `AtomicState` adapter sees the
/// same `Versioned` value the caller's `save` just sealed.
pub struct FileState<P> {
    memory: MemoryState<EndpointState, SdkPendingItem, P>,
    checkpoint: PathBuf,
    generation: PathBuf,
    integrity: Rc<CheckpointIntegrityKey>,
    scope: Rc<[u8; 32]>,
    minimum: Rc<Cell<u64>>,
}

impl<P> Clone for FileState<P> {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            checkpoint: self.checkpoint.clone(),
            generation: self.generation.clone(),
            integrity: self.integrity.clone(),
            scope: self.scope.clone(),
            minimum: self.minimum.clone(),
        }
    }
}

impl<P> FileState<P>
where
    P: Provider + Clone,
{
    /// Opens the responder endpoint state at `dir`.
    ///
    /// With a checkpoint file present the sealed snapshot is decoded and
    /// verified against `line` — a wrong line, profile, version, or digest is
    /// refused — and the live store starts from the restored generation.
    /// Without one the state starts in the `ResponderReady` phase.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when the checkpoint cannot be read or refuses to
    /// decode; a checkpoint is never repaired or skipped silently.
    pub fn responder(
        dir: &Path,
        line: VerifiedProtocolLine,
        custody: FileCustody<P>,
        provider: P,
    ) -> Result<Self, PortFailure> {
        Self::open(dir, line, custody, provider, EndpointState::responder)
    }

    /// Opens the initiator endpoint state at `dir`; see
    /// [`FileState::responder`]. Without a checkpoint the state starts in the
    /// `InitiatorNew` phase.
    pub fn initiator(
        dir: &Path,
        line: VerifiedProtocolLine,
        custody: FileCustody<P>,
        provider: P,
    ) -> Result<Self, PortFailure> {
        Self::open(dir, line, custody, provider, EndpointState::initiator)
    }

    fn open(
        dir: &Path,
        line: VerifiedProtocolLine,
        custody: FileCustody<P>,
        provider: P,
        fresh: fn() -> EndpointState,
    ) -> Result<Self, PortFailure> {
        let checkpoint = dir.join(CHECKPOINT_FILE);
        let bytes = match std::fs::read(&checkpoint) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(PortFailure::Unavailable),
        };
        let integrity = Rc::new(integrity_key(&dir.join(INTEGRITY_FILE), bytes.is_some())?);
        let scope = Rc::new(endpoint_scope(&dir.join(SCOPE_FILE), bytes.is_some())?);
        let generation = dir.join(GENERATION_FILE);
        let minimum = match bytes {
            Some(_) => generation_floor(&generation)?,
            None => 0,
        };
        let memory = match bytes {
            Some(bytes) => {
                let sealed = EndpointCheckpoint::from_secret_bytes(bytes)
                    .map_err(|_| PortFailure::Unavailable)?;
                let restored =
                    decode_endpoint_checkpoint(&provider, &line, &sealed, &integrity, &scope[..])
                        .map_err(|_| PortFailure::Unavailable)?;
                let sealed = restored
                    .into_versioned()
                    .map_err(|_| PortFailure::Unavailable)?;
                let versioned = Versioned::restored(
                    Revision::from_value(sealed.revision().value()),
                    sealed.state().clone(),
                    sealed.pending().to_vec(),
                );
                MemoryState::restored(versioned, custody)
            }
            None => MemoryState::initial(fresh(), custody),
        };
        Ok(Self {
            memory,
            checkpoint,
            generation,
            integrity,
            scope,
            minimum: Rc::new(Cell::new(minimum)),
        })
    }

    /// The live coupled store the endpoint commits against.
    #[must_use]
    pub const fn memory(&self) -> &MemoryState<EndpointState, SdkPendingItem, P> {
        &self.memory
    }

    /// Seals the endpoint's committed snapshot into the checkpoint file.
    ///
    /// Call it after every state-advancing operation — offer admission,
    /// handshake acceptance or verification, record send or receive, pending
    /// dispatch or release — so a restart restores exactly the last committed
    /// snapshot. The write is atomic: a crash leaves the previous complete
    /// checkpoint or the new one, never a torn file.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when the endpoint refuses to checkpoint (for
    /// example a state carrying a capability runtime, which has no canonical
    /// form) or when the file cannot be written.
    pub fn save<R, EP, C, S>(&self, endpoint: &Endpoint<R, EP, C, S>) -> Result<(), PortFailure>
    where
        R: Role,
        EP: Provider,
        C: KeyCustody,
        S: SdkAtomicState<EndpointState>,
    {
        let checkpoint = endpoint
            .checkpoint(&self.integrity, &self.scope[..])
            .map_err(|_| PortFailure::Unavailable)?;
        write_atomic(&self.checkpoint, checkpoint.expose_secret_bytes())
            .map_err(|_| PortFailure::Unavailable)?;
        // The high-water mark is published after the checkpoint it names: a
        // crash between them leaves a floor behind the sealed bytes, which is
        // always safe to resume.
        let generation = self.memory.load()?.revision().value();
        write_atomic(&self.generation, &generation.to_be_bytes())
            .map_err(|_| PortFailure::Unavailable)?;
        self.minimum.set(generation);
        Ok(())
    }

    /// The persisted generation floor the endpoint must not resume below.
    #[must_use]
    pub fn minimum_generation(&self) -> u64 {
        self.minimum.get()
    }
}

/// Reads the checkpoint integrity key, minting it on a fresh endpoint.
///
/// The key authenticates the checkpoint file, so it never lives inside it:
/// `dir/endpoint.integrity` holds 32 random bytes at mode `0600`, the same
/// custody claim the development custody index makes. A checkpoint without
/// its key fails closed — minting a fresh key over sealed bytes would
/// authenticate whoever placed them there.
fn integrity_key(
    path: &Path,
    checkpoint_present: bool,
) -> Result<CheckpointIntegrityKey, PortFailure> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| PortFailure::Unavailable)?;
            Ok(CheckpointIntegrityKey::from_secret_bytes(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if checkpoint_present {
                return Err(PortFailure::Unavailable);
            }
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| PortFailure::Unavailable)?;
            write_atomic(path, &bytes).map_err(|_| PortFailure::Unavailable)?;
            Ok(CheckpointIntegrityKey::from_secret_bytes(bytes))
        }
        Err(_) => Err(PortFailure::Unavailable),
    }
}

/// Reads the endpoint-scope identifier, minting it on a fresh endpoint.
///
/// The scope is the authenticated identity the checkpoint binds: it is not a
/// secret — the MAC keeps it honest — but it must be stable and unique per
/// endpoint so a blob copied from another endpoint's directory is refused.
/// `dir/endpoint.scope` holds 32 random bytes at mode `0600`; a checkpoint
/// without its scope fails closed for the same reason the integrity key does.
fn endpoint_scope(path: &Path, checkpoint_present: bool) -> Result<[u8; 32], PortFailure> {
    match std::fs::read(path) {
        Ok(bytes) => bytes.try_into().map_err(|_| PortFailure::Unavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if checkpoint_present {
                return Err(PortFailure::Unavailable);
            }
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| PortFailure::Unavailable)?;
            write_atomic(path, &bytes).map_err(|_| PortFailure::Unavailable)?;
            Ok(bytes)
        }
        Err(_) => Err(PortFailure::Unavailable),
    }
}

/// Reads the generation high-water mark paired with a checkpoint.
///
/// The mark is the anti-rollback floor `Endpoint::resume` enforces: it lives
/// outside the checkpoint so replaying older authentic bytes rewinds nothing.
/// A checkpoint without its mark fails closed — a missing mark cannot be
/// distinguished from a tampered pair.
fn generation_floor(path: &Path) -> Result<u64, PortFailure> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| PortFailure::Unavailable)?;
            Ok(u64::from_be_bytes(bytes))
        }
        Err(_) => Err(PortFailure::Unavailable),
    }
}

impl<P> AtomicState for FileState<P>
where
    P: Clone,
{
    type Snapshot = EndpointState;
    type Pending = SdkPendingItem;

    fn load(&self) -> Result<Versioned<EndpointState, SdkPendingItem>, PortFailure> {
        self.memory.load()
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: StateCommit<EndpointState, SdkPendingItem>,
    ) -> Result<Revision, PortFailure> {
        self.memory.compare_and_swap(expected, commit)
    }

    fn settle(
        &mut self,
        revision: Revision,
        pending: &SdkPendingItem,
    ) -> Result<Revision, PortFailure> {
        self.memory.settle(revision, pending)
    }
}
