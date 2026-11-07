//! File-backed [`KeyCustody`] for the standalone CLI.
//!
//! One index file holds every custody object: `{token → purpose, lifecycle,
//! secret bytes}`. Every mutation serializes the complete table to a sibling
//! temporary file and renames it over the index, so a custody change is either
//! the whole new index or the whole old one — the same old-or-new contract
//! `AtomicState` requires, at the granularity one file can give.
//!
//! The secrets on disk are raw seed bytes protected only by file mode `0600`.
//! That is a development custody backend for the standalone client, not a
//! product keystore: consumers with a real custody requirement (LicoUp's
//! keychain custody, for example) implement [`KeyCustody`] themselves.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use licoarc::provider::{AgreementProvider, SignatureProvider};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ports::{CustodyHandle, CustodyLifecycle, CustodyPurpose, KeyMutation, PortFailure};

/// One custody object: the secret the token names, plus the purpose and
/// lifecycle every operation re-checks.
#[derive(Serialize, Deserialize)]
struct Object {
    token: String,
    purpose: String,
    lifecycle: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct Index {
    objects: Vec<Object>,
}

/// The table one index file commits.
#[derive(Default)]
struct Table {
    objects: BTreeMap<u128, Entry>,
}

struct Entry {
    purpose: CustodyPurpose,
    lifecycle: CustodyLifecycle,
    secret: Zeroizing<Vec<u8>>,
}

/// What the filesystem refused, mapped onto the port's vocabulary.
pub enum CustodyRefusal {
    /// The index could not be read, written, or parsed.
    Store(std::io::Error),
    /// Entropy could not be drawn for a new secret.
    Entropy,
    /// The caller asked an operation for a purpose it does not serve.
    InvalidPurpose,
}

impl fmt::Debug for CustodyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => formatter
                .debug_tuple("CustodyRefusal::Store")
                .field(&error.kind())
                .finish(),
            Self::Entropy => formatter.write_str("CustodyRefusal::Entropy"),
            Self::InvalidPurpose => formatter.write_str("CustodyRefusal::InvalidPurpose"),
        }
    }
}

impl fmt::Display for CustodyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(_) => formatter.write_str("custody store unavailable"),
            Self::Entropy => formatter.write_str("entropy unavailable"),
            Self::InvalidPurpose => {
                formatter.write_str("purpose not admitted for this custody operation")
            }
        }
    }
}

impl std::error::Error for CustodyRefusal {}

/// A [`KeyCustody`] whose objects live in one atomically replaced index file.
///
/// `Clone` shares the same table and the same file, so a coupled
/// [`crate::providers::MemoryState`] and the adapter's own custody view always
/// see one consistent backend.
pub struct FileCustody<P> {
    table: Rc<RefCell<Table>>,
    index: PathBuf,
    provider: Rc<P>,
}

impl<P> Clone for FileCustody<P> {
    fn clone(&self) -> Self {
        Self {
            table: Rc::clone(&self.table),
            index: self.index.clone(),
            provider: Rc::clone(&self.provider),
        }
    }
}

impl<P> FileCustody<P> {
    /// Opens (or creates on first mutation) the index at `dir/custody.index`.
    ///
    /// A malformed index fails closed: the caller must not run on a custody
    /// set it cannot name exactly.
    pub fn open(dir: &Path, provider: P) -> Result<Self, CustodyRefusal> {
        let index = dir.join("custody.index");
        let table = match std::fs::read(&index) {
            Ok(bytes) => decode_index(&Zeroizing::new(bytes)[..])?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Table::default(),
            Err(error) => return Err(CustodyRefusal::Store(error)),
        };
        Ok(Self {
            table: Rc::new(RefCell::new(table)),
            index,
            provider: Rc::new(provider),
        })
    }

    /// The crypto provider this custody delegates key operations to.
    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Inserts one fresh adopted secret of `purpose`.
    ///
    /// Signing identities and encapsulation entropy enter custody adopted:
    /// the protocol never stages them, so there is no later adoption step.
    pub fn adopt(&mut self, purpose: CustodyPurpose) -> Result<CustodyHandle, CustodyRefusal> {
        let staged = matches!(
            purpose,
            CustodyPurpose::X25519Private | CustodyPurpose::MlKem768Private
        );
        if staged {
            return Err(CustodyRefusal::InvalidPurpose);
        }
        self.insert(purpose, CustodyLifecycle::Adopted)
    }

    /// Inserts one fresh staged private secret (X25519 or ML-KEM-768).
    ///
    /// Staged secrets are tentative: a later `KeyMutation::Adopt` in a state
    /// commit makes them reachable, and `abort_*` makes them unreachable.
    pub fn stage(&mut self, purpose: CustodyPurpose) -> Result<CustodyHandle, CustodyRefusal> {
        let adoptable = matches!(
            purpose,
            CustodyPurpose::X25519Private | CustodyPurpose::MlKem768Private
        );
        if !adoptable {
            return Err(CustodyRefusal::InvalidPurpose);
        }
        self.insert(purpose, CustodyLifecycle::Staged)
    }

    fn insert(
        &mut self,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<CustodyHandle, CustodyRefusal> {
        let mut secret = Zeroizing::new(vec![0_u8; secret_bytes(purpose)]);
        getrandom::fill(&mut secret[..]).map_err(|_| CustodyRefusal::Entropy)?;
        let mut token_bytes = [0_u8; 16];
        getrandom::fill(&mut token_bytes).map_err(|_| CustodyRefusal::Entropy)?;
        let token = u128::from_le_bytes(token_bytes);
        let handle = match lifecycle {
            CustodyLifecycle::Adopted => CustodyHandle::adopted(token, purpose),
            CustodyLifecycle::Staged => CustodyHandle::staged(token, purpose),
        };
        let mut next = self.table.borrow().clone_objects();
        next.objects.insert(
            token,
            Entry {
                purpose,
                lifecycle,
                secret,
            },
        );
        let mut table = self.table.borrow_mut();
        persist(&self.index, &next)?;
        table.objects = next.objects;
        Ok(handle)
    }

    /// Applies one commit's custody mutations atomically.
    ///
    /// A coupled store calls this inside `compare_and_swap`: every mutation is
    /// validated and applied to a tentative table first, so a refused mutation
    /// — wrong purpose, absent or wrong-lifecycle object — changes nothing,
    /// and the persisted index only ever carries the whole applied set.
    pub fn apply_mutations(&mut self, mutations: &[KeyMutation]) -> Result<(), PortFailure> {
        let mut next = self.table.borrow().clone_objects();
        for mutation in mutations {
            match mutation {
                KeyMutation::Adopt(handle) => {
                    let purpose = handle.purpose();
                    if !matches!(
                        purpose,
                        CustodyPurpose::X25519Private | CustodyPurpose::MlKem768Private
                    ) {
                        return Err(PortFailure::Unavailable);
                    }
                    let entry = next
                        .objects
                        .get_mut(&handle.custody_token())
                        .filter(|entry| {
                            entry.purpose == purpose && entry.lifecycle == CustodyLifecycle::Staged
                        })
                        .ok_or(PortFailure::Unavailable)?;
                    entry.lifecycle = CustodyLifecycle::Adopted;
                }
                KeyMutation::Delete(handle) => {
                    let purpose = handle.purpose();
                    if !matches!(
                        purpose,
                        CustodyPurpose::X25519Private
                            | CustodyPurpose::MlKem768Private
                            | CustodyPurpose::MlKemEncapsulationEntropy
                    ) {
                        return Err(PortFailure::Unavailable);
                    }
                    match next.objects.get(&handle.custody_token()) {
                        Some(entry)
                            if entry.purpose == purpose
                                && entry.lifecycle == CustodyLifecycle::Adopted =>
                        {
                            next.objects.remove(&handle.custody_token());
                        }
                        _ => return Err(PortFailure::Unavailable),
                    }
                }
            }
        }
        let mut table = self.table.borrow_mut();
        persist(&self.index, &next).map_err(|_| PortFailure::Unavailable)?;
        table.objects = next.objects;
        Ok(())
    }

    /// Looks up one handle's secret after re-checking purpose and lifecycle
    /// — the handle's own claims are never proof.
    fn secret(
        &self,
        handle: CustodyHandle,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<Zeroizing<Vec<u8>>, PortFailure> {
        let table = self.table.borrow();
        let entry = table
            .objects
            .get(&handle.custody_token())
            .filter(|entry| entry.purpose == purpose && entry.lifecycle == lifecycle)
            .filter(|_| handle.purpose() == purpose && handle.lifecycle() == lifecycle)
            .ok_or(PortFailure::Unavailable)?;
        Ok(entry.secret.clone())
    }

    fn private(
        &self,
        handle: CustodyHandle,
        purpose: CustodyPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, PortFailure> {
        self.secret(handle, purpose, handle.lifecycle())
    }

    fn adopted_secret(
        &self,
        handle: CustodyHandle,
        purpose: CustodyPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, PortFailure> {
        self.secret(handle, purpose, CustodyLifecycle::Adopted)
    }

    fn abort(&mut self, staged: CustodyHandle, purpose: CustodyPurpose) {
        let token = staged.custody_token();
        let mut next = self.table.borrow().clone_objects();
        let staged_present = next.objects.get(&token).is_some_and(|entry| {
            entry.purpose == purpose && entry.lifecycle == CustodyLifecycle::Staged
        });
        if !staged_present {
            return;
        }
        next.objects.remove(&token);
        let mut table = self.table.borrow_mut();
        if persist(&self.index, &next).is_ok() {
            table.objects = next.objects;
        }
    }
}

impl<P> crate::adapters::CustodyHandles for FileCustody<P> {
    /// The SDK's token names a real custody object only when the stored
    /// purpose and lifecycle match exactly what the adapter asserts.
    fn custody_handle(
        &self,
        token: u128,
        purpose: CustodyPurpose,
        lifecycle: CustodyLifecycle,
    ) -> Result<CustodyHandle, PortFailure> {
        let table = self.table.borrow();
        let entry = table.objects.get(&token).ok_or(PortFailure::Unavailable)?;
        if entry.purpose != purpose || entry.lifecycle != lifecycle {
            return Err(PortFailure::Unavailable);
        }
        Ok(match lifecycle {
            CustodyLifecycle::Adopted => CustodyHandle::adopted(token, purpose),
            CustodyLifecycle::Staged => CustodyHandle::staged(token, purpose),
        })
    }
}

impl Table {
    fn clone_objects(&self) -> Self {
        Self {
            objects: self
                .objects
                .iter()
                .map(|(token, entry)| {
                    (
                        *token,
                        Entry {
                            purpose: entry.purpose,
                            lifecycle: entry.lifecycle,
                            secret: Zeroizing::new(entry.secret.to_vec()),
                        },
                    )
                })
                .collect(),
        }
    }
}

fn secret_bytes(purpose: CustodyPurpose) -> usize {
    match purpose {
        CustodyPurpose::Ed25519Signing
        | CustodyPurpose::MlDsa65Signing
        | CustodyPurpose::X25519Private
        | CustodyPurpose::MlKemEncapsulationEntropy => 32,
        CustodyPurpose::MlKem768Private => 64,
    }
}

fn purpose_name(purpose: CustodyPurpose) -> &'static str {
    match purpose {
        CustodyPurpose::Ed25519Signing => "ed25519-signing",
        CustodyPurpose::MlDsa65Signing => "ml-dsa-65-signing",
        CustodyPurpose::X25519Private => "x25519-private",
        CustodyPurpose::MlKem768Private => "ml-kem-768-private",
        CustodyPurpose::MlKemEncapsulationEntropy => "ml-kem-encapsulation-entropy",
    }
}

fn name_purpose(name: &str) -> Option<CustodyPurpose> {
    Some(match name {
        "ed25519-signing" => CustodyPurpose::Ed25519Signing,
        "ml-dsa-65-signing" => CustodyPurpose::MlDsa65Signing,
        "x25519-private" => CustodyPurpose::X25519Private,
        "ml-kem-768-private" => CustodyPurpose::MlKem768Private,
        "ml-kem-encapsulation-entropy" => CustodyPurpose::MlKemEncapsulationEntropy,
        _ => return None,
    })
}

fn name_lifecycle(name: &str) -> Option<CustodyLifecycle> {
    Some(match name {
        "adopted" => CustodyLifecycle::Adopted,
        "staged" => CustodyLifecycle::Staged,
        _ => return None,
    })
}

fn encode_index(table: &Table) -> Zeroizing<Vec<u8>> {
    let objects = table
        .objects
        .iter()
        .map(|(token, entry)| Object {
            token: hex(&token.to_le_bytes()),
            purpose: purpose_name(entry.purpose).to_owned(),
            lifecycle: match entry.lifecycle {
                CustodyLifecycle::Adopted => "adopted".to_owned(),
                CustodyLifecycle::Staged => "staged".to_owned(),
            },
            secret: hex(&entry.secret),
        })
        .collect();
    Zeroizing::new(serde_json::to_vec(&Index { objects }).expect("the index shape serializes"))
}

fn decode_index(bytes: &[u8]) -> Result<Table, CustodyRefusal> {
    let index: Index = serde_json::from_slice(bytes).map_err(|error| {
        CustodyRefusal::Store(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })?;
    let mut table = Table::default();
    let malformed = || {
        CustodyRefusal::Store(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "custody index object malformed",
        ))
    };
    for object in index.objects {
        let token_bytes = unhex(&object.token).ok_or_else(malformed)?;
        let token_array = <[u8; 16]>::try_from(token_bytes.as_slice()).map_err(|_| malformed())?;
        let token = u128::from_le_bytes(token_array);
        let purpose = name_purpose(&object.purpose).ok_or_else(malformed)?;
        let lifecycle = name_lifecycle(&object.lifecycle).ok_or_else(malformed)?;
        let secret = unhex(&object.secret).ok_or_else(malformed)?;
        if secret.len() != secret_bytes(purpose) {
            return Err(malformed());
        }
        table.objects.insert(
            token,
            Entry {
                purpose,
                lifecycle,
                secret: secret.into(),
            },
        );
    }
    Ok(table)
}

/// Atomically publishes `table`: temporary sibling, fsync, rename.
fn persist(index: &Path, table: &Table) -> Result<(), CustodyRefusal> {
    write_atomic(index, &encode_index(table)[..]).map_err(CustodyRefusal::Store)
}

/// Atomically publishes `bytes` at `path`: temporary sibling, fsync, rename,
/// mode `0600` on unix. Shared by the custody index and the endpoint
/// checkpoint file.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        {
            // `mode` only applies at creation; pin it on the live file so a
            // stale temp never widens a secret's permissions.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    bytes
        .chunks_exact(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

impl<P> crate::ports::KeyCustody for FileCustody<P>
where
    P: AgreementProvider + SignatureProvider,
{
    fn ed25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        let seed = self.adopted_secret(handle, CustodyPurpose::Ed25519Signing)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.ed25519_public(&seed))
    }

    fn ed25519_sign(&self, handle: CustodyHandle, message: &[u8]) -> Result<[u8; 64], PortFailure> {
        let seed = self.adopted_secret(handle, CustodyPurpose::Ed25519Signing)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.ed25519_sign(&seed, message))
    }

    fn ml_dsa_65_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        let seed = self.adopted_secret(handle, CustodyPurpose::MlDsa65Signing)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.ml_dsa_65_public(&seed))
    }

    fn ml_dsa_65_sign(
        &self,
        handle: CustodyHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, PortFailure> {
        let seed = self.adopted_secret(handle, CustodyPurpose::MlDsa65Signing)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.ml_dsa_65_sign(&seed, message))
    }

    fn x25519_public(&self, handle: CustodyHandle) -> Result<[u8; 32], PortFailure> {
        let private = self.private(handle, CustodyPurpose::X25519Private)?;
        let private: Zeroizing<[u8; 32]> = Zeroizing::new(
            private
                .as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.x25519_public(&private))
    }

    fn x25519(&self, handle: CustodyHandle, public: &[u8; 32]) -> Result<[u8; 32], PortFailure> {
        let private = self.private(handle, CustodyPurpose::X25519Private)?;
        let private: Zeroizing<[u8; 32]> = Zeroizing::new(
            private
                .as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        self.provider
            .x25519(&private, public)
            .map_err(|_| PortFailure::Unavailable)
    }

    fn ml_kem_768_public(&self, handle: CustodyHandle) -> Result<Vec<u8>, PortFailure> {
        let seed = self.private(handle, CustodyPurpose::MlKem768Private)?;
        let seed: Zeroizing<[u8; 64]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        Ok(self.provider.ml_kem_768_public(&seed))
    }

    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: CustodyHandle,
    ) -> Result<(Vec<u8>, [u8; 32]), PortFailure> {
        let seed = self.adopted_secret(entropy, CustodyPurpose::MlKemEncapsulationEntropy)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        self.provider
            .ml_kem_768_encapsulate(public, &seed)
            .map_err(|_| PortFailure::Unavailable)
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: CustodyHandle,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], PortFailure> {
        let seed = self.private(handle, CustodyPurpose::MlKem768Private)?;
        let seed: Zeroizing<[u8; 64]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| PortFailure::Unavailable)?,
        );
        self.provider
            .ml_kem_768_decapsulate(&seed, ciphertext)
            .map_err(|_| PortFailure::Unavailable)
    }

    fn abort_x25519(&mut self, staged: CustodyHandle) {
        self.abort(staged, CustodyPurpose::X25519Private);
    }

    fn abort_ml_kem_768(&mut self, staged: CustodyHandle) {
        self.abort(staged, CustodyPurpose::MlKem768Private);
    }
}

#[cfg(test)]
mod tests {
    use licoarc::provider::fixed_provider;

    use super::FileCustody;
    use crate::ports::{CustodyPurpose, KeyCustody, KeyMutation};

    fn custody() -> (
        temp_dir::TempDir,
        FileCustody<impl licoarc::provider::Provider>,
    ) {
        let dir = temp_dir::dir();
        let custody = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        (dir, custody)
    }

    /// A unique empty directory per test, removed on drop.
    mod temp_dir {
        use std::path::{Path, PathBuf};

        #[derive(Clone)]
        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        pub fn dir() -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "licoarc-client-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn adopted_secrets_persist_across_reopen() {
        let (dir, mut custody) = custody();
        let handle = custody.adopt(CustodyPurpose::Ed25519Signing).unwrap();
        let public = custody.ed25519_public(handle).unwrap();
        drop(custody);

        let reopened = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        assert_eq!(reopened.ed25519_public(handle).unwrap(), public);
    }

    #[test]
    fn signing_and_agreement_use_the_persisted_secret() {
        let (_dir, mut custody) = custody();
        let ed = custody.adopt(CustodyPurpose::Ed25519Signing).unwrap();
        assert_eq!(custody.ed25519_sign(ed, b"msg").unwrap().len(), 64);
        let dsa = custody.adopt(CustodyPurpose::MlDsa65Signing).unwrap();
        assert!(!custody.ml_dsa_65_sign(dsa, b"msg").unwrap().is_empty());
        let x = custody.stage(CustodyPurpose::X25519Private).unwrap();
        let public = custody.x25519_public(x).unwrap();
        assert_eq!(custody.x25519(x, &public).unwrap().len(), 32);
        let kem = custody.stage(CustodyPurpose::MlKem768Private).unwrap();
        let enc_public = custody.ml_kem_768_public(kem).unwrap();
        let entropy = custody
            .adopt(CustodyPurpose::MlKemEncapsulationEntropy)
            .unwrap();
        let (ciphertext, _shared) = custody
            .ml_kem_768_encapsulate(&enc_public, entropy)
            .unwrap();
        assert_eq!(
            custody
                .ml_kem_768_decapsulate(kem, &ciphertext)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn mutations_apply_atomically_or_not_at_all() {
        let (dir, mut custody) = custody();
        let staged = custody.stage(CustodyPurpose::X25519Private).unwrap();
        let missing = crate::ports::CustodyHandle::staged(99, CustodyPurpose::X25519Private);
        assert!(
            custody
                .apply_mutations(&[KeyMutation::Adopt(staged), KeyMutation::Adopt(missing),])
                .is_err(),
            "a refused member must void the whole mutation set"
        );
        let mut reopened = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        // The valid adoption must not have persisted either: the object is
        // still staged, and deleting it requires Adopted.
        assert!(
            reopened
                .apply_mutations(&[KeyMutation::Delete(staged)])
                .is_err(),
            "a voided set must leave the staged object staged"
        );
        drop(reopened);

        custody
            .apply_mutations(&[KeyMutation::Adopt(staged)])
            .unwrap();
        let reopened = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        // Adoption spends the staged handle: the adopted handle naming the
        // same token is what operations accept now.
        let adopted =
            crate::ports::CustodyHandle::adopted(staged.custody_token(), staged.purpose());
        assert!(reopened.x25519_public(adopted).is_ok());
        assert!(reopened.x25519_public(staged).is_err());
    }

    #[test]
    fn abort_removes_only_the_staged_object() {
        let (_dir, mut custody) = custody();
        let staged = custody.stage(CustodyPurpose::MlKem768Private).unwrap();
        custody.abort_ml_kem_768(staged);
        assert!(custody.ml_kem_768_public(staged).is_err());
    }
}
