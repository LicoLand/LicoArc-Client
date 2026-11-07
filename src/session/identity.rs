//! A locally minted identity: two custody-held signing keys and their public
//! descriptor.
//!
//! [`LocalIdentity`] is the standalone deployment's caller-owned identity. It
//! mints an Ed25519 and an ML-DSA-65 signing key inside [`FileCustody`], keeps
//! only their custody tokens, and derives a stable [`IdentityPublic`]. The
//! persisted form is `identity.json`: public material plus the opaque custody
//! tokens that re-resolve the private keys — never the private keys
//! themselves.
//!
//! `state_digest` and the two `key_id`s are caller-owned labels. This
//! derivation binds them deterministically to the key material, which keeps a
//! standalone responder's identity stable across restarts. LicoUp derives its
//! own digests from user-authority state and passes the same `IdentityPublic`
//! shape in.

use std::fs;
use std::io;
use std::path::Path;

use licoarc::endpoint::{IdentityPublic, IdentitySigningHandles};
use licoarc::provider::{Provider, fixed_sha256};
use licoarc::state::SecretHandle;
use serde::{Deserialize, Serialize};

use crate::ports::{CustodyPurpose, KeyCustody, PortFailure};
use crate::providers::{CustodyRefusal, FileCustody};

/// Why an identity could not be minted.
#[derive(Debug)]
pub enum MintRefusal {
    /// Custody refused to hold the fresh secrets.
    Custody(CustodyRefusal),
    /// A public key could not be read back for the descriptor.
    Readback(PortFailure),
}

impl std::fmt::Display for MintRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custody(refusal) => refusal.fmt(formatter),
            Self::Readback(failure) => write!(formatter, "custody readback failed: {failure}"),
        }
    }
}

impl std::error::Error for MintRefusal {}

/// What this process proves ownership of during a handshake.
#[derive(Clone, Debug)]
pub struct LocalIdentity {
    public: IdentityPublic,
    ed25519: u128,
    ml_dsa_65: u128,
}

impl LocalIdentity {
    /// Mints a fresh identity inside `custody`.
    ///
    /// Both signing keys enter custody adopted. The returned value holds only
    /// public material and the two custody tokens; the private keys never
    /// leave the custody backend.
    ///
    /// # Errors
    ///
    /// Returns `MintRefusal::Custody` when key generation fails and
    /// `MintRefusal::Readback` when a fresh public key cannot be read back.
    pub fn mint<P: Provider>(custody: &mut FileCustody<P>) -> Result<Self, MintRefusal> {
        let ed25519 = custody
            .adopt(CustodyPurpose::Ed25519Signing)
            .map_err(MintRefusal::Custody)?;
        let ml_dsa_65 = custody
            .adopt(CustodyPurpose::MlDsa65Signing)
            .map_err(MintRefusal::Custody)?;
        let ed25519_public = custody
            .ed25519_public(ed25519)
            .map_err(MintRefusal::Readback)?;
        let ml_dsa_65_public = custody
            .ml_dsa_65_public(ml_dsa_65)
            .map_err(MintRefusal::Readback)?;
        let ed25519_key_id = key_id(b"ed25519", &ed25519_public);
        let ml_dsa_65_key_id = key_id(b"ml-dsa-65", &ml_dsa_65_public);
        let state_digest = state_digest(
            ed25519_key_id,
            ml_dsa_65_key_id,
            &ed25519_public,
            &ml_dsa_65_public,
        );
        Ok(Self {
            public: IdentityPublic {
                state_digest,
                ed25519_key_id,
                ed25519_public,
                ml_dsa_65_key_id,
                ml_dsa_65_public,
            },
            ed25519: ed25519.custody_token(),
            ml_dsa_65: ml_dsa_65.custody_token(),
        })
    }

    /// The public descriptor presented to peers.
    #[must_use]
    pub const fn public(&self) -> &IdentityPublic {
        &self.public
    }

    /// The custody handles the SDK uses when this identity must sign.
    #[must_use]
    pub fn signing_handles(&self) -> IdentitySigningHandles {
        IdentitySigningHandles {
            ed25519: SecretHandle::from_custody_token(self.ed25519),
            ml_dsa_65: SecretHandle::from_custody_token(self.ml_dsa_65),
        }
    }

    /// Persists `identity.json` under `dir` (private to the owner, `0600`).
    ///
    /// # Errors
    ///
    /// Returns the filesystem or serialization error verbatim.
    pub fn persist(&self, dir: &Path) -> io::Result<()> {
        let file = IdentityFile {
            state_digest: hex(&self.public.state_digest),
            ed25519_key_id: hex(&self.public.ed25519_key_id),
            ed25519_public: hex(&self.public.ed25519_public),
            ml_dsa_65_key_id: hex(&self.public.ml_dsa_65_key_id),
            ml_dsa_65_public: hex(&self.public.ml_dsa_65_public),
            ed25519_token: hex(&self.ed25519.to_le_bytes()),
            ml_dsa_65_token: hex(&self.ml_dsa_65.to_le_bytes()),
        };
        let body = serde_json::to_vec_pretty(&file)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        fs::write(dir.join("identity.json"), body)
    }

    /// Loads a previously persisted identity from `dir`.
    ///
    /// Loading does not touch custody — the referenced keys must still exist
    /// under the same tokens in the deployment's own custody backend.
    ///
    /// # Errors
    ///
    /// Returns the filesystem or deserialization error verbatim.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let body = fs::read(dir.join("identity.json"))?;
        let file: IdentityFile = serde_json::from_slice(&body)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "identity.json shape");
        let mut state_digest = [0u8; 32];
        state_digest.copy_from_slice(&unhex(&file.state_digest).ok_or_else(invalid)?);
        let mut ed25519_key_id = [0u8; 32];
        ed25519_key_id.copy_from_slice(&unhex(&file.ed25519_key_id).ok_or_else(invalid)?);
        let mut ed25519_public = [0u8; 32];
        ed25519_public.copy_from_slice(&unhex(&file.ed25519_public).ok_or_else(invalid)?);
        let mut ml_dsa_65_key_id = [0u8; 32];
        ml_dsa_65_key_id.copy_from_slice(&unhex(&file.ml_dsa_65_key_id).ok_or_else(invalid)?);
        let mut ed25519 = [0u8; 16];
        ed25519.copy_from_slice(&unhex(&file.ed25519_token).ok_or_else(invalid)?);
        let mut ml_dsa_65 = [0u8; 16];
        ml_dsa_65.copy_from_slice(&unhex(&file.ml_dsa_65_token).ok_or_else(invalid)?);
        Ok(Self {
            public: IdentityPublic {
                state_digest,
                ed25519_key_id,
                ed25519_public,
                ml_dsa_65_key_id,
                ml_dsa_65_public: unhex(&file.ml_dsa_65_public).ok_or_else(invalid)?,
            },
            ed25519: u128::from_le_bytes(ed25519),
            ml_dsa_65: u128::from_le_bytes(ml_dsa_65),
        })
    }

    /// Publishes `peer-identity.json` under `dir`: the public descriptor only,
    /// safe to hand to a peer. The private custody tokens stay in
    /// `identity.json`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem or serialization error verbatim.
    pub fn persist_peer(&self, dir: &Path) -> io::Result<()> {
        let body = serde_json::to_vec_pretty(&PeerIdentityFile::of(&self.public))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        fs::write(dir.join("peer-identity.json"), body)
    }
}

/// Loads one peer's published identity from an explicit path.
///
/// The file carries only public material; trusting it is the caller's own
/// boundary (out-of-band verification, a directory, a signed roster).
///
/// # Errors
///
/// Returns the filesystem or deserialization error verbatim.
pub fn load_peer_identity(path: &Path) -> io::Result<IdentityPublic> {
    let body = fs::read(path)?;
    let file: PeerIdentityFile = serde_json::from_slice(&body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "peer identity shape");
    let mut state_digest = [0u8; 32];
    state_digest.copy_from_slice(&unhex(&file.state_digest).ok_or_else(invalid)?);
    let mut ed25519_key_id = [0u8; 32];
    ed25519_key_id.copy_from_slice(&unhex(&file.ed25519_key_id).ok_or_else(invalid)?);
    let mut ed25519_public = [0u8; 32];
    ed25519_public.copy_from_slice(&unhex(&file.ed25519_public).ok_or_else(invalid)?);
    let mut ml_dsa_65_key_id = [0u8; 32];
    ml_dsa_65_key_id.copy_from_slice(&unhex(&file.ml_dsa_65_key_id).ok_or_else(invalid)?);
    Ok(IdentityPublic {
        state_digest,
        ed25519_key_id,
        ed25519_public,
        ml_dsa_65_key_id,
        ml_dsa_65_public: unhex(&file.ml_dsa_65_public).ok_or_else(invalid)?,
    })
}

/// The shareable form of an [`IdentityPublic`]; every field is lowercase hex.
#[derive(Serialize, Deserialize)]
struct PeerIdentityFile {
    state_digest: String,
    ed25519_key_id: String,
    ed25519_public: String,
    ml_dsa_65_key_id: String,
    ml_dsa_65_public: String,
}

impl PeerIdentityFile {
    fn of(public: &IdentityPublic) -> Self {
        Self {
            state_digest: hex(&public.state_digest),
            ed25519_key_id: hex(&public.ed25519_key_id),
            ed25519_public: hex(&public.ed25519_public),
            ml_dsa_65_key_id: hex(&public.ml_dsa_65_key_id),
            ml_dsa_65_public: hex(&public.ml_dsa_65_public),
        }
    }
}

/// A caller-owned key label: deterministic and domain-separated per purpose.
fn key_id(purpose: &[u8], public: &[u8]) -> [u8; 32] {
    let mut preimage = b"licoarc-client.identity-key.v1\0".to_vec();
    preimage.extend_from_slice(purpose);
    preimage.push(0);
    preimage.extend_from_slice(public);
    fixed_sha256(&preimage)
}

/// A caller-owned identity label binding all four public facts.
fn state_digest(
    ed25519_key_id: [u8; 32],
    ml_dsa_65_key_id: [u8; 32],
    ed25519_public: &[u8; 32],
    ml_dsa_65_public: &[u8],
) -> [u8; 32] {
    let mut preimage = b"licoarc-client.identity-state.v1\0".to_vec();
    preimage.extend_from_slice(&ed25519_key_id);
    preimage.extend_from_slice(&ml_dsa_65_key_id);
    preimage.extend_from_slice(ed25519_public);
    preimage.extend_from_slice(ml_dsa_65_public);
    fixed_sha256(&preimage)
}

/// The persisted form; every field is lowercase hex.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    state_digest: String,
    ed25519_key_id: String,
    ed25519_public: String,
    ml_dsa_65_key_id: String,
    ml_dsa_65_public: String,
    ed25519_token: String,
    ml_dsa_65_token: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use licoarc::provider::fixed_provider;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "licoarc-client-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    #[test]
    fn a_minted_identity_resolves_back_through_custody() {
        let dir = temp();
        let mut custody = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        let identity = LocalIdentity::mint(&mut custody).unwrap();

        // The handles resolve to the same public keys the descriptor carries.
        let signing = identity.signing_handles();
        let handle = crate::CustodyHandle::adopted(
            signing.ed25519.custody_token(),
            CustodyPurpose::Ed25519Signing,
        );
        assert_eq!(
            custody.ed25519_public(handle).unwrap(),
            identity.public().ed25519_public
        );
        let mldsa_handle = crate::CustodyHandle::adopted(
            signing.ml_dsa_65.custody_token(),
            CustodyPurpose::MlDsa65Signing,
        );
        assert_eq!(
            custody.ml_dsa_65_public(mldsa_handle).unwrap(),
            identity.public().ml_dsa_65_public
        );

        // Two mints differ; one mint's descriptors are stable and bound.
        let other = LocalIdentity::mint(&mut custody).unwrap();
        assert_ne!(identity.public().state_digest, other.public().state_digest);
    }

    #[test]
    fn a_persisted_identity_reloads_exactly() {
        let dir = temp();
        let mut custody = FileCustody::open(dir.path(), fixed_provider()).unwrap();
        let identity = LocalIdentity::mint(&mut custody).unwrap();
        identity.persist(dir.path()).unwrap();

        let loaded = LocalIdentity::load(dir.path()).unwrap();
        assert_eq!(loaded.public(), identity.public());
        assert_eq!(loaded.ed25519, identity.ed25519);
        assert_eq!(loaded.ml_dsa_65, identity.ml_dsa_65);

        // The reloaded handles still reach custody.
        let signing = loaded.signing_handles();
        let handle = crate::CustodyHandle::adopted(
            signing.ed25519.custody_token(),
            CustodyPurpose::Ed25519Signing,
        );
        assert_eq!(
            custody.ed25519_public(handle).unwrap(),
            identity.public().ed25519_public
        );
    }
}
