//! A caller-owned [`TrustFacts`] view over explicitly registered identities.
//!
//! The SDK asks for peer identity key material by `(state_digest, purpose)`;
//! this store answers only for identities the caller registered. An unknown
//! digest is a lookup failure, not a guess — the SDK decides what the refusal
//! means for the handshake.
//!
//! A standalone deployment seeds the store from the peer's pairing offer.
//! LicoUp supplies its own richer trust view through the same port.

use std::collections::BTreeMap;

use licoarc::endpoint::IdentityPublic;
use licoarc::error::{Error, ErrorCode, Stage};
use licoarc::state::TrustFacts;

/// Resolves identity key material for explicitly registered identities.
#[derive(Clone, Debug, Default)]
pub struct StaticTrust {
    identities: BTreeMap<[u8; 32], IdentityPublic>,
}

impl StaticTrust {
    /// An empty view: every peer lookup fails until `register` runs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts exactly one identity, indexed by its own state digest.
    ///
    /// Registering another identity under an existing digest replaces it —
    /// the caller owns that decision.
    pub fn register(&mut self, identity: IdentityPublic) -> &mut Self {
        self.identities.insert(identity.state_digest, identity);
        self
    }

    /// A view trusting only `identity`.
    #[must_use]
    pub fn for_identity(identity: &IdentityPublic) -> Self {
        let mut trust = Self::new();
        trust.register(identity.clone());
        trust
    }
}

impl TrustFacts for StaticTrust {
    fn identity_key(
        &self,
        identity: &[u8; 32],
        purpose: &'static str,
        _profile: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        let missing = || Error::terminal(ErrorCode::ProviderFailure, Stage::Validation);
        let entry = self.identities.get(identity).ok_or_else(missing)?;
        match purpose {
            "ed25519-key-id" => Ok(entry.ed25519_key_id.to_vec()),
            "ed25519-public" => Ok(entry.ed25519_public.to_vec()),
            "ml-dsa-65-key-id" => Ok(entry.ml_dsa_65_key_id.to_vec()),
            "ml-dsa-65-public" => Ok(entry.ml_dsa_65_public.clone()),
            _ => Err(missing()),
        }
    }
}

#[cfg(test)]
mod tests {
    use licoarc::provider::ML_DSA_65_PUBLIC_KEY_BYTES;

    use super::*;

    fn identity(seed: u8) -> IdentityPublic {
        IdentityPublic {
            state_digest: [seed; 32],
            ed25519_key_id: [seed + 1; 32],
            ed25519_public: [seed + 2; 32],
            ml_dsa_65_key_id: [seed + 3; 32],
            ml_dsa_65_public: vec![seed + 4; ML_DSA_65_PUBLIC_KEY_BYTES],
        }
    }

    #[test]
    fn registered_identities_answer_every_purpose() {
        let peer = identity(10);
        let mut trust = StaticTrust::new();
        trust.register(peer.clone());
        let digest = peer.state_digest;
        assert_eq!(
            trust
                .identity_key(&digest, "ed25519-key-id", &[0; 32])
                .unwrap(),
            peer.ed25519_key_id.to_vec()
        );
        assert_eq!(
            trust
                .identity_key(&digest, "ed25519-public", &[0; 32])
                .unwrap(),
            peer.ed25519_public.to_vec()
        );
        assert_eq!(
            trust
                .identity_key(&digest, "ml-dsa-65-key-id", &[0; 32])
                .unwrap(),
            peer.ml_dsa_65_key_id.to_vec()
        );
        assert_eq!(
            trust
                .identity_key(&digest, "ml-dsa-65-public", &[0; 32])
                .unwrap(),
            peer.ml_dsa_65_public
        );
        assert!(trust.identity_key(&digest, "unknown", &[0; 32]).is_err());
    }

    #[test]
    fn unknown_digests_and_unregistered_peers_are_refused() {
        let trust = StaticTrust::new();
        assert!(
            trust
                .identity_key(&[0; 32], "ed25519-public", &[0; 32])
                .is_err()
        );
        let peer = identity(10);
        let mut trust = StaticTrust::for_identity(&peer);
        assert!(
            trust
                .identity_key(&[99; 32], "ed25519-public", &[0; 32])
                .is_err()
        );
        trust.register(identity(20));
        assert!(
            trust
                .identity_key(&[20; 32], "ed25519-public", &[0; 32])
                .is_ok()
        );
    }
}
