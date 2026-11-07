//! The responder's published pairing material.
//!
//! A [`PairingOffer`] is what one responder publishes out of band so an
//! initiator can build a `FirstPacket`: the responder's public identity, one
//! freshly staged [`PrekeyBundle`], the bootstrap handle the initiator must
//! submit to, and the responder's user-authority state digest at publication
//! time.
//!
//! The wire form is canonical CBOR; the same fields are validated on decode
//! with the bounds the SDK's own handshake enforces (fixed field counts,
//! byte-length caps, an ordered validity window, `pair_sequence >= 1`). No
//! secret material ever appears in an offer.

use std::collections::BTreeMap;

use licoarc::encoding::{self, CborValue};
use licoarc::endpoint::{IdentityPublic, PrekeyBundle};
use licoarc::provider::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
};

use crate::HandleToken;

/// The responder's published material for one pairing attempt.
#[derive(Clone, Debug)]
pub struct PairingOffer {
    /// The responder's public identity descriptor.
    pub identity: IdentityPublic,
    /// One freshly staged prekey bundle signed by that identity.
    pub prekey: PrekeyBundle,
    /// The bootstrap handle the initiator submits its `FirstPacket` to.
    pub handle: HandleToken,
    /// The responder's user-authority state digest at publication time.
    pub responder_authority_state_digest: [u8; 32],
}

/// Why a decoded offer cannot be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfferRefusal;

impl std::fmt::Display for OfferRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("malformed pairing offer")
    }
}

impl std::error::Error for OfferRefusal {}

/// `PrekeyBundle` bounds must hold before a decoded offer is admitted.
const PREKEY_MAX_VALIDITY_SECONDS: u64 = 604_800;
/// An offer is public material bounded by its largest members.
const MAX_OFFER_BYTES: usize = 16 * 1024;

fn map(entries: impl IntoIterator<Item = (u64, CborValue)>) -> CborValue {
    CborValue::Map(BTreeMap::from_iter(entries))
}

fn bytes(value: &[u8]) -> CborValue {
    CborValue::Bytes(value.to_vec())
}

fn bytes32(value: &[u8; 32]) -> CborValue {
    CborValue::Bytes(value.to_vec())
}

fn uint(value: u64) -> CborValue {
    CborValue::Unsigned(value)
}

fn identity_value(identity: &IdentityPublic) -> CborValue {
    map([
        (0, bytes32(&identity.state_digest)),
        (1, bytes32(&identity.ed25519_key_id)),
        (2, bytes32(&identity.ed25519_public)),
        (3, bytes32(&identity.ml_dsa_65_key_id)),
        (4, bytes(&identity.ml_dsa_65_public)),
    ])
}

fn prekey_value(prekey: &PrekeyBundle) -> CborValue {
    map([
        (0, bytes32(&prekey.protocol_line_id)),
        (1, bytes32(&prekey.protection_profile_id)),
        (2, bytes32(&prekey.responder_identity_state_digest)),
        (3, bytes32(&prekey.ed25519_key_id)),
        (4, bytes32(&prekey.ml_dsa_65_key_id)),
        (5, uint(prekey.pair_sequence)),
        (6, bytes32(&prekey.x25519_public)),
        (7, bytes(&prekey.ml_kem_768_public)),
        (8, uint(prekey.valid_from)),
        (9, uint(prekey.valid_until)),
        (10, bytes(&prekey.ed25519_signature)),
        (11, bytes(&prekey.ml_dsa_65_signature)),
    ])
}

fn exact_map<'a>(
    value: &'a CborValue,
    keys: &[u64],
) -> Result<&'a BTreeMap<u64, CborValue>, OfferRefusal> {
    let CborValue::Map(map) = value else {
        return Err(OfferRefusal);
    };
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(key)) {
        return Err(OfferRefusal);
    }
    Ok(map)
}

fn at(map: &BTreeMap<u64, CborValue>, key: u64) -> Result<&CborValue, OfferRefusal> {
    map.get(&key).ok_or(OfferRefusal)
}

fn as_bytes(value: &CborValue, length: usize) -> Result<Vec<u8>, OfferRefusal> {
    let CborValue::Bytes(bytes) = value else {
        return Err(OfferRefusal);
    };
    if bytes.len() != length {
        return Err(OfferRefusal);
    }
    Ok(bytes.clone())
}

fn as_bytes32(value: &CborValue) -> Result<[u8; 32], OfferRefusal> {
    let bytes = as_bytes(value, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn as_bytes64(value: &CborValue) -> Result<[u8; 64], OfferRefusal> {
    let bytes = as_bytes(value, 64)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn as_uint(value: &CborValue) -> Result<u64, OfferRefusal> {
    let CborValue::Unsigned(unsigned) = value else {
        return Err(OfferRefusal);
    };
    Ok(*unsigned)
}

fn decode_identity(value: &CborValue) -> Result<IdentityPublic, OfferRefusal> {
    let map = exact_map(value, &[0, 1, 2, 3, 4])?;
    let ml_dsa_65_public = match at(map, 4)? {
        CborValue::Bytes(bytes) if bytes.len() == ML_DSA_65_PUBLIC_KEY_BYTES => bytes.clone(),
        _ => return Err(OfferRefusal),
    };
    Ok(IdentityPublic {
        state_digest: as_bytes32(at(map, 0)?)?,
        ed25519_key_id: as_bytes32(at(map, 1)?)?,
        ed25519_public: as_bytes32(at(map, 2)?)?,
        ml_dsa_65_key_id: as_bytes32(at(map, 3)?)?,
        ml_dsa_65_public,
    })
}

fn decode_prekey(value: &CborValue) -> Result<PrekeyBundle, OfferRefusal> {
    let map = exact_map(value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
    let ml_kem_768_public = match at(map, 7)? {
        CborValue::Bytes(bytes) if bytes.len() == ML_KEM_768_PUBLIC_KEY_BYTES => bytes.clone(),
        _ => return Err(OfferRefusal),
    };
    let ml_dsa_65_signature = match at(map, 11)? {
        CborValue::Bytes(bytes) if bytes.len() == ML_DSA_65_SIGNATURE_BYTES => bytes.clone(),
        _ => return Err(OfferRefusal),
    };
    let prekey = PrekeyBundle {
        protocol_line_id: as_bytes32(at(map, 0)?)?,
        protection_profile_id: as_bytes32(at(map, 1)?)?,
        responder_identity_state_digest: as_bytes32(at(map, 2)?)?,
        ed25519_key_id: as_bytes32(at(map, 3)?)?,
        ml_dsa_65_key_id: as_bytes32(at(map, 4)?)?,
        pair_sequence: as_uint(at(map, 5)?)?,
        x25519_public: as_bytes32(at(map, 6)?)?,
        ml_kem_768_public,
        valid_from: as_uint(at(map, 8)?)?,
        valid_until: as_uint(at(map, 9)?)?,
        ed25519_signature: as_bytes64(at(map, 10)?)?,
        ml_dsa_65_signature,
    };
    // The SDK refuses an out-of-window bundle during admission; refuse the
    // same shape here so a malformed offer never reaches the handshake.
    if prekey.pair_sequence == 0
        || prekey.valid_from >= prekey.valid_until
        || prekey.valid_until - prekey.valid_from > PREKEY_MAX_VALIDITY_SECONDS
    {
        return Err(OfferRefusal);
    }
    Ok(prekey)
}

impl PairingOffer {
    /// The canonical-CBOR publication form.
    ///
    /// # Errors
    ///
    /// Returns `OfferRefusal` when the encoding itself fails — unreachable for
    /// well-typed fields, so it is structural only.
    pub fn encode(&self) -> Result<Vec<u8>, OfferRefusal> {
        encoding::encode(&map([
            (0, identity_value(&self.identity)),
            (1, prekey_value(&self.prekey)),
            (2, bytes(self.handle.as_bytes())),
            (3, bytes32(&self.responder_authority_state_digest)),
        ]))
        .map_err(|_| OfferRefusal)
    }

    /// Decodes one offer, applying the SDK's own field and window bounds.
    ///
    /// # Errors
    ///
    /// Returns `OfferRefusal` for any malformed, oversized, or out-of-window
    /// document.
    pub fn decode(bytes: &[u8]) -> Result<Self, OfferRefusal> {
        if bytes.is_empty() || bytes.len() > MAX_OFFER_BYTES {
            return Err(OfferRefusal);
        }
        let value = encoding::decode(bytes).map_err(|_| OfferRefusal)?;
        let map = exact_map(&value, &[0, 1, 2, 3])?;
        let identity = decode_identity(at(map, 0)?)?;
        let prekey = decode_prekey(at(map, 1)?)?;
        // The bundle must name the identity that signed it; a mismatch is a
        // malformed offer, not a handshake question.
        if prekey.responder_identity_state_digest != identity.state_digest {
            return Err(OfferRefusal);
        }
        Ok(Self {
            identity,
            prekey,
            handle: HandleToken::from_bytes(as_bytes32(at(map, 2)?)?),
            responder_authority_state_digest: as_bytes32(at(map, 3)?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use licoarc::provider::{
        ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
    };

    fn identity() -> IdentityPublic {
        IdentityPublic {
            state_digest: [1; 32],
            ed25519_key_id: [2; 32],
            ed25519_public: [3; 32],
            ml_dsa_65_key_id: [4; 32],
            ml_dsa_65_public: vec![5; ML_DSA_65_PUBLIC_KEY_BYTES],
        }
    }

    fn prekey() -> PrekeyBundle {
        PrekeyBundle {
            protocol_line_id: [6; 32],
            protection_profile_id: [7; 32],
            responder_identity_state_digest: [1; 32],
            ed25519_key_id: [2; 32],
            ml_dsa_65_key_id: [4; 32],
            pair_sequence: 1,
            x25519_public: [8; 32],
            ml_kem_768_public: vec![9; ML_KEM_768_PUBLIC_KEY_BYTES],
            valid_from: 100,
            valid_until: 200,
            ed25519_signature: [10; 64],
            ml_dsa_65_signature: vec![11; ML_DSA_65_SIGNATURE_BYTES],
        }
    }

    fn fixture() -> PairingOffer {
        PairingOffer {
            identity: identity(),
            prekey: prekey(),
            handle: HandleToken::from_bytes([12; 32]),
            responder_authority_state_digest: [13; 32],
        }
    }

    #[test]
    fn offer_roundtrips_every_field() {
        let offer = fixture();
        let decoded = PairingOffer::decode(&offer.encode().unwrap()).unwrap();
        assert_eq!(decoded.identity, offer.identity);
        assert_eq!(decoded.prekey, offer.prekey);
        assert_eq!(decoded.handle, offer.handle);
        assert_eq!(
            decoded.responder_authority_state_digest,
            offer.responder_authority_state_digest
        );
    }

    #[test]
    fn malformed_offers_are_refused() {
        assert_eq!(PairingOffer::decode(b"").unwrap_err(), OfferRefusal,);
        assert_eq!(PairingOffer::decode(b"not cbor").unwrap_err(), OfferRefusal,);
        // Truncated mid-document.
        let body = fixture().encode().unwrap();
        assert_eq!(
            PairingOffer::decode(&body[..body.len() - 3]).unwrap_err(),
            OfferRefusal,
        );
    }

    #[test]
    fn a_prekey_outside_the_window_is_refused() {
        let mut offer = fixture();
        offer.prekey.valid_from = offer.prekey.valid_until;
        assert_eq!(
            PairingOffer::decode(&offer.encode().unwrap()).unwrap_err(),
            OfferRefusal,
        );
        let mut offer = fixture();
        offer.prekey.valid_until = offer.prekey.valid_from + 604_801;
        assert_eq!(
            PairingOffer::decode(&offer.encode().unwrap()).unwrap_err(),
            OfferRefusal,
        );
        let mut offer = fixture();
        offer.prekey.pair_sequence = 0;
        assert_eq!(
            PairingOffer::decode(&offer.encode().unwrap()).unwrap_err(),
            OfferRefusal,
        );
    }

    #[test]
    fn a_prekey_binding_another_identity_is_refused() {
        let mut offer = fixture();
        offer.prekey.responder_identity_state_digest = [99; 32];
        assert_eq!(
            PairingOffer::decode(&offer.encode().unwrap()).unwrap_err(),
            OfferRefusal,
        );
    }
}
