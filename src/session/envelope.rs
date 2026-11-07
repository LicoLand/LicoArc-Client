//! Pairing control envelopes carried *inside* station payloads.
//!
//! The SDK's `FirstPacket` and `SessionAccept` carry no return-address field —
//! a Station handle is transport addressing, not protocol content — so the
//! client binds each protocol document to the handle it answers through:
//!
//! - [`PairingSubmission`] `{0: firstPacketBytes, 1: replyHandle}`: the
//!   initiator's `FirstPacket` (SDK-canonical bytes verbatim) plus the
//!   initiator's handle that must receive the reply.
//! - [`PairingReply`] `{0: sessionAccept, 1: sessionHandle}`: the responder's
//!   `SessionAccept` plus the responder's session handle the initiator sends
//!   session traffic to.
//!
//! Both decode paths defer to the SDK for protocol content: `FirstPacket`
//! bytes round-trip through `decode_first_packet`, and each `SessionAccept`
//! field is re-checked by `verify_session_accept` before the session opens.

use std::collections::BTreeMap;

use licoarc::encoding::{self, CborValue};
use licoarc::endpoint::{self, FirstPacket, SessionAccept};
use licoarc::protection::MAX_FIRST_PACKET_BYTES;

use crate::HandleToken;

/// Why a decoded envelope cannot be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeRefusal;

impl std::fmt::Display for EnvelopeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("malformed pairing envelope")
    }
}

impl std::error::Error for EnvelopeRefusal {}

/// A submission is one `FirstPacket` plus one handle; bound loosely here and
/// exactly by `decode_first_packet`.
const MAX_SUBMISSION_BYTES: usize = MAX_FIRST_PACKET_BYTES + 128;
/// A reply is one `SessionAccept` plus one handle.
const MAX_REPLY_BYTES: usize = 1_024;

fn map(entries: impl IntoIterator<Item = (u64, CborValue)>) -> CborValue {
    CborValue::Map(BTreeMap::from_iter(entries))
}

fn bytes(value: &[u8]) -> CborValue {
    CborValue::Bytes(value.to_vec())
}

fn uint(value: u64) -> CborValue {
    CborValue::Unsigned(value)
}

fn exact_map<'a>(
    value: &'a CborValue,
    keys: &[u64],
) -> Result<&'a BTreeMap<u64, CborValue>, EnvelopeRefusal> {
    let CborValue::Map(map) = value else {
        return Err(EnvelopeRefusal);
    };
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(key)) {
        return Err(EnvelopeRefusal);
    }
    Ok(map)
}

fn as_bytes32(value: &CborValue) -> Result<[u8; 32], EnvelopeRefusal> {
    let CborValue::Bytes(bytes) = value else {
        return Err(EnvelopeRefusal);
    };
    if bytes.len() != 32 {
        return Err(EnvelopeRefusal);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn as_uint(value: &CborValue) -> Result<u64, EnvelopeRefusal> {
    let CborValue::Unsigned(unsigned) = value else {
        return Err(EnvelopeRefusal);
    };
    Ok(*unsigned)
}

/// The initiator's pairing submission, bound to its reply handle.
#[derive(Clone, Debug)]
pub struct PairingSubmission {
    /// The protocol content, decoded and shape-checked by the SDK.
    pub packet: FirstPacket,
    /// The initiator's handle the `PairingReply` must be submitted to.
    pub reply_handle: HandleToken,
}

/// The responder's pairing reply, bound to its session handle.
#[derive(Clone, Debug)]
pub struct PairingReply {
    /// The SDK's acceptance document; `verify_session_accept` re-checks it.
    pub accept: SessionAccept,
    /// The responder's handle that carries session traffic.
    pub session_handle: HandleToken,
}

impl PairingSubmission {
    /// Wraps already-encoded `FirstPacket` bytes and a reply handle.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeRefusal` when the packet bytes do not decode as a
    /// `FirstPacket` or the envelope cannot be encoded.
    pub fn from_packet_bytes(
        packet_bytes: &[u8],
        reply_handle: HandleToken,
    ) -> Result<Vec<u8>, EnvelopeRefusal> {
        endpoint::decode_first_packet(packet_bytes).map_err(|_| EnvelopeRefusal)?;
        encoding::encode(&map([
            (0, bytes(packet_bytes)),
            (1, bytes(reply_handle.as_bytes())),
        ]))
        .map_err(|_| EnvelopeRefusal)
    }

    /// Decodes and SDK-validates a submission.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeRefusal` for malformed envelopes and for `FirstPacket`
    /// bytes the SDK itself refuses.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeRefusal> {
        if bytes.is_empty() || bytes.len() > MAX_SUBMISSION_BYTES {
            return Err(EnvelopeRefusal);
        }
        let value = encoding::decode(bytes).map_err(|_| EnvelopeRefusal)?;
        let map = exact_map(&value, &[0, 1])?;
        let CborValue::Bytes(packet_bytes) = &map[&0] else {
            return Err(EnvelopeRefusal);
        };
        Ok(Self {
            packet: endpoint::decode_first_packet(packet_bytes).map_err(|_| EnvelopeRefusal)?,
            reply_handle: HandleToken::from_bytes(as_bytes32(&map[&1])?),
        })
    }
}

impl PairingReply {
    /// The canonical-CBOR form.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeRefusal` when the encoding fails — structural only.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeRefusal> {
        let accept = &self.accept;
        encoding::encode(&map([
            (
                0,
                map([
                    (0, bytes(&accept.transcript_digest)),
                    (1, bytes(&accept.session_context_digest)),
                    (2, bytes(&accept.initiator_user_authority_state_digest)),
                    (3, bytes(&accept.responder_identity_state_digest)),
                    (4, bytes(&accept.responder_user_authority_state_digest)),
                    (5, uint(accept.pair_sequence)),
                    (6, bytes(&accept.mac)),
                ]),
            ),
            (1, bytes(self.session_handle.as_bytes())),
        ]))
        .map_err(|_| EnvelopeRefusal)
    }

    /// Decodes a reply; `verify_session_accept` remains the authority on the
    /// accept's cryptographic validity.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeRefusal` for malformed envelopes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeRefusal> {
        if bytes.is_empty() || bytes.len() > MAX_REPLY_BYTES {
            return Err(EnvelopeRefusal);
        }
        let value = encoding::decode(bytes).map_err(|_| EnvelopeRefusal)?;
        let map = exact_map(&value, &[0, 1])?;
        let accept_map = exact_map(&map[&0], &[0, 1, 2, 3, 4, 5, 6])?;
        Ok(Self {
            accept: SessionAccept {
                transcript_digest: as_bytes32(&accept_map[&0])?,
                session_context_digest: as_bytes32(&accept_map[&1])?,
                initiator_user_authority_state_digest: as_bytes32(&accept_map[&2])?,
                responder_identity_state_digest: as_bytes32(&accept_map[&3])?,
                responder_user_authority_state_digest: as_bytes32(&accept_map[&4])?,
                pair_sequence: as_uint(&accept_map[&5])?,
                mac: as_bytes32(&accept_map[&6])?,
            },
            session_handle: HandleToken::from_bytes(as_bytes32(&map[&1])?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use licoarc::endpoint::PrekeyBundle;
    use licoarc::provider::{
        ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
    };

    /// A shape-valid `FirstPacket`: the SDK's own decoder validates fields, so
    /// the fixture honors every exact byte bound and the inner equalities
    /// `validate_first_packet_shape` requires. Signatures are not verified
    /// here — only structure travels through the envelope.
    fn packet() -> FirstPacket {
        FirstPacket {
            protocol_line_id: [1; 32],
            protection_profile_id: [2; 32],
            initiator_identity_state_digest: [11; 32],
            initiator_user_authority_state_digest: [12; 32],
            responder_identity_state_digest: [13; 32],
            responder_user_authority_state_digest: [14; 32],
            prekey: PrekeyBundle {
                protocol_line_id: [1; 32],
                protection_profile_id: [2; 32],
                responder_identity_state_digest: [13; 32],
                ed25519_key_id: [15; 32],
                ml_dsa_65_key_id: [16; 32],
                pair_sequence: 1,
                x25519_public: [17; 32],
                ml_kem_768_public: vec![18; ML_KEM_768_PUBLIC_KEY_BYTES],
                valid_from: 10,
                valid_until: 20,
                ed25519_signature: [19; 64],
                ml_dsa_65_signature: vec![20; ML_DSA_65_SIGNATURE_BYTES],
            },
            initiator_x25519_public: [21; 32],
            ml_kem_768_ciphertext: vec![22; ML_KEM_768_CIPHERTEXT_BYTES],
            initiator_ed25519_key_id: [23; 32],
            initiator_ml_dsa_65_key_id: [24; 32],
            initiator_ed25519_signature: [25; 64],
            initiator_ml_dsa_65_signature: vec![26; ML_DSA_65_SIGNATURE_BYTES],
            client_confirm_ciphertext: [27; 36],
            client_confirm_tag: [28; 16],
        }
    }

    fn accept() -> SessionAccept {
        SessionAccept {
            transcript_digest: [31; 32],
            session_context_digest: [32; 32],
            initiator_user_authority_state_digest: [12; 32],
            responder_identity_state_digest: [13; 32],
            responder_user_authority_state_digest: [14; 32],
            pair_sequence: 1,
            mac: [33; 32],
        }
    }

    #[test]
    fn a_submission_roundtrips_packet_and_reply_handle() {
        let packet = packet();
        let packet_bytes = endpoint::encode_first_packet(&packet).unwrap();
        let reply_handle = HandleToken::from_bytes([7; 32]);
        let body = PairingSubmission::from_packet_bytes(&packet_bytes, reply_handle).unwrap();
        let decoded = PairingSubmission::decode(&body).unwrap();
        assert_eq!(decoded.packet, packet);
        assert_eq!(decoded.reply_handle, reply_handle);
    }

    #[test]
    fn a_submission_refuses_malformed_envelopes_and_packets() {
        for body in [b"".as_slice(), b"not cbor", b"\xbf\xff"] {
            assert_eq!(
                PairingSubmission::decode(body).unwrap_err(),
                EnvelopeRefusal
            );
        }
        // Well-formed CBOR but no FirstPacket inside.
        let foreign =
            encoding::encode(&map([(0, bytes(b"foreign")), (1, bytes(&[1; 32]))])).unwrap();
        assert_eq!(
            PairingSubmission::decode(&foreign).unwrap_err(),
            EnvelopeRefusal
        );
        // A FirstPacket whose inner bindings disagree is refused by the SDK.
        let mut packet = packet();
        packet.prekey.responder_identity_state_digest = [99; 32];
        let packet_bytes = endpoint::encode_first_packet(&packet);
        assert!(packet_bytes.is_err());
    }

    #[test]
    fn a_reply_roundtrips_accept_and_session_handle() {
        let reply = PairingReply {
            accept: accept(),
            session_handle: HandleToken::from_bytes([9; 32]),
        };
        let decoded = PairingReply::decode(&reply.encode().unwrap()).unwrap();
        assert_eq!(decoded.accept, reply.accept);
        assert_eq!(decoded.session_handle, reply.session_handle);
    }

    #[test]
    fn a_reply_refuses_malformed_envelopes() {
        for body in [b"".as_slice(), b"not cbor"] {
            assert_eq!(PairingReply::decode(body).unwrap_err(), EnvelopeRefusal);
        }
        let mut body = PairingReply {
            accept: accept(),
            session_handle: HandleToken::from_bytes([9; 32]),
        }
        .encode()
        .unwrap();
        body.truncate(body.len() - 4);
        assert_eq!(PairingReply::decode(&body).unwrap_err(), EnvelopeRefusal);
    }
}
