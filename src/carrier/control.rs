//! Typed control requests encoded as canonical CBOR.
//!
//! Each builder produces the exact closed map of the transport profile and
//! then runs the SDK's own `validate_control_record` over the value before it
//! is encoded, so a request this module emits has already passed the same
//! check the Station will apply. A request that cannot pass is refused here,
//! before any byte leaves the client.

use std::collections::BTreeMap;

use licoarc::encoding::{self, CborValue};
use licoarc::transport::{self, Operation};

use crate::HandleToken;

/// SHA-256 of the fixed Transport Profile source, as the Candidate Station
/// publishes it (`TransportSourceDigest` in `licoarc-candidate/binding.go`).
/// RESERVE names this exact value; a station enforcing a different profile
/// refuses.
pub const TRANSPORT_PROFILE_DIGEST: [u8; 32] = [
    0x6d, 0x46, 0x36, 0xc9, 0x83, 0x60, 0x6f, 0xb2, 0x66, 0x44, 0x3a, 0x3c, 0xe0, 0x51, 0x71, 0xa8,
    0xaf, 0x7a, 0xb5, 0x28, 0x4e, 0x0c, 0xe3, 0x01, 0xbe, 0x70, 0x24, 0xce, 0x16, 0x59, 0x2c, 0xb5,
];

/// The delivery-handle class named by RESERVE (`uint .le 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleClass {
    /// Finite asynchronous handle with a service statement.
    Async = 0,
    /// One-shot handle consumed by its first accepted submission.
    FirstContact = 1,
}

impl HandleClass {
    const fn code(self) -> u64 {
        self as u64
    }
}

/// The settlement action of one claimed item (`uint .le 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettleAction {
    /// The endpoint consumed the item; delete it at the Station.
    Complete = 0,
    /// The endpoint did not consume the item; make it claimable again.
    Release = 1,
}

impl SettleAction {
    const fn code(self) -> u64 {
        self as u64
    }
}

/// Refused before any wire byte is produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlRefusal {
    cause: licoarc::error::Error,
}

impl ControlRefusal {
    #[must_use]
    pub const fn cause(self) -> licoarc::error::Error {
        self.cause
    }
}

impl core::fmt::Display for ControlRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid transport control record: {}",
            self.cause
        )
    }
}

impl std::error::Error for ControlRefusal {}

/// AFFILIATE `{0: descriptorDigest, 1: affiliationCommitment}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffiliateRequest {
    pub station_descriptor_digest: [u8; 32],
    /// Caller-chosen opaque 32-byte affiliation commitment, bound by the
    /// Station to this affiliation for the storage window.
    pub affiliation_commitment: [u8; 32],
}

/// RESERVE `{0: descriptorDigest, 1: affiliationCommitment, 2: profileDigest, 3: class}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveRequest {
    pub station_descriptor_digest: [u8; 32],
    pub affiliation_commitment: [u8; 32],
    /// The exact Transport Profile digest the Station enforces.
    pub transport_profile_digest: [u8; 32],
    pub handle_class: HandleClass,
}

/// RETRIEVE `{0: claimId, 1: claimEpoch, 2: itemId}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrieveRequest {
    pub claim_id: [u8; 32],
    pub claim_epoch: u64,
    pub item_id: [u8; 32],
}

/// CLAIM `{0: maxItems}`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimRequest {
    pub max_items: u64,
}

/// One `{0: itemId, 1: action}` inside SETTLE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settlement {
    pub item_id: [u8; 32],
    pub action: SettleAction,
}

/// SETTLE `{0: claimId, 1: claimEpoch, 2: [settlement ...]}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettleRequest {
    pub claim_id: [u8; 32],
    pub claim_epoch: u64,
    pub settlements: Vec<Settlement>,
}

fn digest(value: &[u8; 32]) -> CborValue {
    CborValue::Bytes(value.to_vec())
}

fn map(entries: impl IntoIterator<Item = (u64, CborValue)>) -> CborValue {
    CborValue::Map(BTreeMap::from_iter(entries))
}

fn encode(operation: Operation, value: &CborValue) -> Result<Vec<u8>, ControlRefusal> {
    transport::validate_control_record(operation, value)
        .map_err(|cause| ControlRefusal { cause })?;
    encoding::encode(value).map_err(|cause| ControlRefusal { cause })
}

impl AffiliateRequest {
    pub fn encode(&self) -> Result<Vec<u8>, ControlRefusal> {
        encode(
            Operation::Affiliate,
            &map([
                (0, digest(&self.station_descriptor_digest)),
                (1, digest(&self.affiliation_commitment)),
            ]),
        )
    }
}

impl ReserveRequest {
    pub fn encode(&self) -> Result<Vec<u8>, ControlRefusal> {
        encode(
            Operation::Reserve,
            &map([
                (0, digest(&self.station_descriptor_digest)),
                (1, digest(&self.affiliation_commitment)),
                (2, digest(&self.transport_profile_digest)),
                (3, CborValue::Unsigned(self.handle_class.code())),
            ]),
        )
    }
}

impl RetrieveRequest {
    pub fn encode(&self) -> Result<Vec<u8>, ControlRefusal> {
        encode(
            Operation::Retrieve,
            &map([
                (0, digest(&self.claim_id)),
                (1, CborValue::Unsigned(self.claim_epoch)),
                (2, digest(&self.item_id)),
            ]),
        )
    }
}

impl ClaimRequest {
    pub fn encode(&self) -> Result<Vec<u8>, ControlRefusal> {
        encode(
            Operation::Claim,
            &map([(0, CborValue::Unsigned(self.max_items))]),
        )
    }
}

impl SettleRequest {
    pub fn encode(&self) -> Result<Vec<u8>, ControlRefusal> {
        let settlements = self
            .settlements
            .iter()
            .map(|settlement| {
                map([
                    (0, digest(&settlement.item_id)),
                    (1, CborValue::Unsigned(settlement.action.code())),
                ])
            })
            .collect();
        encode(
            Operation::Settle,
            &map([
                (0, digest(&self.claim_id)),
                (1, CborValue::Unsigned(self.claim_epoch)),
                (2, CborValue::Array(settlements)),
            ]),
        )
    }
}

impl HandleToken {
    /// The canonical request-target path for one handle-bound operation.
    #[must_use]
    pub fn path(&self, operation: &str) -> String {
        format!("/v1/handles/{}/{operation}", self.as_text())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AffiliateRequest, ClaimRequest, HandleClass, ReserveRequest, RetrieveRequest, SettleAction,
        SettleRequest, Settlement,
    };
    use crate::HandleToken;
    use licoarc::encoding::{self, CborValue};

    fn bytes(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn affiliate_encodes_the_closed_two_label_map() {
        let request = AffiliateRequest {
            station_descriptor_digest: bytes(1),
            affiliation_commitment: bytes(2),
        };
        let body = request.encode().unwrap();
        let CborValue::Map(map) = encoding::decode(&body).unwrap() else {
            panic!("not a map")
        };
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&0), Some(&CborValue::Bytes(bytes(1).to_vec())));
        assert_eq!(map.get(&1), Some(&CborValue::Bytes(bytes(2).to_vec())));
    }

    #[test]
    fn reserve_carries_profile_digest_and_class() {
        let request = ReserveRequest {
            station_descriptor_digest: bytes(1),
            affiliation_commitment: bytes(2),
            transport_profile_digest: bytes(3),
            handle_class: HandleClass::Async,
        };
        assert!(request.encode().is_ok());
        let first_contact = ReserveRequest {
            handle_class: HandleClass::FirstContact,
            ..request
        };
        assert!(first_contact.encode().is_ok());
    }

    #[test]
    fn claim_refuses_out_of_bound_item_counts() {
        assert!(ClaimRequest { max_items: 0 }.encode().is_err());
        assert!(ClaimRequest { max_items: 1 }.encode().is_ok());
        assert!(ClaimRequest { max_items: 64 }.encode().is_ok());
        assert!(ClaimRequest { max_items: 65 }.encode().is_err());
    }

    #[test]
    fn settle_refuses_empty_and_duplicate_sets() {
        let base = SettleRequest {
            claim_id: bytes(9),
            claim_epoch: 3,
            settlements: vec![],
        };
        assert!(base.encode().is_err());
        let duplicate = SettleRequest {
            settlements: vec![
                Settlement {
                    item_id: bytes(4),
                    action: SettleAction::Complete,
                },
                Settlement {
                    item_id: bytes(4),
                    action: SettleAction::Release,
                },
            ],
            ..base.clone()
        };
        assert!(duplicate.encode().is_err());
        let valid = SettleRequest {
            settlements: vec![Settlement {
                item_id: bytes(4),
                action: SettleAction::Release,
            }],
            ..base
        };
        assert!(valid.encode().is_ok());
    }

    #[test]
    fn retrieve_encodes_claim_and_item() {
        let request = RetrieveRequest {
            claim_id: bytes(1),
            claim_epoch: 7,
            item_id: bytes(2),
        };
        assert!(request.encode().is_ok());
    }

    #[test]
    fn handle_paths_match_the_fixed_routes() {
        // Fill 0x04 ends in 'Q': the pinned SDK's `operation_from_path`
        // additionally restricts the final character to {A,Q,g,w}, a subset
        // of the spec-canonical {A,E,I,M,Q,U,Y,c,g,k,o,s,w,0,4,8}. The client
        // enforces the spec-canonical form; this fill satisfies both.
        let handle = HandleToken::from_bytes([0x04; 32]);
        for operation in ["submit", "retrieve", "claim", "settle"] {
            let path = handle.path(operation);
            assert!(path.starts_with("/v1/handles/"));
            assert!(path.len() <= 128);
            assert_eq!(
                licoarc::transport::operation_from_path(&path).unwrap(),
                match operation {
                    "submit" => licoarc::transport::Operation::Submit,
                    "retrieve" => licoarc::transport::Operation::Retrieve,
                    "claim" => licoarc::transport::Operation::Claim,
                    _ => licoarc::transport::Operation::Settle,
                }
            );
        }
    }
}

#[cfg(test)]
mod profile_digest_tests {
    #[test]
    fn the_profile_digest_matches_the_candidate_constant() {
        // `TransportSourceDigest` in licoarc-candidate/binding.go.
        let expected = "6d4636c983606fb266443a3ce05171a8af7ab5284e0ce301be7024ce16592cb5";
        let mut decoded = [0_u8; 32];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16).unwrap();
        }
        assert_eq!(super::TRANSPORT_PROFILE_DIGEST, decoded);
    }
}
