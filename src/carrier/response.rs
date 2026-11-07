//! Strict canonical-CBOR decoders for the closed transport response grammar.
//!
//! The SDK's own decoder is deliberately bounded far below the maximum claim
//! response, so responses are read by this dedicated reader instead. It
//! accepts only the profile's closed value subset — compact unsigned map
//! labels, unsigned integers, byte strings, arrays, and maps — encoded in
//! canonical form: definite lengths, shortest-form integers and lengths, map
//! keys in strictly ascending canonical order, no duplicate or unknown major
//! types, no trailing bytes. A response outside that subset is a
//! non-conforming Station answer and is refused before its claims are read.

use core::fmt;

use licoarc::transport::TransportOutcome;

use super::{HandleToken, control::HandleClass};

/// Control response bound for every op except CLAIM.
const MAX_CONTROL_RESPONSE_BYTES: usize = 16_384;
/// Claim response bound (`spec/v1/transport/bounds.json`).
const MAX_CLAIM_RESPONSE_BYTES: usize = 33_554_432;
/// Maximum `retryAfterMs` a station may name.
const MAX_RETRY_AFTER_MS: u64 = 60_000;
/// Maximum nested containers the grammar admits.
const MAX_DEPTH: usize = 8;
/// Maximum map pairs in any record (the grammar's largest map has 6 labels).
const MAX_MAP_PAIRS: usize = 16;
/// Maximum array elements (bounded settlement/claim batches).
const MAX_ARRAY_ITEMS: usize = 64;
/// Maximum protected-packet bytes inside one claimed item.
const MAX_PACKET_BYTES: usize = 524_288;

/// The profile's failure classes (`uint .le 7`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    InvalidRequest = 0,
    UnsupportedProfile = 1,
    TargetUnavailable = 2,
    PacketTooLarge = 3,
    CapacityUnavailable = 4,
    RateLimited = 5,
    Conflict = 6,
    InternalUnavailable = 7,
}

impl FailureClass {
    fn decode(value: u64) -> Result<Self, DecodeRefusal> {
        Ok(match value {
            0 => Self::InvalidRequest,
            1 => Self::UnsupportedProfile,
            2 => Self::TargetUnavailable,
            3 => Self::PacketTooLarge,
            4 => Self::CapacityUnavailable,
            5 => Self::RateLimited,
            6 => Self::Conflict,
            7 => Self::InternalUnavailable,
            _ => return Err(DecodeRefusal),
        })
    }
}

/// Per-item settlement outcomes (`uint .le 3`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettleOutcome {
    Completed = 0,
    Released = 1,
    StaleClaim = 2,
    AttemptLimit = 3,
}

/// One `settlement-result` entry of an accepted SETTLE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemResult {
    pub item_id: [u8; 32],
    pub outcome: SettleOutcome,
}

/// A decoded Station reply: either the accepted payload, or the typed decline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StationReply<T> {
    Accepted(T),
    Declined {
        outcome: TransportOutcome,
        failure_class: Option<FailureClass>,
        retry_after_ms: Option<u64>,
    },
}

impl<T> StationReply<T> {
    /// The profile outcome the reply named.
    #[must_use]
    pub const fn outcome(&self) -> TransportOutcome {
        match self {
            Self::Accepted(_) => TransportOutcome::Accepted,
            Self::Declined { outcome, .. } => *outcome,
        }
    }
}

/// The reply was outside the closed canonical grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeRefusal;

impl fmt::Display for DecodeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("non-canonical transport response")
    }
}

impl std::error::Error for DecodeRefusal {}

/// The closed value subset the response grammar admits.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(u64, Value)>),
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn value(&mut self, depth: usize) -> Result<Value, DecodeRefusal> {
        if depth > MAX_DEPTH || self.offset >= self.bytes.len() {
            return Err(DecodeRefusal);
        }
        let head = self.bytes[self.offset];
        self.offset += 1;
        match head >> 5 {
            0 => Ok(Value::Unsigned(self.length(head)?)),
            2 => {
                let length = usize::try_from(self.length(head)?).map_err(|_| DecodeRefusal)?;
                Ok(Value::Bytes(self.take(length)?.to_vec()))
            }
            4 => {
                let length = usize::try_from(self.length(head)?).map_err(|_| DecodeRefusal)?;
                if length > MAX_ARRAY_ITEMS {
                    return Err(DecodeRefusal);
                }
                let mut items = Vec::with_capacity(length);
                for _ in 0..length {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let length = usize::try_from(self.length(head)?).map_err(|_| DecodeRefusal)?;
                if length > MAX_MAP_PAIRS {
                    return Err(DecodeRefusal);
                }
                let mut pairs = Vec::with_capacity(length);
                let mut previous: Option<(usize, Vec<u8>)> = None;
                for _ in 0..length {
                    let key_head = *self.bytes.get(self.offset).ok_or(DecodeRefusal)?;
                    if key_head >> 5 != 0 {
                        return Err(DecodeRefusal);
                    }
                    let key_start = self.offset;
                    self.offset += 1;
                    let key = self.length(key_head)?;
                    // Canonical map order: ascending encoded length, then
                    // lexicographic within one length.
                    let key_bytes = self.bytes[key_start..self.offset].to_vec();
                    if let Some((previous_len, previous_bytes)) = &previous
                        && (*previous_len > key_bytes.len()
                            || (*previous_len == key_bytes.len()
                                && previous_bytes.as_slice() >= key_bytes.as_slice()))
                    {
                        return Err(DecodeRefusal);
                    }
                    previous = Some((key_bytes.len(), key_bytes));
                    pairs.push((key, self.value(depth + 1)?));
                }
                Ok(Value::Map(pairs))
            }
            _ => Err(DecodeRefusal),
        }
    }

    /// Reads one integer/length argument in its definite shortest form.
    fn length(&mut self, head: u8) -> Result<u64, DecodeRefusal> {
        let read = |reader: &mut Self, width: usize| -> Result<u64, DecodeRefusal> {
            let bytes = reader.take(width)?;
            let mut value = 0_u64;
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
            Ok(value)
        };
        match head & 0x1f {
            additional @ 0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = read(self, 1)?;
                if value < 24 {
                    Err(DecodeRefusal)
                } else {
                    Ok(value)
                }
            }
            25 => {
                let value = read(self, 2)?;
                if value < 256 {
                    Err(DecodeRefusal)
                } else {
                    Ok(value)
                }
            }
            26 => {
                let value = read(self, 4)?;
                if value < 65_536 {
                    Err(DecodeRefusal)
                } else {
                    Ok(value)
                }
            }
            27 => {
                let value = read(self, 8)?;
                if value < 4_294_967_296 {
                    Err(DecodeRefusal)
                } else {
                    Ok(value)
                }
            }
            _ => Err(DecodeRefusal),
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeRefusal> {
        let end = self.offset.checked_add(length).ok_or(DecodeRefusal)?;
        if end > self.bytes.len() {
            return Err(DecodeRefusal);
        }
        let taken = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(taken)
    }
}

fn decode_root(body: &[u8], limit: usize) -> Result<Vec<(u64, Value)>, DecodeRefusal> {
    if body.is_empty() || body.len() > limit {
        return Err(DecodeRefusal);
    }
    let mut reader = Reader {
        bytes: body,
        offset: 0,
    };
    let Value::Map(labels) = reader.value(0)? else {
        return Err(DecodeRefusal);
    };
    if reader.offset != body.len() {
        return Err(DecodeRefusal);
    }
    Ok(labels)
}

fn label(labels: &[(u64, Value)], key: u64) -> Option<&Value> {
    labels
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value)
}

fn closed(labels: &[(u64, Value)], allowed: &[u64]) -> Result<(), DecodeRefusal> {
    if labels.iter().any(|(key, _)| !allowed.contains(key)) {
        return Err(DecodeRefusal);
    }
    Ok(())
}

fn forbidden(labels: &[(u64, Value)], keys: &[u64]) -> Result<(), DecodeRefusal> {
    if keys.iter().any(|key| label(labels, *key).is_some()) {
        return Err(DecodeRefusal);
    }
    Ok(())
}

fn unsigned_of(value: Option<&Value>) -> Result<u64, DecodeRefusal> {
    match value {
        Some(Value::Unsigned(value)) => Ok(*value),
        _ => Err(DecodeRefusal),
    }
}

fn bytes_of(value: Option<&Value>, size: usize) -> Result<&[u8], DecodeRefusal> {
    match value {
        Some(Value::Bytes(bytes)) if bytes.len() == size => Ok(bytes),
        _ => Err(DecodeRefusal),
    }
}

fn token(value: Option<&Value>) -> Result<[u8; 32], DecodeRefusal> {
    bytes_of(value, 32)?.try_into().map_err(|_| DecodeRefusal)
}

fn signature(value: Option<&Value>) -> Result<[u8; 64], DecodeRefusal> {
    bytes_of(value, 64)?.try_into().map_err(|_| DecodeRefusal)
}

fn outcome_of(labels: &[(u64, Value)]) -> Result<TransportOutcome, DecodeRefusal> {
    Ok(match unsigned_of(label(labels, 0))? {
        0 => TransportOutcome::Accepted,
        1 => TransportOutcome::Rejected,
        2 => TransportOutcome::Transient,
        3 => TransportOutcome::Ambiguous,
        _ => return Err(DecodeRefusal),
    })
}

/// Reads the shared failure tail of one declined response map.
///
/// `failure`/`retry` are the op's own decline labels. A retry hint is only
/// canonical on a transient outcome; any other placement is refused.
fn decline<T>(
    labels: &[(u64, Value)],
    outcome: TransportOutcome,
    failure_label: u64,
    retry_label: u64,
) -> Result<StationReply<T>, DecodeRefusal> {
    let failure_class = match label(labels, failure_label) {
        Some(value) => Some(FailureClass::decode(unsigned_of(Some(value))?)?),
        None => None,
    };
    let retry_after_ms = match label(labels, retry_label) {
        Some(value) => {
            let retry = unsigned_of(Some(value))?;
            if retry > MAX_RETRY_AFTER_MS {
                return Err(DecodeRefusal);
            }
            Some(retry)
        }
        None => None,
    };
    if retry_after_ms.is_some() && outcome != TransportOutcome::Transient {
        return Err(DecodeRefusal);
    }
    Ok(StationReply::Declined {
        outcome,
        failure_class,
        retry_after_ms,
    })
}

/// The accepted payload of AFFILIATE: `affiliationNotAfter` + service statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Affiliation {
    pub not_after: u64,
    pub signature: [u8; 64],
}

/// AFFILIATE: `{0, ?1 notAfter, ?2 signature | ?3 failure, ?4 retryAfter}`.
pub fn decode_affiliate(body: &[u8]) -> Result<StationReply<Affiliation>, DecodeRefusal> {
    let labels = decode_root(body, MAX_CONTROL_RESPONSE_BYTES)?;
    closed(&labels, &[0, 1, 2, 3, 4])?;
    let outcome = outcome_of(&labels)?;
    if outcome == TransportOutcome::Accepted {
        forbidden(&labels, &[3, 4])?;
        let affiliation = Affiliation {
            not_after: unsigned_of(label(&labels, 1))?,
            signature: signature(label(&labels, 2))?,
        };
        Ok(StationReply::Accepted(affiliation))
    } else {
        forbidden(&labels, &[1, 2])?;
        decline(&labels, outcome, 3, 4)
    }
}

/// The accepted payload of RESERVE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub handle: HandleToken,
    pub handle_class: HandleClass,
    /// `(serviceUntil, route-service signature)` — async handles only.
    pub service: Option<(u64, [u8; 64])>,
}

/// RESERVE: `{0, ?1 handle, ?2 class, ?3 serviceUntil, ?4 signature | ?5 failure, ?6 retry}`.
pub fn decode_reserve(body: &[u8]) -> Result<StationReply<Lease>, DecodeRefusal> {
    let labels = decode_root(body, MAX_CONTROL_RESPONSE_BYTES)?;
    closed(&labels, &[0, 1, 2, 3, 4, 5, 6])?;
    let outcome = outcome_of(&labels)?;
    if outcome == TransportOutcome::Accepted {
        forbidden(&labels, &[5, 6])?;
        let handle = HandleToken::from_bytes(token(label(&labels, 1))?);
        let handle_class = match unsigned_of(label(&labels, 2))? {
            0 => HandleClass::Async,
            1 => HandleClass::FirstContact,
            _ => return Err(DecodeRefusal),
        };
        let service = match handle_class {
            HandleClass::Async => Some((
                unsigned_of(label(&labels, 3))?,
                signature(label(&labels, 4))?,
            )),
            HandleClass::FirstContact => {
                forbidden(&labels, &[3, 4])?;
                None
            }
        };
        Ok(StationReply::Accepted(Lease {
            handle,
            handle_class,
            service,
        }))
    } else {
        forbidden(&labels, &[1, 2, 3, 4])?;
        decline(&labels, outcome, 5, 6)
    }
}

/// SUBMIT: `{0 | ?1 failure, ?2 retry}`.
pub fn decode_submit(body: &[u8]) -> Result<StationReply<()>, DecodeRefusal> {
    let labels = decode_root(body, MAX_CONTROL_RESPONSE_BYTES)?;
    closed(&labels, &[0, 1, 2])?;
    let outcome = outcome_of(&labels)?;
    if outcome == TransportOutcome::Accepted {
        if labels.len() != 1 {
            return Err(DecodeRefusal);
        }
        Ok(StationReply::Accepted(()))
    } else {
        decline(&labels, outcome, 1, 2)
    }
}

/// One claimed item: `{0: itemId, 1: protectedPacket}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedItem {
    pub item_id: [u8; 32],
    pub packet: Vec<u8>,
}

/// The accepted payload of CLAIM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimBatch {
    pub claim_id: [u8; 32],
    pub claim_epoch: u64,
    pub items: Vec<ClaimedItem>,
}

/// CLAIM: `{0, ?1 claimId, ?2 claimEpoch, ?3 [claimed-item] | ?4 failure, ?5 retry}`.
///
/// An accepted claim with no items carries only label 0.
pub fn decode_claim(body: &[u8]) -> Result<StationReply<ClaimBatch>, DecodeRefusal> {
    let labels = decode_root(body, MAX_CLAIM_RESPONSE_BYTES)?;
    closed(&labels, &[0, 1, 2, 3, 4, 5])?;
    let outcome = outcome_of(&labels)?;
    if outcome == TransportOutcome::Accepted {
        forbidden(&labels, &[4, 5])?;
        if labels.len() == 1 {
            return Ok(StationReply::Accepted(ClaimBatch {
                claim_id: [0; 32],
                claim_epoch: 0,
                items: Vec::new(),
            }));
        }
        let claim_id = token(label(&labels, 1))?;
        let claim_epoch = unsigned_of(label(&labels, 2))?;
        let Some(Value::Array(items)) = label(&labels, 3) else {
            return Err(DecodeRefusal);
        };
        if items.is_empty() || items.len() > MAX_ARRAY_ITEMS {
            return Err(DecodeRefusal);
        }
        let mut total = 0_usize;
        let mut claimed = Vec::with_capacity(items.len());
        let mut seen = std::collections::BTreeSet::new();
        for item in items {
            let Value::Map(fields) = item else {
                return Err(DecodeRefusal);
            };
            closed(fields, &[0, 1])?;
            if fields.len() != 2 {
                return Err(DecodeRefusal);
            }
            let item_id = token(label(fields, 0))?;
            let Some(Value::Bytes(packet)) = label(fields, 1) else {
                return Err(DecodeRefusal);
            };
            if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
                return Err(DecodeRefusal);
            }
            total = total.checked_add(packet.len()).ok_or(DecodeRefusal)?;
            if !seen.insert(item_id) {
                return Err(DecodeRefusal);
            }
            claimed.push(ClaimedItem {
                item_id,
                packet: packet.clone(),
            });
        }
        if total > MAX_CLAIM_RESPONSE_BYTES {
            return Err(DecodeRefusal);
        }
        Ok(StationReply::Accepted(ClaimBatch {
            claim_id,
            claim_epoch,
            items: claimed,
        }))
    } else {
        forbidden(&labels, &[1, 2, 3])?;
        decline(&labels, outcome, 4, 5)
    }
}

/// SETTLE: `{0, ?1 [settlement-result] | ?2 failure, ?3 retry}`.
pub fn decode_settle(body: &[u8]) -> Result<StationReply<Vec<ItemResult>>, DecodeRefusal> {
    let labels = decode_root(body, MAX_CONTROL_RESPONSE_BYTES)?;
    closed(&labels, &[0, 1, 2, 3])?;
    let outcome = outcome_of(&labels)?;
    if outcome == TransportOutcome::Accepted {
        let Some(Value::Array(results)) = label(&labels, 1) else {
            return Err(DecodeRefusal);
        };
        if results.is_empty() || results.len() > MAX_ARRAY_ITEMS {
            return Err(DecodeRefusal);
        }
        let mut items = Vec::with_capacity(results.len());
        for result in results {
            let Value::Map(fields) = result else {
                return Err(DecodeRefusal);
            };
            closed(fields, &[0, 1])?;
            if fields.len() != 2 {
                return Err(DecodeRefusal);
            }
            let item_id = token(label(fields, 0))?;
            let outcome = match unsigned_of(label(fields, 1))? {
                0 => SettleOutcome::Completed,
                1 => SettleOutcome::Released,
                2 => SettleOutcome::StaleClaim,
                3 => SettleOutcome::AttemptLimit,
                _ => return Err(DecodeRefusal),
            };
            items.push(ItemResult { item_id, outcome });
        }
        Ok(StationReply::Accepted(items))
    } else {
        forbidden(&labels, &[1])?;
        decline(&labels, outcome, 2, 3)
    }
}

#[cfg(test)]
mod tests {
    use licoarc::transport::TransportOutcome;

    use super::{
        ClaimBatch, DecodeRefusal, FailureClass, ItemResult, SettleOutcome, StationReply,
        decode_affiliate, decode_claim, decode_reserve, decode_settle, decode_submit,
    };
    use crate::carrier::HandleClass;

    /// Minimal canonical-CBOR writers for fixtures.
    fn head(out: &mut Vec<u8>, major: u8, value: u64) {
        let (tag, width) = match value {
            0..=23 => (value as u8, 0),
            24..=0xff => (24, 1),
            0x100..=0xffff => (25, 2),
            0x1_0000..=0xffff_ffff => (26, 4),
            _ => (27, 8),
        };
        out.push((major << 5) | tag);
        out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    }

    fn map_head(out: &mut Vec<u8>, pairs: u64) {
        head(out, 5, pairs);
    }

    fn array_head(out: &mut Vec<u8>, items: u64) {
        head(out, 4, items);
    }

    fn unsigned(out: &mut Vec<u8>, value: u64) {
        head(out, 0, value);
    }

    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        head(out, 2, value.len() as u64);
        out.extend_from_slice(value);
    }

    fn key(out: &mut Vec<u8>, label: u64) {
        unsigned(out, label);
    }

    #[test]
    fn affiliate_accepted_reads_not_after_and_signature() {
        let mut body = Vec::new();
        map_head(&mut body, 3);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        unsigned(&mut body, 123_456);
        key(&mut body, 2);
        bytes(&mut body, &[9; 64]);
        match decode_affiliate(&body).unwrap() {
            StationReply::Accepted(affiliation) => {
                assert_eq!(affiliation.not_after, 123_456);
                assert_eq!(affiliation.signature, [9; 64]);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn affiliate_declined_reads_failure_and_retry() {
        let mut body = Vec::new();
        map_head(&mut body, 3);
        key(&mut body, 0);
        unsigned(&mut body, 2);
        key(&mut body, 3);
        unsigned(&mut body, 6);
        key(&mut body, 4);
        unsigned(&mut body, 1_000);
        match decode_affiliate(&body).unwrap() {
            StationReply::Declined {
                outcome,
                failure_class,
                retry_after_ms,
            } => {
                assert_eq!(outcome, TransportOutcome::Transient);
                assert_eq!(failure_class, Some(FailureClass::Conflict));
                assert_eq!(retry_after_ms, Some(1_000));
            }
            other => panic!("expected declined, got {other:?}"),
        }
    }

    #[test]
    fn reserve_accepted_async_reads_lease() {
        let mut body = Vec::new();
        map_head(&mut body, 5);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        bytes(&mut body, &[5; 32]);
        key(&mut body, 2);
        unsigned(&mut body, 0);
        key(&mut body, 3);
        unsigned(&mut body, 999);
        key(&mut body, 4);
        bytes(&mut body, &[7; 64]);
        match decode_reserve(&body).unwrap() {
            StationReply::Accepted(lease) => {
                assert_eq!(lease.handle_class, HandleClass::Async);
                assert_eq!(lease.service, Some((999, [7; 64])));
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn reserve_accepted_first_contact_carries_no_service() {
        let mut body = Vec::new();
        map_head(&mut body, 3);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        bytes(&mut body, &[5; 32]);
        key(&mut body, 2);
        unsigned(&mut body, 1);
        match decode_reserve(&body).unwrap() {
            StationReply::Accepted(lease) => {
                assert_eq!(lease.handle_class, HandleClass::FirstContact);
                assert_eq!(lease.service, None);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
        // A first-contact handle must not carry async fields.
        let mut bad = Vec::new();
        map_head(&mut bad, 4);
        key(&mut bad, 0);
        unsigned(&mut bad, 0);
        key(&mut bad, 1);
        bytes(&mut bad, &[5; 32]);
        key(&mut bad, 2);
        unsigned(&mut bad, 1);
        key(&mut bad, 3);
        unsigned(&mut bad, 1);
        assert_eq!(decode_reserve(&bad), Err(DecodeRefusal));
    }

    #[test]
    fn submit_accepted_is_the_unit_outcome() {
        let mut body = Vec::new();
        map_head(&mut body, 1);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        assert_eq!(decode_submit(&body), Ok(StationReply::Accepted(())));
        // Extra fields on accept are refused.
        let mut bad = body.clone();
        bad[0] = 0xa2;
        key(&mut bad, 1);
        unsigned(&mut bad, 0);
        assert_eq!(decode_submit(&bad), Err(DecodeRefusal));
    }

    #[test]
    fn claim_reads_items_including_large_packets() {
        let packet = vec![0xAB; 300_000];
        let mut body = Vec::new();
        map_head(&mut body, 4);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        bytes(&mut body, &[3; 32]);
        key(&mut body, 2);
        unsigned(&mut body, 7);
        key(&mut body, 3);
        array_head(&mut body, 2);
        map_head(&mut body, 2);
        key(&mut body, 0);
        bytes(&mut body, &[8; 32]);
        key(&mut body, 1);
        bytes(&mut body, &packet);
        map_head(&mut body, 2);
        key(&mut body, 0);
        bytes(&mut body, &[9; 32]);
        key(&mut body, 1);
        bytes(&mut body, &[1, 2, 3]);
        match decode_claim(&body).unwrap() {
            StationReply::Accepted(ClaimBatch {
                claim_id,
                claim_epoch,
                items,
            }) => {
                assert_eq!(claim_id, [3; 32]);
                assert_eq!(claim_epoch, 7);
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].item_id, [8; 32]);
                assert_eq!(items[0].packet, packet);
                assert_eq!(items[1].packet, vec![1, 2, 3]);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn claim_empty_batch_is_label_zero_only() {
        let mut body = Vec::new();
        map_head(&mut body, 1);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        match decode_claim(&body).unwrap() {
            StationReply::Accepted(batch) => assert!(batch.items.is_empty()),
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn claim_rejects_duplicate_item_ids_and_empty_packets() {
        let mut body = Vec::new();
        map_head(&mut body, 4);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        bytes(&mut body, &[3; 32]);
        key(&mut body, 2);
        unsigned(&mut body, 1);
        key(&mut body, 3);
        array_head(&mut body, 2);
        for _ in 0..2 {
            map_head(&mut body, 2);
            key(&mut body, 0);
            bytes(&mut body, &[8; 32]);
            key(&mut body, 1);
            bytes(&mut body, &[1]);
        }
        assert_eq!(decode_claim(&body), Err(DecodeRefusal));
    }

    #[test]
    fn settle_reads_per_item_outcomes() {
        let mut body = Vec::new();
        map_head(&mut body, 2);
        key(&mut body, 0);
        unsigned(&mut body, 0);
        key(&mut body, 1);
        array_head(&mut body, 2);
        map_head(&mut body, 2);
        key(&mut body, 0);
        bytes(&mut body, &[4; 32]);
        key(&mut body, 1);
        unsigned(&mut body, 0);
        map_head(&mut body, 2);
        key(&mut body, 0);
        bytes(&mut body, &[5; 32]);
        key(&mut body, 1);
        unsigned(&mut body, 2);
        match decode_settle(&body).unwrap() {
            StationReply::Accepted(results) => {
                assert_eq!(
                    results,
                    vec![
                        ItemResult {
                            item_id: [4; 32],
                            outcome: SettleOutcome::Completed
                        },
                        ItemResult {
                            item_id: [5; 32],
                            outcome: SettleOutcome::StaleClaim
                        },
                    ]
                );
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn noncanonical_and_malformed_bodies_are_refused() {
        let mut dup = Vec::new();
        map_head(&mut dup, 2);
        key(&mut dup, 0);
        unsigned(&mut dup, 0);
        key(&mut dup, 0);
        unsigned(&mut dup, 0);
        assert_eq!(decode_submit(&dup), Err(DecodeRefusal));

        let mut wrong_order = Vec::new();
        map_head(&mut wrong_order, 2);
        key(&mut wrong_order, 1);
        unsigned(&mut wrong_order, 0);
        key(&mut wrong_order, 0);
        unsigned(&mut wrong_order, 0);
        assert_eq!(decode_submit(&wrong_order), Err(DecodeRefusal));

        // Non-shortest integer (0 encoded as u8).
        let mut padded = vec![0xa2, 0x00, 0x00];
        key(&mut padded, 1);
        unsigned(&mut padded, 0);
        padded[2] = 0x18;
        padded.insert(3, 0x00);
        assert_eq!(decode_submit(&padded), Err(DecodeRefusal));

        // Indefinite length and tags are outside the grammar.
        assert_eq!(decode_submit(&[0x9f, 0x00, 0xff]), Err(DecodeRefusal));
        assert_eq!(decode_submit(&[0xc1, 0x00]), Err(DecodeRefusal));

        // Trailing bytes are refused.
        let mut trailing = Vec::new();
        map_head(&mut trailing, 1);
        key(&mut trailing, 0);
        unsigned(&mut trailing, 0);
        trailing.push(0x00);
        assert_eq!(decode_submit(&trailing), Err(DecodeRefusal));
    }

    #[test]
    fn declined_with_retry_on_non_transient_is_refused() {
        let mut body = Vec::new();
        map_head(&mut body, 3);
        key(&mut body, 0);
        unsigned(&mut body, 1);
        key(&mut body, 1);
        unsigned(&mut body, 0);
        key(&mut body, 2);
        unsigned(&mut body, 5);
        assert_eq!(decode_submit(&body), Err(DecodeRefusal));
    }
}
