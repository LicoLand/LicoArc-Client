//! Canonical textual forms of the profile's opaque wire tokens.
//!
//! A delivery handle is 32 bytes encoded as exactly 43 unpadded base64url
//! characters in the fixed request-target slot. An operation identifier is 16
//! bytes encoded as exactly 32 lowercase hexadecimal characters in the
//! `LicoArc-Operation-Id` header. Both forms are fully canonical: every handle
//! byte-string has exactly one accepted text form and every operation id has
//! exactly one accepted header value.

use core::fmt;

/// One 32-byte delivery handle (`token256`).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandleToken([u8; 32]);

impl HandleToken {
    /// Wraps raw handle bytes obtained from a reserve response or a caller.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical unpadded-base64url form, exactly 43 characters.
    #[must_use]
    pub fn as_text(&self) -> String {
        encode_base64url(&self.0)
    }

    /// Parses the canonical 43-character form. Any other form is refused.
    pub fn parse(text: &str) -> Result<Self, TokenRefusal> {
        decode_base64url(text).map(Self)
    }
}

impl fmt::Display for HandleToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_text())
    }
}

impl fmt::Debug for HandleToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// One 16-byte idempotency operation identifier.
///
/// The profile names this an unpredictable identifier scoped to one logical
/// operation: retries of one unchanged canonical request must reuse its id,
/// and reusing an id for a different request is a conflict the Station fails
/// closed. For operations whose content *is* their identity (affiliate,
/// reserve, submit, retrieve, settle) the client derives the id from the
/// canonical request bytes, so a re-driven committed work item names the same
/// identifier by construction. Claim instead binds fresh entropy per call —
/// a second claim of the same shape is a new operation, not a retry.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId([u8; 16]);

impl OperationId {
    /// Derives the idempotent operation id for one canonical request.
    ///
    /// `operation` is the profile operation name (e.g. `b"submit"`) and
    /// `material` is the exact canonical request target and body bytes the
    /// caller will send. The first 16 bytes of the SDK's own SHA-256 over a
    /// domain-separated input are the identifier: one unchanged request always
    /// derives one id, and two different requests do not collide in practice.
    #[must_use]
    pub fn derive(operation: &[u8], material: &[u8]) -> Self {
        let mut input = Vec::with_capacity(27 + operation.len() + 1 + material.len());
        input.extend_from_slice(b"licoarc-client.operation-id.v1\0");
        input.extend_from_slice(operation);
        input.push(0);
        input.extend_from_slice(material);
        let digest = licoarc::provider::fixed_sha256(&input);
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }

    /// Wraps 16 id bytes obtained elsewhere.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The canonical lowercase-hex header form, exactly 32 characters.
    #[must_use]
    pub fn as_header(&self) -> String {
        let mut text = String::with_capacity(32);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// Parses the canonical 32-character lowercase-hex form.
    pub fn parse(text: &str) -> Result<Self, TokenRefusal> {
        if text.len() != 32
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(TokenRefusal);
        }
        let mut id = [0_u8; 16];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            id[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        Ok(Self(id))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_header())
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

const fn hex_value(byte: u8) -> Result<u8, TokenRefusal> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TokenRefusal),
    }
}

/// A token text that is not the canonical wire form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenRefusal;

impl fmt::Display for TokenRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid canonical token text")
    }
}

impl std::error::Error for TokenRefusal {}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_base64url(bytes: &[u8; 32]) -> String {
    // 32 bytes produce 10 complete sextets groups of 3 (30 bytes -> 40 chars)
    // plus a final 2-byte group (2 bytes -> 3 chars): 43 characters, no pad.
    let mut out = String::with_capacity(43);
    for chunk in bytes.chunks_exact(3) {
        let value = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(BASE64URL[(value >> 18) as usize & 63] as char);
        out.push(BASE64URL[(value >> 12) as usize & 63] as char);
        out.push(BASE64URL[(value >> 6) as usize & 63] as char);
        out.push(BASE64URL[value as usize & 63] as char);
    }
    let tail = (u32::from(bytes[30]) << 8) | u32::from(bytes[31]);
    out.push(BASE64URL[(tail >> 10) as usize & 63] as char);
    out.push(BASE64URL[(tail >> 4) as usize & 63] as char);
    out.push(BASE64URL[(tail << 2) as usize & 63] as char);
    out
}

fn decode_base64url(text: &str) -> Result<[u8; 32], TokenRefusal> {
    let chars = text.as_bytes();
    if chars.len() != 43 {
        return Err(TokenRefusal);
    }
    let mut sextets = [0_u8; 43];
    for (index, byte) in chars.iter().enumerate() {
        sextets[index] = BASE64URL
            .iter()
            .position(|candidate| candidate == byte)
            .map(|position| position as u8)
            .ok_or(TokenRefusal)?;
    }
    // Canonicality: the final 2-byte group uses exactly 4 of its 6 trailing
    // bits, so the last sextet must be a multiple of 4 — the same check the
    // TypeScript and Go stations apply. (The pinned Rust SDK's
    // `operation_from_path` additionally narrows this to {A,Q,g,w}; handles
    // outside that subset remain spec-canonical and are served by Stations.)
    if sextets[42] & 0b11 != 0 {
        return Err(TokenRefusal);
    }
    let mut out = [0_u8; 32];
    for (index, group) in sextets[..40].chunks_exact(4).enumerate() {
        let value = (u32::from(group[0]) << 18)
            | (u32::from(group[1]) << 12)
            | (u32::from(group[2]) << 6)
            | u32::from(group[3]);
        out[index * 3] = (value >> 16) as u8;
        out[index * 3 + 1] = (value >> 8) as u8;
        out[index * 3 + 2] = value as u8;
    }
    out[30] = (sextets[40] << 2) | (sextets[41] >> 4);
    out[31] = (sextets[41] << 4) | (sextets[42] >> 2);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{HandleToken, OperationId, TokenRefusal};

    #[test]
    fn handle_round_trips_through_its_canonical_form() {
        for fill in [0x00_u8, 0x01, 0x55, 0xfe, 0xff] {
            let token = HandleToken::from_bytes([fill; 32]);
            let text = token.as_text();
            assert_eq!(text.len(), 43);
            assert_eq!(HandleToken::parse(&text), Ok(token), "fill {fill:#x}");
        }
    }

    #[test]
    fn handle_refuses_noncanonical_text() {
        let token = HandleToken::from_bytes([7; 32]);
        let text = token.as_text();
        for bad in [
            String::new(),
            text[..42].to_owned(),
            format!("{text}x"),
            format!("{text}="),
            format!("+{}", &text[1..]),
        ] {
            assert_eq!(HandleToken::parse(&bad), Err(TokenRefusal), "{bad:?}");
        }
        // Non-canonical trailing bits are refused: the final sextet must be a
        // multiple of 4, so ending in 'B' (sextet 1) cannot encode 32 bytes.
        let mut noncanonical = text.clone().into_bytes();
        *noncanonical.last_mut().unwrap() = b'B';
        let mutated = String::from_utf8(noncanonical).unwrap();
        assert_eq!(HandleToken::parse(&mutated), Err(TokenRefusal));
    }

    #[test]
    fn operation_id_forms_are_exact() {
        let id = OperationId::derive(b"submit", b"material");
        let header = id.as_header();
        assert_eq!(header.len(), 32);
        assert_eq!(OperationId::parse(&header), Ok(id));
        assert_eq!(OperationId::derive(b"submit", b"material"), id);
        assert_ne!(OperationId::derive(b"submit", b"other"), id);
        assert_eq!(
            OperationId::parse(&header.to_uppercase()),
            Err(TokenRefusal)
        );
    }
}
