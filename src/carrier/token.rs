//! Canonical textual form of the mailbox handle token.
//!
//! A delivery handle is 32 bytes encoded as exactly 43 unpadded base64url
//! characters. The first 16 bytes are the mailbox id, the last 16 a random
//! per-handle tag; the form is fully canonical: every handle byte-string has
//! exactly one accepted text form.

use core::fmt;

/// One 32-byte mailbox handle (`mailboxId ‖ tag`).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandleToken([u8; 32]);

impl HandleToken {
    /// Mints one new handle for `mailbox_id` with a random 16-byte tag.
    ///
    /// An RNG failure is a caller-visible error, not a panic: every other
    /// entropy-drawing mint path in the crate already returns one.
    pub fn mint(mailbox_id: [u8; 16]) -> std::io::Result<Self> {
        let mut handle = [0_u8; 32];
        handle[..16].copy_from_slice(&mailbox_id);
        getrandom::fill(&mut handle[16..]).map_err(std::io::Error::other)?;
        Ok(Self(handle))
    }

    /// Wraps raw handle bytes obtained elsewhere.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The mailbox identity embedded in the handle's first 16 bytes.
    #[must_use]
    pub fn mailbox_id(&self) -> [u8; 16] {
        let mut id = [0_u8; 16];
        id.copy_from_slice(&self.0[..16]);
        id
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

/// A token that is not the exact canonical form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenRefusal;

impl fmt::Display for TokenRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid token form")
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
    // bits, so the last sextet must be a multiple of 4.
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
    use super::{HandleToken, TokenRefusal};

    #[test]
    fn handle_forms_are_exact() {
        let handle = HandleToken::from_bytes([7_u8; 32]);
        let text = handle.as_text();
        assert_eq!(text.len(), 43);
        assert!(!text.contains('='));
        assert_eq!(HandleToken::parse(&text), Ok(handle));
        assert_eq!(HandleToken::parse(&text.to_uppercase()), Err(TokenRefusal));
        let mut noncanonical = text.clone().into_bytes();
        *noncanonical.last_mut().unwrap() = b'B';
        let mutated = String::from_utf8(noncanonical).unwrap();
        assert_eq!(HandleToken::parse(&mutated), Err(TokenRefusal));
    }

    #[test]
    fn a_minted_handle_carries_its_mailbox_id() {
        let mailbox = [9_u8; 16];
        let handle = HandleToken::mint(mailbox).unwrap();
        assert_eq!(handle.mailbox_id(), mailbox);
        assert_ne!(handle.as_bytes()[16..], [0_u8; 16]);
    }
}
