//! Station admission credentials for the mailbox transport.
//!
//! The credential is one device Ed25519 seed plus the Station-issued
//! admission token (`btm1…`). It is written owner-only through the same
//! atomic writer the fs provider uses. `mailbox_id` is learned at the
//! first READY and persisted back into the same file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::providers::fs::write_atomic;

/// What the credential file's `token` must start with.
pub const TOKEN_PREFIX: &str = "btm1.";

/// Why a credentials file was refused.
#[derive(Debug)]
pub enum CredentialsError {
    /// Storage or serialization failure.
    Io(std::io::Error),
    /// Missing, malformed, or non-canonical material.
    Invalid,
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(cause) => write!(formatter, "credentials I/O: {cause}"),
            Self::Invalid => write!(formatter, "credentials file is invalid"),
        }
    }
}

impl std::error::Error for CredentialsError {}

impl From<std::io::Error> for CredentialsError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Deserialize, Serialize)]
struct CredentialRecord {
    station: String,
    token: String,
    #[serde(rename = "deviceSecret")]
    device_secret: String,
    #[serde(rename = "mailboxId", skip_serializing_if = "Option::is_none")]
    mailbox_id: Option<String>,
}

/// One admission credential: the Station base URL, the `btm1` token, the
/// device Ed25519 seed, and the learned mailbox identity.
pub struct Credentials {
    station: String,
    token: Zeroizing<String>,
    device_secret: Zeroizing<[u8; 32]>,
    mailbox_id: Option<[u8; 16]>,
    store: Option<PathBuf>,
}

impl Credentials {
    /// Loads one credentials file. Missing, malformed, or non-canonical
    /// material is refused before any network use.
    pub fn load(store: &Path) -> Result<Self, CredentialsError> {
        let text = Zeroizing::new(std::fs::read_to_string(store)?);
        let record: CredentialRecord =
            serde_json::from_str(&text).map_err(|_| CredentialsError::Invalid)?;
        if !record.token.starts_with(TOKEN_PREFIX) {
            return Err(CredentialsError::Invalid);
        }
        let secret_vec = decode_base64(&record.device_secret)?;
        if secret_vec.len() != 32 {
            return Err(CredentialsError::Invalid);
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(&secret_vec);
        let mailbox_id = record
            .mailbox_id
            .map(|value| decode_base64(&value))
            .transpose()?;
        if mailbox_id.as_ref().is_some_and(|id| id.len() != 16) {
            return Err(CredentialsError::Invalid);
        }
        let mut id = [0_u8; 16];
        if let Some(bytes) = mailbox_id.as_ref() {
            id.copy_from_slice(bytes.as_slice());
        }
        Ok(Self {
            station: record.station,
            token: Zeroizing::new(record.token),
            device_secret: secret,
            mailbox_id: mailbox_id.map(|_| id),
            store: Some(store.to_path_buf()),
        })
    }

    /// Builds one fresh credential set (new device key) in memory.
    pub fn mint(station: String, token: String, store: PathBuf) -> Result<Self, CredentialsError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(CredentialsError::Invalid);
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut secret[..]).map_err(|_| CredentialsError::Invalid)?;
        Ok(Self {
            station,
            token: Zeroizing::new(token),
            device_secret: secret,
            mailbox_id: None,
            store: Some(store),
        })
    }

    /// Builds one credential set directly from its parts — no file I/O.
    /// `store` is `None`; callers that keep the device secret in an OS
    /// secret store construct this way and never touch `load`/`save`.
    pub fn new(
        station: String,
        token: String,
        device_secret: Zeroizing<[u8; 32]>,
        mailbox_id: Option<[u8; 16]>,
    ) -> Result<Self, CredentialsError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(CredentialsError::Invalid);
        }
        Ok(Self {
            station,
            token: Zeroizing::new(token),
            device_secret,
            mailbox_id,
            store: None,
        })
    }

    /// Persists the current record owner-only (0600, atomic).
    pub fn save(&self) -> Result<(), CredentialsError> {
        let Some(store) = self.store.clone() else {
            return Err(CredentialsError::Io(std::io::Error::other(
                "no credentials file bound",
            )));
        };
        let record = CredentialRecord {
            station: self.station.clone(),
            token: self.token.as_str().to_owned(),
            device_secret: encode_base64(&self.device_secret[..]),
            mailbox_id: self.mailbox_id.map(|id| encode_base64(&id)),
        };
        let text = serde_json::to_string_pretty(&record).map_err(|_| CredentialsError::Invalid)?;
        write_atomic(&store, text.as_bytes()).map_err(CredentialsError::Io)
    }

    #[must_use]
    pub fn station(&self) -> &str {
        &self.station
    }

    /// The admission token for the `Authorization: Bearer` header.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// The device Ed25519 seed for the HELLO signature.
    #[must_use]
    pub fn device_secret(&self) -> &[u8; 32] {
        &self.device_secret
    }

    /// The mailbox id learned at READY, when bound.
    #[must_use]
    pub const fn mailbox_id(&self) -> Option<[u8; 16]> {
        self.mailbox_id
    }

    /// Records the mailbox id learned at READY. File-bound credentials
    /// persist it immediately; file-less ones just update the value.
    pub fn bind_mailbox(&mut self, mailbox_id: [u8; 16]) -> Result<(), CredentialsError> {
        if self.mailbox_id.is_none() {
            self.mailbox_id = Some(mailbox_id);
            self.save().or_else(|error| {
                if self.store.is_none() {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        }
        Ok(())
    }
}

/// Standard base64 decode for credential material (not wire-canonical
/// base64url — the file format is a local concern).
fn decode_base64(text: &str) -> Result<Vec<u8>, CredentialsError> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(CredentialsError::Invalid);
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'=' {
            if index < bytes.len() - 2 || (index == bytes.len() - 2 && bytes[index + 1] != b'=') {
                return Err(CredentialsError::Invalid);
            }
            continue;
        }
        let value = T
            .iter()
            .position(|&c| c == byte)
            .ok_or(CredentialsError::Invalid)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

fn encode_base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let a = u32::from(chunk[0]);
        let b = u32::from(*chunk.get(1).unwrap_or(&0));
        let c = u32::from(*chunk.get(2).unwrap_or(&0));
        let v = (a << 16) | (b << 8) | c;
        out.push(T[((v >> 18) & 63) as usize] as char);
        out.push(T[((v >> 12) & 63) as usize] as char);
        out.push(if n > 1 {
            T[((v >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if n > 2 {
            T[(v & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
