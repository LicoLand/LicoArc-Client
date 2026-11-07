//! BadTower access-grant credentials and per-request proofs.
//!
//! A capability-gated Station admits one Ed25519 request proof per attempt:
//! the `bta2` access token in the Authorization header plus the three
//! `badtower-proof-*` headers. The signed transcript binds the capability
//! digest, the exact request target, the media type, the exact content
//! length, the operation identifier, the body digest, an issue timestamp,
//! and a strictly monotonic counter. One credentials file owns one grant;
//! the counter is persisted through that file before any request leaves, so
//! no crash or rerun can ever replay a number the Station already charged.

use licoarc::provider::{DigestProvider, SignatureProvider, fixed_provider};
use serde::Deserialize;
use serde::Serialize;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::token::OperationId;

const EXCHANGE_PATH: &str = "/v1/invitations/exchange";
const EXCHANGE_MEDIA_TYPE: &str = "application/json";
const PROOF_DOMAIN: &[u8] = b"badtower-request-proof-v2";
const ACCESS_PREFIX: &str = "bta2.";

/// The bearer header carrying the `bta2` capability.
pub const AUTHORIZATION_HEADER: &str = "authorization";
/// Canonical-decimal issue timestamp (unix milliseconds).
pub const PROOF_ISSUED_AT_HEADER: &str = "badtower-proof-issued-at";
/// Canonical-decimal strictly monotonic grant counter.
pub const PROOF_COUNTER_HEADER: &str = "badtower-proof-counter";
/// Unpadded-base64url Ed25519 signature over the request transcript.
pub const PROOF_SIGNATURE_HEADER: &str = "badtower-proof-signature";

/// Everything loading, storing, or proving one grant can end in.
#[derive(Debug)]
pub enum AccessError {
    /// The credentials file could not be read, written, or exchanged safely.
    Io(std::io::Error),
    /// The credentials file is malformed or names a wrong capability shape.
    Invalid,
    /// The Station refused the invitation exchange.
    ExchangeRejected,
    /// The credentials store already holds a grant the exchange would
    /// overwrite.
    StoreExists,
}

impl core::fmt::Display for AccessError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "access credential I/O: {error}"),
            Self::Invalid => formatter.write_str("invalid access credentials"),
            Self::ExchangeRejected => {
                formatter.write_str("station rejected the invitation exchange")
            }
            Self::StoreExists => formatter.write_str("access credentials store already exists"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<std::io::Error> for AccessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The on-disk credential record. The secret key is the device's Ed25519
/// seed; the counter is the last persisted proof number.
#[derive(Deserialize, Serialize)]
struct GrantRecord {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "secretKey")]
    secret_key: String,
    counter: u64,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// One signed request proof: the three header values plus the counter that
/// produced them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessProof {
    pub issued_at: u64,
    pub counter: u64,
    pub signature: String,
}

/// One live grant: the capability token, the device's Ed25519 material, and
/// the persisted monotonic counter.
pub struct AccessGrant {
    token: String,
    public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    counter: u64,
    expires_at: Option<String>,
    store: PathBuf,
}

impl AccessGrant {
    /// Loads one credentials file. Missing, malformed, or non-canonical
    /// material is refused before any network use.
    pub fn load(store: &Path) -> Result<Self, AccessError> {
        let text = Zeroizing::new(std::fs::read_to_string(store)?);
        let record: GrantRecord = serde_json::from_str(&text).map_err(|_| AccessError::Invalid)?;
        if !record.access_token.starts_with(ACCESS_PREFIX) {
            return Err(AccessError::Invalid);
        }
        let public = decode_base64url(&record.public_key)?;
        let secret = Zeroizing::new(decode_base64url(&record.secret_key)?);
        if fixed_provider().ed25519_public(&secret) != public {
            return Err(AccessError::Invalid);
        }
        Ok(Self {
            token: record.access_token,
            public,
            secret,
            counter: record.counter,
            expires_at: record.expires_at,
            store: store.to_path_buf(),
        })
    }

    /// The capability token for the Authorization header.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The credential's expiry statement as issued, when present.
    #[must_use]
    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }

    /// Mints the next proof for one canonical request attempt.
    ///
    /// The counter is advanced and persisted *before* the signature exists,
    /// so a crash between proving and sending can only skip numbers, never
    /// replay one.
    pub fn prove(
        &mut self,
        path: &str,
        media_type: &str,
        content_length: u64,
        operation_id: &OperationId,
        body_digest: &[u8; 32],
    ) -> Result<AccessProof, AccessError> {
        self.counter = self.counter.checked_add(1).ok_or(AccessError::Invalid)?;
        self.store()?;
        let issued_at = unix_ms();
        let capability_digest = fixed_provider().sha256(self.token.as_bytes());
        let transcript = encode_request_proof(
            &capability_digest,
            &ProofTarget {
                path,
                media_type,
                content_length,
                operation_id: operation_id.as_bytes(),
                body_digest,
            },
            issued_at,
            self.counter,
        );
        let signature = fixed_provider().ed25519_sign(&self.secret, &transcript);
        Ok(AccessProof {
            issued_at,
            counter: self.counter,
            signature: encode_base64url(&signature),
        })
    }

    /// Atomically replaces the credentials file (tmp write + rename), so a
    /// crash never leaves a half-written counter behind.
    fn store(&self) -> Result<(), AccessError> {
        let record = GrantRecord {
            access_token: self.token.clone(),
            public_key: encode_base64url(&self.public),
            secret_key: encode_base64url(&self.secret[..]),
            counter: self.counter,
            expires_at: self.expires_at.clone(),
        };
        let text =
            Zeroizing::new(serde_json::to_string(&record).map_err(|_| AccessError::Invalid)?);
        let temporary = self.store.with_extension("tmp");
        write_owner_only(&temporary, text.as_bytes())?;
        std::fs::rename(&temporary, &self.store)?;
        // The rename is only durable once the directory entry is. Windows
        // has no directory fsync, so this is a unix-only step.
        #[cfg(unix)]
        if let Some(parent) = self.store.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

/// Exchanges one `bti2` invitation for a fresh grant at the data origin.
///
/// The device Ed25519 seed is generated locally and never leaves this host;
/// only the public half crosses the wire inside the fixed JSON exchange
/// shape. The returned grant is persisted to `store` before it is handed
/// back — an exchange that cannot persist its own credentials is refused.
pub async fn exchange(
    http: &reqwest::Client,
    origin: &str,
    invitation: &str,
    store: &Path,
) -> Result<AccessGrant, AccessError> {
    if !invitation.starts_with("bti2.") {
        return Err(AccessError::Invalid);
    }
    if store.exists() {
        return Err(AccessError::StoreExists);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut secret[..]).map_err(|_| AccessError::Invalid)?;
    let public = fixed_provider().ed25519_public(&secret);
    let request = serde_json::json!({
        "invitation": invitation,
        "clientPublicKey": encode_base64url(&public),
    });
    let body = request.to_string();
    let url = format!("{origin}{EXCHANGE_PATH}");
    let response = http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, EXCHANGE_MEDIA_TYPE)
        .body(body)
        .send()
        .await
        .map_err(|_| AccessError::ExchangeRejected)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(AccessError::ExchangeRejected);
    }
    let text = bounded_text(response, MAX_EXCHANGE_BODY_BYTES)
        .await
        .map_err(|_| AccessError::ExchangeRejected)?;
    let parsed: ExchangeReply =
        serde_json::from_str(&text).map_err(|_| AccessError::ExchangeRejected)?;
    if !parsed.access_token.starts_with(ACCESS_PREFIX) {
        return Err(AccessError::ExchangeRejected);
    }
    let grant = AccessGrant {
        token: parsed.access_token,
        public,
        secret,
        counter: 0,
        expires_at: parsed.expires_at,
        store: store.to_path_buf(),
    };
    grant.store()?;
    Ok(grant)
}

#[derive(Deserialize)]
struct ExchangeReply {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
}

fn unix_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

const MAX_EXCHANGE_BODY_BYTES: u64 = 16_384;

/// Reads a control-plane reply body with the same ceiling the carrier
/// applies to control responses; an oversized or declared-oversized body is
/// refused rather than buffered.
async fn bounded_text(mut response: reqwest::Response, limit: u64) -> Result<String, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(());
    }
    let mut body = Vec::<u8>::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| ())
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        // `mode` only applies to a file this call creates; an existing temp
        // file keeps its old permissions, so pin the mode on the live file.
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// The request-bound fields of one proof transcript.
struct ProofTarget<'a> {
    path: &'a str,
    media_type: &'a str,
    content_length: u64,
    operation_id: &'a [u8; 16],
    body_digest: &'a [u8; 32],
}

/// The exact `badtower-request-proof-v2` transcript: every field carried as
/// one big-endian-u32 length prefix followed by its bytes.
fn encode_request_proof(
    capability_digest: &[u8; 32],
    target: &ProofTarget<'_>,
    issued_at: u64,
    counter: u64,
) -> Vec<u8> {
    fn part(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = Vec::with_capacity(256);
    part(&mut out, PROOF_DOMAIN);
    part(&mut out, capability_digest);
    part(&mut out, b"POST");
    part(&mut out, target.path.as_bytes());
    part(&mut out, target.media_type.as_bytes());
    part(&mut out, &target.content_length.to_be_bytes());
    part(&mut out, target.operation_id);
    part(&mut out, target.body_digest);
    part(&mut out, &issued_at.to_be_bytes());
    part(&mut out, &counter.to_be_bytes());
    out
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Canonical unpadded base64url of arbitrary-length bytes.
fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let (b0, b1, b2) = (
            u32::from(group[0]),
            u32::from(*group.get(1).unwrap_or(&0)),
            u32::from(*group.get(2).unwrap_or(&0)),
        );
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64URL[(value >> 18) as usize & 63] as char);
        out.push(BASE64URL[(value >> 12) as usize & 63] as char);
        if group.len() > 1 {
            out.push(BASE64URL[(value >> 6) as usize & 63] as char);
        }
        if group.len() > 2 {
            out.push(BASE64URL[value as usize & 63] as char);
        }
    }
    out
}

/// Strict canonical decode of a 32-byte unpadded-base64url value.
fn decode_base64url(text: &str) -> Result<[u8; 32], AccessError> {
    let chars = text.as_bytes();
    if chars.len() != 43 {
        return Err(AccessError::Invalid);
    }
    let mut sextets = [0_u8; 43];
    for (index, byte) in chars.iter().enumerate() {
        sextets[index] = BASE64URL
            .iter()
            .position(|candidate| candidate == byte)
            .map(|position| position as u8)
            .ok_or(AccessError::Invalid)?;
    }
    if sextets[42] & 0b11 != 0 {
        return Err(AccessError::Invalid);
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
    use super::{
        AccessError, AccessGrant, ProofTarget, decode_base64url, encode_base64url,
        encode_request_proof,
    };

    #[test]
    fn base64url_round_trips_32_and_64_bytes() {
        let thirty_two = [0xabu8; 32];
        let sixty_four = [0xabu8; 64];
        assert_eq!(encode_base64url(&thirty_two).len(), 43);
        assert_eq!(encode_base64url(&sixty_four).len(), 86);
        assert_eq!(
            decode_base64url(&encode_base64url(&thirty_two)).unwrap(),
            thirty_two
        );
    }

    #[test]
    fn proof_transcript_uses_be_length_prefixes() {
        let digest = [0x11u8; 32];
        let operation = [0x22u8; 16];
        let transcript = encode_request_proof(
            &digest,
            &ProofTarget {
                path: "/v1/reserve",
                media_type: "application/licoarc-transport+cbor",
                content_length: 71,
                operation_id: &operation,
                body_digest: &digest,
            },
            1_000,
            7,
        );
        // Domain string: len 25 + 25 bytes.
        assert_eq!(&transcript[..4], &25_u32.to_be_bytes());
        assert_eq!(&transcript[4..29], b"badtower-request-proof-v2");
        // The exact golden transcript: every part is one BE-u32 length prefix
        // followed by its bytes (BadTower.js token.ts verifier, same order).
        let mut expected = Vec::new();
        expected.extend_from_slice(&25_u32.to_be_bytes());
        expected.extend_from_slice(b"badtower-request-proof-v2");
        expected.extend_from_slice(&32_u32.to_be_bytes());
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(&4_u32.to_be_bytes());
        expected.extend_from_slice(b"POST");
        expected.extend_from_slice(&11_u32.to_be_bytes());
        expected.extend_from_slice(b"/v1/reserve");
        expected.extend_from_slice(&34_u32.to_be_bytes());
        expected.extend_from_slice(b"application/licoarc-transport+cbor");
        expected.extend_from_slice(&8_u32.to_be_bytes());
        expected.extend_from_slice(&71_u64.to_be_bytes());
        expected.extend_from_slice(&16_u32.to_be_bytes());
        expected.extend_from_slice(&operation);
        expected.extend_from_slice(&32_u32.to_be_bytes());
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(&8_u32.to_be_bytes());
        expected.extend_from_slice(&1_000_u64.to_be_bytes());
        expected.extend_from_slice(&8_u32.to_be_bytes());
        expected.extend_from_slice(&7_u64.to_be_bytes());
        assert_eq!(transcript, expected);
    }

    #[test]
    fn load_rejects_mismatched_keypair() {
        let dir = std::env::temp_dir().join(format!("licoarc-access-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("grant.json");
        let record = serde_json::json!({
            "accessToken": "bta2.x",
            "publicKey": encode_base64url(&[1u8; 32]),
            "secretKey": encode_base64url(&[2u8; 32]),
            "counter": 0,
        });
        std::fs::write(&file, record.to_string()).unwrap();
        assert!(matches!(
            AccessGrant::load(&file),
            Err(AccessError::Invalid)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
