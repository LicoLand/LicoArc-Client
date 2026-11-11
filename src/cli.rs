//! The standalone `licoarc-client` command line.
//!
//! This slice exposes the carrier directly — the minimal loop two
//! processes can close over one Station without an endpoint session.
//!
//! Commands drive both the endpoint lifecycle and the mailbox transport:
//!
//! ```text
//! licoarc-client enroll --station URL --invitation-file PATH --credentials FILE [--ca PATH]
//! licoarc-client handle --credentials FILE
//! licoarc-client send --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]
//! licoarc-client receive --credentials FILE --spool DIR [--follow] [--ca PATH]
//! licoarc-client init --dir DIR --authority BUNDLE
//! licoarc-client offer --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]
//! licoarc-client begin --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]
//! licoarc-client accept --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]
//! licoarc-client finish --dir DIR --authority BUNDLE [--in FILE|-]
//! licoarc-client dispatch --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--out DIR] [--ca PATH]
//! licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]
//! licoarc-client record-read --dir DIR --role responder|initiator --authority BUNDLE --spool DIR --handle TOKEN --out DIR
//! ```
//!
//! One `--dir` is one endpoint in one role: `custody.index`,
//! `identity.json`, the shareable `peer-identity.json`, and the sealed
//! `endpoint.checkpoint` live there, so every command resumes exactly where
//! the last one committed.
//!
//! `--ca PATH` adds one trust root (PEM) for locally operated Stations with
//! development certificates; production listeners validate against the
//! system verifier.
//!
use licoarc::provider::{DigestProvider, RustCryptoProvider};
use licoarc::state::PlaintextReceiver;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::adapters::PacketCarrierAdapter;
use crate::carrier::{Credentials, Event, HandleToken, MailboxClient, StationError, SubmitCarrier};
use crate::inbound::EndpointConsumer;
use crate::ports::Clock;
use crate::providers::FileCustody;
use crate::runtime::{
    EndpointSink, LoopExit, PacketSink, Spool, Verdict, drain_pending, receive_loop,
};
use crate::session::{
    InitiatorDrive, LocalIdentity, PairingOffer, ResponderDrive, StaticTrust, SystemClock,
    load_peer_identity,
};
use crate::{AuthorityInput, Error};

/// The process exit code the caller sees.
pub struct Exit(pub i32);

impl Exit {
    const USAGE: Self = Self(2);
    const FAILURE: Self = Self(1);
}

/// One invocation: parse, run, render.
pub fn run(arguments: &[String], out: &mut impl Write, err: &mut impl Write) -> Exit {
    let Some(command) = arguments.get(1) else {
        return usage(err);
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        return usage(err);
    }
    let options = match Options::parse(&arguments[2..]) {
        Ok(options) => options,
        Err(message) => {
            let _ = writeln!(err, "licoarc-client: {message}");
            return usage(err);
        }
    };
    if options.flag("help") {
        return usage(err);
    }
    // Multi-thread so the spawned mailbox io_loop keeps advancing while the
    // protocol thread blocks inside SubmitCarrier's private runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "licoarc-client: tokio runtime: {error}");
            return Exit::FAILURE;
        }
    };
    let result = dispatch(command.as_str(), &options, &runtime, out);
    match result {
        Ok(()) => Exit(0),
        Err(message) => {
            let _ = writeln!(err, "licoarc-client: {message}");
            Exit::FAILURE
        }
    }
}

fn usage(err: &mut impl Write) -> Exit {
    let _ = err.write_all(
        b"usage:\n  licoarc-client enroll --station URL --invitation-file PATH --credentials FILE [--ca PATH]\n  licoarc-client handle --credentials FILE\n  licoarc-client send --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]\n  licoarc-client receive --credentials FILE --spool DIR [--follow] [--ca PATH]\n  licoarc-client init --dir DIR --authority BUNDLE\n  licoarc-client offer --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]\n  licoarc-client begin --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]\n  licoarc-client accept --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]\n  licoarc-client finish --dir DIR --authority BUNDLE [--in FILE|-]\n  licoarc-client dispatch --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--out DIR] [--ca PATH]\n  licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]\n  licoarc-client record-read --dir DIR --role responder|initiator --authority BUNDLE --spool DIR --handle TOKEN --out DIR\n",
    );
    Exit::USAGE
}

struct Options {
    values: std::collections::BTreeMap<String, String>,
    flags: std::collections::BTreeSet<String>,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut options = Self {
            values: std::collections::BTreeMap::new(),
            flags: std::collections::BTreeSet::new(),
        };
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            let Some(name) = argument.strip_prefix("--") else {
                return Err(format!("unexpected argument: {argument}"));
            };
            if index + 1 < arguments.len() && !arguments[index + 1].starts_with("--") {
                options
                    .values
                    .insert(name.to_owned(), arguments[index + 1].clone());
                index += 2;
            } else {
                options.flags.insert(name.to_owned());
                index += 1;
            }
        }
        Ok(options)
    }

    fn require(&self, name: &str) -> Result<String, String> {
        self.values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn optional(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

fn credentials_path(options: &Options) -> Result<PathBuf, String> {
    Ok(PathBuf::from(options.require("credentials")?))
}

fn credentials(options: &Options) -> Result<Credentials, String> {
    let path = credentials_path(options)?;
    Credentials::load(&path).map_err(|error| format!("--credentials: {error}"))
}

fn extra_roots(options: &Options) -> Result<Vec<PathBuf>, String> {
    Ok(match options.optional("ca") {
        Some(path) => vec![PathBuf::from(path)],
        None => vec![],
    })
}

/// Connects one mailbox client from `--credentials` (and optional `--ca`).
fn connect(options: &Options, rt: &tokio::runtime::Runtime) -> Result<Arc<MailboxClient>, String> {
    let credentials = credentials(options)?;
    let roots = extra_roots(options)?;
    rt.block_on(MailboxClient::connect(&credentials, &roots))
        .map(Arc::new)
        .map_err(station_error)
}

fn handle(options: &Options) -> Result<HandleToken, String> {
    HandleToken::parse(&options.require("handle")?)
        .map_err(|_| "invalid --handle (expected the 43-character handle token)".to_owned())
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", bytes.len()));
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(
            std::str::from_utf8(&bytes[index * 2..index * 2 + 2])
                .map_err(|_| "invalid hex".to_owned())?,
            16,
        )
        .map_err(|_| "invalid hex".to_owned())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            acc.push(DIGITS[(byte >> 4) as usize] as char);
            acc.push(DIGITS[(byte & 0xf) as usize] as char);
            acc
        })
}

fn station_error(error: StationError) -> String {
    error.to_string()
}

/// The dispatch stays synchronous: every carrier leaf call drives the
/// runtime itself, which keeps the SDK's synchronous boundary — and
/// [`SubmitCarrier`]'s private `block_on` — out of any runtime context.
fn dispatch(
    command: &str,
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    match command {
        "enroll" => {
            let invitation_path = options.require("invitation-file")?;
            let token = std::fs::read_to_string(&invitation_path)
                .map_err(|error| format!("--invitation-file {invitation_path}: {error}"))?
                .trim()
                .to_owned();
            let path = credentials_path(options)?;
            let credentials = Credentials::mint(options.require("station")?, token, path.clone())
                .map_err(|error| format!("credentials: {error}"))?;
            let roots = extra_roots(options)?;
            let client = rt
                .block_on(MailboxClient::connect(&credentials, &roots))
                .map_err(station_error)?;
            let mut credentials = credentials;
            credentials
                .bind_mailbox(client.mailbox_id())
                .map_err(|error| format!("credentials: {error}"))?;
            let handle = credentials
                .mailbox_id()
                .ok_or_else(|| "station did not bind a mailbox".to_owned())
                .and_then(|id| HandleToken::mint(id).map_err(|error| error.to_string()))?;
            writeln!(out, "{{\"handle\":\"{}\"}}", handle.as_text())
                .map_err(|error| error.to_string())
        }
        "handle" => {
            let credentials = credentials(options)?;
            let handle = credentials
                .mailbox_id()
                .ok_or_else(|| "credentials have no bound mailbox yet".to_owned())
                .and_then(|id| HandleToken::mint(id).map_err(|error| error.to_string()))?;
            writeln!(out, "{{\"handle\":\"{}\"}}", handle.as_text())
                .map_err(|error| error.to_string())
        }
        "send" => {
            let client = connect(options, rt)?;
            let packet = read_packet(options)?;
            rt.block_on(client.send(handle(options)?, &packet))
                .map_err(station_error)?;
            writeln!(out, "{{\"submitted\":true}}").map_err(|error| error.to_string())
        }
        "receive" => receive(options, rt, out),
        "init" => init(options, out),
        "offer" => offer(options, out),
        "begin" => begin(options, out),
        "accept" => accept(options, out),
        "finish" => finish(options, out),
        "dispatch" => flush_pending(options, rt, out),
        "record-send" => record_send(options, rt, out),
        "record-read" => record_read(options, out),
        other => Err(format!("unknown command {other}")),
    }
}

fn read_packet(options: &Options) -> Result<Vec<u8>, String> {
    match options.optional("file").unwrap_or("-") {
        "-" => {
            let mut packet = Vec::new();
            std::io::stdin()
                .read_to_end(&mut packet)
                .map_err(|error| format!("stdin: {error}"))?;
            Ok(packet)
        }
        path => std::fs::read(path).map_err(|error| format!("--file {path}: {error}")),
    }
}

/// Optional `--out`: absent means plaintexts go to the command's own writer.
fn optional_sink_dir(options: &Options) -> Option<PathBuf> {
    match options.optional("out").unwrap_or("-") {
        "-" => None,
        path => Some(PathBuf::from(path)),
    }
}

/// Receives deliveries into the local spool. Without `--follow` it drains
/// until the Station reports the mailbox empty; with `--follow` it keeps
/// the lane until SIGINT or a terminal error.
fn receive(
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let credentials = credentials(options)?;
    let roots = extra_roots(options)?;
    let mut spool = Spool::open(&PathBuf::from(options.require("spool")?))
        .map_err(|error| format!("spool: {error}"))?;
    if options.flag("follow") {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        std::thread::spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = std::io::stdin().read(&mut byte);
            let _ = stop_tx.send(true);
        });
        match rt.block_on(receive_loop(&credentials, &roots, &mut spool, stop_rx)) {
            LoopExit::Stopped => {
                writeln!(out, "{{\"stopped\":true}}").map_err(|error| error.to_string())
            }
            LoopExit::Failed(error) => Err(station_error(error)),
        }
    } else {
        let mut client = rt
            .block_on(MailboxClient::connect(&credentials, &roots))
            .map_err(station_error)?;
        let mut delivered = 0_u64;
        loop {
            match rt.block_on(client.next()) {
                Ok(Event::Deliver {
                    sequence,
                    handle,
                    packet,
                }) => {
                    if spool.accept(sequence, handle, &packet) != Verdict::Done {
                        return Err("spool refused a delivery".to_owned());
                    }
                    rt.block_on(client.ack(sequence)).map_err(station_error)?;
                    delivered += 1;
                }
                Ok(Event::Drained) => break,
                Err(error) => return Err(station_error(error)),
            }
        }
        writeln!(out, "{{\"delivered\":{delivered}}}").map_err(|error| error.to_string())
    }
}

// ---------------------------------------------------------------------------
// Endpoint-session commands
// ---------------------------------------------------------------------------

fn dir_path(options: &Options) -> Result<PathBuf, String> {
    Ok(PathBuf::from(options.require("dir")?))
}

fn authority(options: &Options) -> Result<crate::VerifiedProtocolLine, String> {
    let path = options.require("authority")?;
    let bytes = std::fs::read(&path).map_err(|error| format!("--authority {path}: {error}"))?;
    AuthorityInput::new(&bytes)
        .admit()
        .map_err(|refusal| format!("authority bundle refused: {refusal}"))
}

fn authority_digest(options: &Options) -> Result<[u8; 32], String> {
    hex32(&options.require("authority-digest")?)
}

fn peer_identity(options: &Options) -> Result<licoarc::endpoint::IdentityPublic, String> {
    let path = options.require("peer")?;
    load_peer_identity(Path::new(&path)).map_err(|error| format!("--peer {path}: {error}"))
}

fn read_input(options: &Options) -> Result<Vec<u8>, String> {
    match options.optional("in").unwrap_or("-") {
        "-" => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|error| format!("stdin: {error}"))?;
            Ok(bytes)
        }
        path => std::fs::read(path).map_err(|error| format!("--in {path}: {error}")),
    }
}

fn write_output(options: &Options, bytes: &[u8], out: &mut impl Write) -> Result<(), String> {
    match options.optional("out").unwrap_or("-") {
        "-" => out.write_all(bytes).map_err(|error| error.to_string()),
        path => std::fs::write(path, bytes).map_err(|error| format!("--out {path}: {error}")),
    }
}

fn custody(dir: &Path) -> Result<FileCustody<RustCryptoProvider>, String> {
    FileCustody::open(dir, RustCryptoProvider).map_err(|refusal| format!("custody: {refusal}"))
}

fn responder_drive(options: &Options) -> Result<ResponderDrive<RustCryptoProvider>, String> {
    let line = authority(options)?;
    let dir = dir_path(options)?;
    let custody = custody(&dir)?;
    ResponderDrive::open(&dir, line, custody, RustCryptoProvider)
        .map_err(|refusal| format!("endpoint: {refusal}"))
}

fn initiator_drive(options: &Options) -> Result<InitiatorDrive<RustCryptoProvider>, String> {
    let line = authority(options)?;
    let dir = dir_path(options)?;
    let custody = custody(&dir)?;
    InitiatorDrive::open(&dir, line, custody, RustCryptoProvider)
        .map_err(|refusal| format!("endpoint: {refusal}"))
}

/// One endpoint directory's own identity; `identity.json` is private to the
/// owner and `peer-identity.json` is the shareable public descriptor.
fn init(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let dir = dir_path(options)?;
    std::fs::create_dir_all(&dir).map_err(|error| format!("--dir: {error}"))?;
    #[cfg(unix)]
    {
        // Owner-only, like the credentials and spool directories.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("--dir: {error}"))?;
    }
    let mut custody = custody(&dir)?;
    let identity = match LocalIdentity::load(&dir) {
        Ok(identity) => identity,
        Err(_) => {
            let identity =
                LocalIdentity::mint(&mut custody).map_err(|error| format!("mint: {error}"))?;
            identity
                .persist(&dir)
                .map_err(|error| format!("identity.json: {error}"))?;
            identity
        }
    };
    identity
        .persist_peer(&dir)
        .map_err(|error| format!("peer-identity.json: {error}"))?;
    writeln!(
        out,
        "{{\"stateDigest\":\"{}\"}}",
        hex(&identity.public().state_digest)
    )
    .map_err(|error| error.to_string())
}

/// Responder: admit one prekey and emit the [`PairingOffer`] the initiator
/// answers. The caller publishes the bytes itself — `send` to the initiator's
/// bootstrap handle, or an out-of-band channel.
fn offer(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let mut drive = responder_drive(options)?;
    let identity =
        LocalIdentity::load(&dir_path(options)?).map_err(|error| format!("identity: {error}"))?;
    let handle = handle(options)?;
    let sequence = options.optional("sequence").map_or(Ok(1_u64), |text| {
        text.parse::<u64>()
            .map_err(|_| "invalid --sequence".to_owned())
    })?;
    let now = SystemClock
        .now_unix_seconds()
        .map_err(|_| "clock unavailable".to_owned())?;
    let from = options.optional("from").map_or(Ok(now), |text| {
        text.parse::<u64>().map_err(|_| "invalid --from".to_owned())
    })?;
    let until = options.optional("until").map_or(Ok(now + 86_400), |text| {
        text.parse::<u64>()
            .map_err(|_| "invalid --until".to_owned())
    })?;
    let offer = drive
        .issue_offer(
            &identity,
            authority_digest(options)?,
            handle,
            sequence,
            from,
            until,
        )
        .map_err(|refusal| format!("offer: {refusal}"))?;
    let bytes = offer
        .encode()
        .map_err(|_| "offer encode failed".to_owned())?;
    write_output(options, &bytes, out)
}

/// Initiator: answer the offer with a [`PairingSubmission`] bound to the
/// caller's own reply handle.
fn begin(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let mut drive = initiator_drive(options)?;
    let identity =
        LocalIdentity::load(&dir_path(options)?).map_err(|error| format!("identity: {error}"))?;
    let offer_bytes = match options.optional("offer").unwrap_or("-") {
        "-" => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|error| format!("stdin: {error}"))?;
            bytes
        }
        path => std::fs::read(path).map_err(|error| format!("--offer {path}: {error}"))?,
    };
    let offer =
        PairingOffer::decode(&offer_bytes).map_err(|_| "invalid pairing offer".to_owned())?;
    let reply_handle = HandleToken::parse(&options.require("reply-handle")?)
        .map_err(|_| "invalid --reply-handle".to_owned())?;
    let bytes = drive
        .begin(
            &EndpointConsumer::new(),
            &identity,
            authority_digest(options)?,
            &offer,
            reply_handle,
            &StaticTrust::for_identity(&offer.identity),
            &SystemClock,
        )
        .map_err(|refusal| format!("begin: {refusal}"))?;
    write_output(options, &bytes, out)
}

/// Responder: authenticate one claimed submission against the peer's
/// published identity and emit the [`crate::PairingReply`].
fn accept(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let mut drive = responder_drive(options)?;
    let identity =
        LocalIdentity::load(&dir_path(options)?).map_err(|error| format!("identity: {error}"))?;
    let peer = peer_identity(options)?;
    let submission = read_input(options)?;
    let session_handle = HandleToken::parse(&options.require("session-handle")?)
        .map_err(|_| "invalid --session-handle".to_owned())?;
    let mut trust = StaticTrust::new();
    trust.register(peer.clone());
    let (reply, _session, _facts) = drive
        .accept(
            &EndpointConsumer::new(),
            peer,
            &identity,
            authority_digest(options)?,
            &trust,
            session_handle,
            &submission,
            &SystemClock,
        )
        .map_err(|refusal| format!("accept: {refusal}"))?;
    let bytes = reply
        .encode()
        .map_err(|_| "reply encode failed".to_owned())?;
    write_output(options, &bytes, out)
}

/// Initiator: verify the reply and report the established session handle.
fn finish(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let mut drive = initiator_drive(options)?;
    let reply = read_input(options)?;
    let (accept, session_handle) = drive
        .finish(&reply)
        .map_err(|refusal| format!("finish: {refusal}"))?;
    writeln!(
        out,
        "{{\"sessionHandle\":\"{}\",\"pairSequence\":{},\"transcriptDigest\":\"{}\"}}",
        session_handle.as_text(),
        accept.pair_sequence,
        hex(&accept.transcript_digest)
    )
    .map_err(|error| error.to_string())
}

/// The caller's plaintext receiver: each released record lands in
/// `dir/<digest>.record`, or raw on the command's writer.
struct PlaintextSink<'a> {
    dir: Option<PathBuf>,
    out: &'a mut dyn Write,
}

impl PlaintextReceiver for PlaintextSink<'_> {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let failed = || Error::terminal(crate::ErrorCode::ProviderFailure, crate::Stage::Provider);
        match &self.dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).map_err(|_| failed())?;
                let digest = licoarc::provider::fixed_provider().sha256(plaintext);
                crate::providers::fs::write_atomic(
                    &dir.join(format!("{}.record", hex(&digest))),
                    plaintext,
                )
                .map_err(|_| failed())
            }
            None => self.out.write_all(plaintext).map_err(|_| failed()),
        }
    }
}

/// Effects the standalone CLI cannot express are refused; session traffic is
/// packet-shaped here.
struct NoEffects;

impl licoarc::state::ApplicationEffects for NoEffects {
    fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
        Err(Error::terminal(
            crate::ErrorCode::ProviderFailure,
            crate::Stage::Provider,
        ))
    }
}

/// `dispatch --dir DIR --role responder|initiator --authority FILE
/// --station URL --handle TOKEN [--out DIR]`
///
/// Drains the endpoint's durable pending ledger through the carrier: packets
/// and effects are submitted to the given handle and settled on acceptance,
/// plaintexts are released to `--out` when one is supplied. Pairing envelopes
/// written by `begin`/`accept` stay pending until this (or an embedded
/// dispatch) settles them — the ledger, not the transport, owns the retry.
fn flush_pending(
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let client = connect(options, rt)?;
    let handle = handle(options)?;
    let mut carrier = PacketCarrierAdapter::new(
        SubmitCarrier::new(client, handle).map_err(|failure| format!("transport: {failure}"))?,
    );
    let mut plaintext = PlaintextSink {
        dir: optional_sink_dir(options),
        out,
    };
    let report = match options.require("role")?.as_str() {
        "responder" => {
            let mut drive = responder_drive(options)?;
            let report = drain_pending(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                &mut carrier,
                &mut NoEffects,
                &mut plaintext,
            )
            .map_err(|error| format!("drain: {error:?}"))?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            report
        }
        "initiator" => {
            let mut drive = initiator_drive(options)?;
            let report = drain_pending(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                &mut carrier,
                &mut NoEffects,
                &mut plaintext,
            )
            .map_err(|error| format!("drain: {error:?}"))?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            report
        }
        other => return Err(format!("unknown --role {other}")),
    };
    writeln!(
        out,
        "{{\"settled\":{},\"released\":{},\"failed\":{}}}",
        report.settled.len(),
        report.released.len(),
        report.failed.len()
    )
    .map_err(|error| error.to_string())
}

/// The responder's first send needs a fresh staged X25519 for the DH
/// ratchet step — `send_record` reports `InvalidTransition` without it, so
/// stage through the drive's custody (the same `Rc`-shared index the
/// endpoint resolves) and retry once.
fn send_record_maybe_bootstrap<R, C, S>(
    endpoint: &mut licoarc::endpoint::Endpoint<R, RustCryptoProvider, C, S>,
    mut custody: FileCustody<RustCryptoProvider>,
    plaintext: &[u8],
) -> Result<licoarc::state::PendingId, String>
where
    R: licoarc::endpoint::Role,
    C: licoarc::state::KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
{
    match endpoint.send_record(plaintext, None) {
        Err(error) if error.code == crate::ErrorCode::InvalidTransition => {
            let staged = custody
                .stage(crate::ports::CustodyPurpose::X25519Private)
                .map_err(|refusal| format!("custody: {refusal}"))?;
            endpoint
                .send_record(
                    plaintext,
                    Some(licoarc::state::StagedSecretHandle::<
                        licoarc::state::X25519Private,
                    >::from_custody_token(
                        staged.custody_token()
                    )),
                )
                .map_err(|error| format!("send: {error:?}"))
        }
        other => other.map_err(|error| format!("send: {error:?}")),
    }
}

/// Sends one plaintext as a protected record to the session handle.
fn record_send(
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let plaintext = read_packet(options)?;
    let client = connect(options, rt)?;
    let handle = handle(options)?;
    match options.require("role")?.as_str() {
        "responder" => {
            let mut drive = responder_drive(options)?;
            let custody = drive.custody_mut().clone();
            let pending = send_record_maybe_bootstrap(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                custody,
                &plaintext,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            let mut carrier = PacketCarrierAdapter::new(
                SubmitCarrier::new(client, handle)
                    .map_err(|failure| format!("transport: {failure}"))?,
            );
            drive
                .endpoint()
                .map_err(|refusal| format!("endpoint: {refusal}"))?
                .dispatch_pending(pending, &mut carrier, &mut NoEffects)
                .map_err(|error| format!("dispatch: {error:?}"))?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))
        }
        "initiator" => {
            let mut drive = initiator_drive(options)?;
            let custody = drive.custody_mut().clone();
            let pending = send_record_maybe_bootstrap(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                custody,
                &plaintext,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            let mut carrier = PacketCarrierAdapter::new(
                SubmitCarrier::new(client, handle)
                    .map_err(|failure| format!("transport: {failure}"))?,
            );
            drive
                .endpoint()
                .map_err(|refusal| format!("endpoint: {refusal}"))?
                .dispatch_pending(pending, &mut carrier, &mut NoEffects)
                .map_err(|error| format!("dispatch: {error:?}"))?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))
        }
        other => return Err(format!("unknown --role {other}")),
    }?;
    writeln!(out, "{{\"submitted\":true}}").map_err(|error| error.to_string())
}

/// Reads one handle's spool files through the resumed endpoint — the local
/// half of `receive`, with no Station traffic of its own. Committed packets
/// are deleted, permanently refused ones move to `refused/`.
fn record_read(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let spool = Spool::open(&PathBuf::from(options.require("spool")?))
        .map_err(|error| format!("spool: {error}"))?;
    let handle = handle(options)?;
    let stored = spool
        .stored(handle)
        .map_err(|error| format!("spool: {error}"))?;
    let sink_dir = match options.require("out")?.as_str() {
        "-" => None,
        path => Some(PathBuf::from(path)),
    };
    match options.require("role")?.as_str() {
        "responder" => {
            let mut drive = responder_drive(options)?;
            let custody = drive.custody_mut().clone();
            let (received, refused) = read_spool(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                custody,
                &spool,
                &stored,
                sink_dir,
                out,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            report(out, received, refused)
        }
        "initiator" => {
            let mut drive = initiator_drive(options)?;
            let custody = drive.custody_mut().clone();
            let (received, refused) = read_spool(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                custody,
                &spool,
                &stored,
                sink_dir,
                out,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            report(out, received, refused)
        }
        other => Err(format!("unknown --role {other}")),
    }
}

fn report(out: &mut impl Write, received: usize, refused: usize) -> Result<(), String> {
    writeln!(out, "{{\"received\":{received},\"refused\":{refused}}}")
        .map_err(|error| error.to_string())
}

fn read_spool<R, C, S>(
    endpoint: &mut licoarc::endpoint::Endpoint<R, RustCryptoProvider, C, S>,
    mut custody: FileCustody<RustCryptoProvider>,
    spool: &Spool,
    stored: &[(u64, PathBuf)],
    sink_dir: Option<PathBuf>,
    out: &mut dyn Write,
) -> Result<(usize, usize), String>
where
    R: licoarc::endpoint::Role,
    C: licoarc::state::KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
{
    // A peer's first send rotates the DH ratchet — every record may need a
    // fresh staged X25519 from the endpoint's own custody (shared handle).
    let fresh = move || {
        custody
            .stage(crate::ports::CustodyPurpose::X25519Private)
            .ok()
            .map(|handle| {
                licoarc::state::StagedSecretHandle::<licoarc::state::X25519Private>::from_custody_token(
                    handle.custody_token(),
                )
            })
    };
    let mut sink = EndpointSink::with_fresh(endpoint, PlaintextSink { dir: sink_dir, out }, fresh);
    let mut marks = Vec::with_capacity(stored.len());
    for (seq, path) in stored {
        let packet = std::fs::read(path).map_err(|error| format!("{path:?}: {error}"))?;
        let refused_before = sink.refused().len();
        // `EndpointSink::accept` ignores the handle; a fixed placeholder
        // token keeps the call well-formed without drawing entropy.
        sink.accept(*seq, HandleToken::from_bytes([0_u8; 32]), &packet);
        marks.push(sink.refused().len() > refused_before);
    }
    for ((_, path), refused_file) in stored.iter().zip(marks.iter()) {
        spool
            .resolve(path, *refused_file)
            .map_err(|error| format!("spool: {error}"))?;
    }
    Ok((sink.received().len(), sink.refused().len()))
}
