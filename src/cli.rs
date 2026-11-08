//! The standalone `licoarc-client` command line.
//!
//! This slice exposes the carrier directly — the honest minimal loop two
//! processes can close over one Station without an endpoint session:
//!
//! ```text
//! licoarc-client affiliate --station URL --descriptor HEX64 --commitment HEX64
//! licoarc-client reserve   --station URL --descriptor HEX64 --commitment HEX64 [--class async|first-contact]
//! licoarc-client send      --station URL --handle TOKEN [--file PATH|-]
//! licoarc-client poll      --station URL --handle TOKEN --out DIR|- [--max N]
//! licoarc-client daemon    --station URL --handle TOKEN --out DIR|--out - [--idle MS]
//! ```
//!
//! Every command needs the caller's own inputs: the Station publishes its
//! descriptor digest out-of-band, the caller chooses and keeps its
//! affiliation commitment, and the handle comes from `reserve` or from the
//! peer. Nothing is searched, synthesized, or defaulted to a built-in
//! Station.
//!
//! Endpoint-session commands drive the pairing handshake and established
//! record flow over the same carrier; pairing envelopes still travel through
//! `send`/`poll` on caller-reserved handles:
//!
//! ```text
//! licoarc-client init        --dir DIR --authority BUNDLE
//! licoarc-client offer       --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]
//! licoarc-client begin       --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]
//! licoarc-client accept      --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]
//! licoarc-client finish      --dir DIR --authority BUNDLE [--in FILE|-]
//! licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN [--file PATH|-] [--ca PATH]
//! licoarc-client record-poll --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN --out DIR|- [--max N] [--ca PATH]
//! ```
//!
//! One `--dir` is one endpoint in one role: `custody.index`,
//! `identity.json`, the shareable `peer-identity.json`, and the sealed
//! `endpoint.checkpoint` live there, so every command resumes exactly where
//! the last one committed.
//!
//! `--ca PATH` adds one trust root (PEM or DER) for locally operated Stations
//! with development certificates; production listeners validate against the
//! system verifier.
//!
//! `--access FILE` attaches one BadTower access grant (written by `exchange`)
//! to every Station request: the `bta2` capability plus a freshly numbered
//! Ed25519 request proof. Stations without capability admission simply run
//! without it.

use licoarc::provider::{DigestProvider, RustCryptoProvider};
use licoarc::state::PlaintextReceiver;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::PacketCarrierAdapter;
use crate::carrier::{
    AffiliateRequest, CarrierConfig, HandleClass, HandleToken, ReserveRequest, StationClient,
    StationError, SubmitCarrier, TRANSPORT_PROFILE_DIGEST,
};
use crate::inbound::EndpointConsumer;
use crate::ports::Clock;
use crate::providers::FileCustody;
use crate::runtime::{
    ConsumeVerdict, EndpointSink, HandleCarrier, Mailbox, PacketSink, PollPace, drain_pending,
    poll_loop,
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
    let runtime = match tokio::runtime::Builder::new_current_thread()
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
        b"usage:\n  licoarc-client exchange --station URL (--invitation TOKEN|--invitation-file PATH) --access FILE [--ca PATH]\n  licoarc-client affiliate --station URL --descriptor HEX64 --commitment HEX64 [--ca PATH] [--access FILE]\n  licoarc-client reserve --station URL --descriptor HEX64 --commitment HEX64 [--class async|first-contact] [--ca PATH] [--access FILE]\n  licoarc-client send --station URL --handle TOKEN [--file PATH|-] [--ca PATH] [--access FILE]\n  licoarc-client poll --station URL --handle TOKEN --out DIR|--out - [--max N] [--ca PATH] [--access FILE]\n  licoarc-client daemon --station URL --handle TOKEN --out DIR|--out - [--idle MS] [--ca PATH] [--access FILE]\n  licoarc-client init --dir DIR --authority BUNDLE\n  licoarc-client offer --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]\n  licoarc-client begin --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]\n  licoarc-client accept --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]\n  licoarc-client finish --dir DIR --authority BUNDLE [--in FILE|-]\n  licoarc-client dispatch --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN [--out DIR] [--ca PATH] [--access FILE]\n  licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN [--file PATH|-] [--ca PATH] [--access FILE]\n  licoarc-client record-poll --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN --out DIR|- [--max N] [--ca PATH] [--access FILE]\n",
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

fn station_client(options: &Options) -> Result<Arc<StationClient>, String> {
    client(options).map(Arc::new)
}

fn client(options: &Options) -> Result<StationClient, String> {
    let mut config = carrier_config(options)?;
    if let Some(path) = options.optional("access") {
        config.access_credentials = Some(PathBuf::from(path));
    }
    StationClient::new(config).map_err(|error| error.to_string())
}

fn carrier_config(options: &Options) -> Result<CarrierConfig, String> {
    let mut config = CarrierConfig {
        origin: options.require("station")?,
        ..CarrierConfig::default()
    };
    if let Some(path) = options.optional("ca") {
        let bytes = std::fs::read(path).map_err(|error| format!("--ca {path}: {error}"))?;
        let certificate = reqwest::Certificate::from_pem(&bytes)
            .or_else(|_| reqwest::Certificate::from_der(&bytes))
            .map_err(|error| format!("--ca {path}: {error}"))?;
        config.extra_root_certificates.push(certificate);
    }
    Ok(config)
}

fn invitation(options: &Options) -> Result<String, String> {
    if let Some(text) = options.optional("invitation") {
        return Ok(text.to_owned());
    }
    if let Some(path) = options.optional("invitation-file") {
        return std::fs::read_to_string(path)
            .map(|text| text.trim().to_owned())
            .map_err(|error| format!("--invitation-file {path}: {error}"));
    }
    Err("--invitation TOKEN or --invitation-file PATH is required".to_owned())
}

fn descriptor(options: &Options) -> Result<[u8; 32], String> {
    hex32(&options.require("descriptor")?)
}

fn commitment(options: &Options) -> Result<[u8; 32], String> {
    hex32(&options.require("commitment")?)
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
        "exchange" => {
            // `--access` names the file the grant is written to; nothing is
            // loaded from it before the exchange commits.
            let config = carrier_config(options)?;
            let client = StationClient::new(config).map_err(|error| error.to_string())?;
            let store = PathBuf::from(options.require("access")?);
            let grant = rt
                .block_on(client.exchange_invitation(&invitation(options)?, store))
                .map_err(station_error)?;
            writeln!(
                out,
                "{{\"expiresAt\":{}}}",
                grant
                    .expires_at()
                    .map_or_else(|| "null".to_owned(), |text| format!("\"{text}\""))
            )
            .map_err(|error| error.to_string())
        }
        "affiliate" => {
            let client = station_client(options)?;
            let accepted = rt
                .block_on(client.affiliate(&AffiliateRequest {
                    station_descriptor_digest: descriptor(options)?,
                    affiliation_commitment: commitment(options)?,
                }))
                .map_err(station_error)?;
            writeln!(
                out,
                "{{\"notAfter\":{},\"signature\":\"{}\"}}",
                accepted.not_after,
                hex(&accepted.signature)
            )
            .map_err(|error| error.to_string())
        }
        "reserve" => {
            let client = station_client(options)?;
            let handle_class = match options.optional("class").unwrap_or("async") {
                "async" => HandleClass::Async,
                "first-contact" => HandleClass::FirstContact,
                other => return Err(format!("unknown --class {other}")),
            };
            let accepted = rt
                .block_on(client.reserve(&ReserveRequest {
                    station_descriptor_digest: descriptor(options)?,
                    affiliation_commitment: commitment(options)?,
                    transport_profile_digest: TRANSPORT_PROFILE_DIGEST,
                    handle_class,
                }))
                .map_err(station_error)?;
            let (service_until, signature) = accepted.service.map_or(
                ("null".to_owned(), "null".to_owned()),
                |(until, signature)| (until.to_string(), format!("\"{}\"", hex(&signature))),
            );
            writeln!(
                out,
                "{{\"handle\":\"{}\",\"class\":\"{}\",\"serviceUntil\":{},\"signature\":{}}}",
                accepted.handle.as_text(),
                match accepted.handle_class {
                    HandleClass::Async => "async",
                    HandleClass::FirstContact => "first-contact",
                },
                service_until,
                signature
            )
            .map_err(|error| error.to_string())
        }
        "send" => {
            let client = station_client(options)?;
            let packet = read_packet(options)?;
            rt.block_on(client.submit(handle(options)?, &packet))
                .map_err(station_error)?;
            writeln!(out, "{{\"submitted\":true}}").map_err(|error| error.to_string())
        }
        "poll" => poll(station_client(options)?, options, rt, out),
        "daemon" => daemon(station_client(options)?, options, rt, out),
        "init" => init(options, out),
        "offer" => offer(options, out),
        "begin" => begin(options, out),
        "accept" => accept(options, out),
        "finish" => finish(options, out),
        "dispatch" => flush_pending(station_client(options)?, options, out),
        "record-send" => record_send(station_client(options)?, options, out),
        "record-poll" => record_poll(station_client(options)?, options, rt, out),
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

/// The caller-visible packet consumer: each claimed packet is written exactly
/// once — to `dir/<content-digest>.packet`, or raw to the command's writer —
/// then completed. A failed write releases the item so the next claim can
/// retry it.
struct FileSink<'a> {
    dir: Option<PathBuf>,
    out: &'a mut dyn Write,
}

impl FileSink<'_> {
    fn new(dir: Option<PathBuf>, out: &mut dyn Write) -> FileSink<'_> {
        FileSink { dir, out }
    }

    fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        match &self.dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)?;
                let digest = licoarc::provider::fixed_provider().sha256(packet);
                std::fs::write(dir.join(format!("{}.packet", hex(&digest))), packet)
            }
            None => self.out.write_all(packet),
        }
    }
}

impl PacketSink for FileSink<'_> {
    fn accept(&mut self, packet: &[u8]) -> ConsumeVerdict {
        match self.write_packet(packet) {
            Ok(()) => ConsumeVerdict::Complete,
            Err(_) => ConsumeVerdict::Release,
        }
    }
}

fn sink_dir(options: &Options) -> Result<Option<PathBuf>, String> {
    match options.require("out")?.as_str() {
        "-" => Ok(None),
        path => Ok(Some(PathBuf::from(path))),
    }
}

/// Optional `--out`: absent means plaintexts go to the command's own writer.
fn optional_sink_dir(options: &Options) -> Option<PathBuf> {
    match options.optional("out").unwrap_or("-") {
        "-" => None,
        path => Some(PathBuf::from(path)),
    }
}

fn poll(
    client: Arc<StationClient>,
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let handle = handle(options)?;
    let max_items = options.optional("max").map_or(Ok(16_u64), |text| {
        text.parse::<u64>().map_err(|_| "invalid --max".to_owned())
    })?;
    let mailbox = Mailbox::new(HandleCarrier::new(client, handle), max_items);
    let mut sink = FileSink::new(sink_dir(options)?, out);
    let report = rt
        .block_on(mailbox.pump(&mut sink))
        .map_err(station_error)?;
    let outcomes = report
        .results
        .iter()
        .map(|result| result.outcome as u64)
        .collect::<Vec<_>>();
    writeln!(
        out,
        "{{\"claimed\":{},\"settled\":{},\"outcomes\":{:?}}}",
        report.claimed, report.settled, outcomes
    )
    .map_err(|error| error.to_string())
}

fn daemon(
    client: Arc<StationClient>,
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let handle = handle(options)?;
    let idle = options.optional("idle").map_or(Ok(1_000_u64), |text| {
        text.parse::<u64>().map_err(|_| "invalid --idle".to_owned())
    })?;
    let mailbox = Mailbox::new(HandleCarrier::new(client, handle), 16);
    let mut sink = FileSink::new(sink_dir(options)?, out);
    let pace = PollPace {
        idle: Duration::from_millis(idle),
        active: Duration::ZERO,
    };
    let report = rt
        .block_on(poll_loop(
            &mailbox,
            &mut sink,
            pace,
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
            |pass| {
                if pass.claimed > 0 {
                    eprintln!("claimed {} settled {}", pass.claimed, pass.settled);
                }
            },
        ))
        .map_err(station_error)?;
    writeln!(
        out,
        "{{\"passes\":{},\"claimed\":{}}}",
        report.passes, report.claimed
    )
    .map_err(|error| error.to_string())
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
    client: Arc<StationClient>,
    options: &Options,
    out: &mut impl Write,
) -> Result<(), String> {
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

/// Sends one plaintext as a protected record to the session handle.
fn record_send(
    client: Arc<StationClient>,
    options: &Options,
    out: &mut impl Write,
) -> Result<(), String> {
    let plaintext = read_packet(options)?;
    let handle = handle(options)?;
    match options.require("role")?.as_str() {
        "responder" => {
            let mut drive = responder_drive(options)?;
            let pending = drive
                .endpoint()
                .map_err(|refusal| format!("endpoint: {refusal}"))?
                .send_record(&plaintext, None)
                .map_err(|error| format!("send: {error:?}"))?;
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
            let pending = drive
                .endpoint()
                .map_err(|refusal| format!("endpoint: {refusal}"))?
                .send_record(&plaintext, None)
                .map_err(|error| format!("send: {error:?}"))?;
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

/// One pump against one live endpoint; the plaintext receiver borrows the
/// command's writer for the sink's lifetime.
fn pump_endpoint<R, C, S>(
    endpoint: &mut licoarc::endpoint::Endpoint<R, RustCryptoProvider, C, S>,
    mailbox: &Mailbox<HandleCarrier>,
    rt: &tokio::runtime::Runtime,
    sink_dir: Option<PathBuf>,
    out: &mut dyn Write,
) -> Result<(usize, usize, usize), String>
where
    R: licoarc::endpoint::Role,
    C: licoarc::state::KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
{
    let mut sink = EndpointSink::new(endpoint, PlaintextSink { dir: sink_dir, out });
    let report = rt
        .block_on(mailbox.pump(&mut sink))
        .map_err(station_error)?;
    Ok((report.claimed, sink.received().len(), sink.refused().len()))
}

/// Claims the session handle, verifies and commits each record through the
/// resumed endpoint, and releases plaintexts to `--out`.
fn record_poll(
    client: Arc<StationClient>,
    options: &Options,
    rt: &tokio::runtime::Runtime,
    out: &mut impl Write,
) -> Result<(), String> {
    let handle = handle(options)?;
    let max_items = options.optional("max").map_or(Ok(16_u64), |text| {
        text.parse::<u64>().map_err(|_| "invalid --max".to_owned())
    })?;
    let mailbox = Mailbox::new(HandleCarrier::new(client, handle), max_items);
    let sink_dir = sink_dir(options)?;
    let (claimed, received, refused) = match options.require("role")?.as_str() {
        "responder" => {
            let mut drive = responder_drive(options)?;
            let result = pump_endpoint(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                &mailbox,
                rt,
                sink_dir,
                out,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            result
        }
        "initiator" => {
            let mut drive = initiator_drive(options)?;
            let result = pump_endpoint(
                drive
                    .endpoint()
                    .map_err(|refusal| format!("endpoint: {refusal}"))?,
                &mailbox,
                rt,
                sink_dir,
                out,
            )?;
            drive
                .persist()
                .map_err(|refusal| format!("persist: {refusal}"))?;
            result
        }
        other => return Err(format!("unknown --role {other}")),
    };
    writeln!(
        out,
        "{{\"claimed\":{},\"received\":{},\"refused\":{}}}",
        claimed, received, refused
    )
    .map_err(|error| error.to_string())
}
