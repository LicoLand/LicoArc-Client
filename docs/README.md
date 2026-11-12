# LicoArc-Client

Standalone Lico Arc endpoint client: a Rust library plus the
`licoarc-client` CLI. The Protocol Line, its definitions, and all
cryptography stay with the LicoArc Rust SDK (pinned at `licoarc = "=0.2.0"`);
secret custody, persistence, trust facts, and application effects stay
caller-owned through [`ports`](../src/ports.rs). This crate composes them:

- `admission` — admits an explicitly supplied authority bundle, fail-closed;
- `carrier` — the `licoarc.mailbox-transport.v1` Station carrier: a TLS 1.3
  WebSocket with the `licoarc.mailbox.v1` subprotocol carrying the eight
  deterministic-CBOR frames (CHALLENGE/READY, HELLO, SEND/RESULT,
  DELIVER/ACK, DRAINED), admission credentials, multiplexed sends, and the
  keepalive cadence — over the `licoarc` SDK's own codecs;
- `runtime` — the receive loop (DELIVER → sink verdict → ACK, jittered
  reconnect on ordinary loss, terminal stop on Superseded/Revoked), the
  durable spool, the pending-item outbox drain, and the endpoint-session
  sink;
- `providers` — the CLI's own backend: `FileCustody` (atomically replaced
  custody index, development-grade) and `MemoryState` (coupled old-or-new
  store; durability comes from the SDK's `checkpoint`/`resume` pair);
- `durable_obligation` — an opt-in ledger of caller-admitted delivery
  obligations, including its serialized recovery record;
- `cli` — the standalone command line.

## Durable obligation records

LicoArc-Client owns the `ObligationLedger<Payload>` API and the
`DurableObligationRecord<Payload>` envelope it produces. The envelope records
admission identities, generation and delivery attempts; callers supply the
payload type and persist the record through their own storage backend.
Admission creates an obligation that remains owed until accepted settlement.

The published record identifier, `DURABLE_OBLIGATION_SCHEMA`, is
`licoup.endpoint-obligations.v1`. That spelling is part of this library's
serialized contract and is retained for existing records. Readers use
`schema_matches` or `from_durable_record` to validate it before recovering
the owed set. This is a client-local persistence format; LicoArc owns the
protocol's wire definitions.

## CLI

```text
licoarc-client enroll  --station URL --invitation-file PATH --credentials FILE [--ca PATH]
licoarc-client handle  --credentials FILE
licoarc-client send    --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]
licoarc-client receive --credentials FILE --spool DIR [--follow] [--ca PATH]
```

Two endpoints close the transport loop over one Station: `enroll` turns a
`btm1` invitation token and a fresh device key into a bound mailbox
(credentials file: Station URL, token, sealed Ed25519 seed, learned mailbox
id), `handle` mints outbound handles for that mailbox, `send` delivers one
packet to a peer's handle, and `receive` drains the mailbox into a local
spool (`--follow` keeps the lane until stopped). Undelivered packets never
expire; a delivery is ACKed only after the sink's verdict. `--ca` adds one
development trust root for a locally operated Station.

Endpoint sessions run over the same carrier:

```text
licoarc-client init        --dir DIR --authority BUNDLE
licoarc-client offer       --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]
licoarc-client begin       --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]
licoarc-client accept      --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]
licoarc-client finish      --dir DIR --authority BUNDLE [--in FILE|-]
licoarc-client dispatch    --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--out DIR] [--ca PATH]
licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]
licoarc-client record-read --dir DIR --role responder|initiator --authority BUNDLE --spool DIR --handle TOKEN --out DIR
```

`init` mints the endpoint identity into `--dir` (private custody index plus
the shareable `peer-identity.json`). Each endpoint's mailbox handle comes
from `handle` after `enroll`. The responder's `offer` advertises its own
mailbox handle; the initiator's `begin` wraps its first packet into a
submission envelope addressed to its own `--reply-handle`; the responder's
`accept` answers on the offered `--session-handle`; `finish` settles the
handshake on the initiator side. Envelope artifacts move over the carrier
with `send`/`receive`; every committed packet also enters the endpoint's
durable pending ledger, so `dispatch` is the settlement step that submits
and clears pending output. Once the session is established,
`record-send` submits a record and `record-read` consumes what `receive`
spooled. All session state persists through the SDK's checkpoint/resume
pair, so any step may run in a fresh process.

## Local state

Keep endpoint state, credentials, spool contents and received plaintext in a
private directory outside Git checkouts. The CLI rejects checkout-local
private output paths, including ignored directories, before creating state
or opening a connection. The check inspects the supplied path and resolves
existing ancestors to reject symlink targets inside a checkout.

The boundary covers endpoint `--dir`, enrollment `--credentials`, receive
and record-read `--spool`, and the commands' file or directory `--out`
destinations. Read-only inputs remain caller-selected. Where a command
supports `--out -`, the caller controls the stdout destination and must keep
private output out of source control.

The repository's ignore rules also cover the fixed endpoint-state filenames,
`credentials.json` and invitation files. The shareable `peer-identity.json`
is a runtime exchange artifact and should not be committed as source.

## Verify

```sh
scripts/verify.sh   # cargo fmt --check, clippy -D warnings, full test suite
```
