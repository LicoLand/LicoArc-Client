# LicoArc-Client

Standalone Lico Arc endpoint client (`licoarc_client` Rust library and
`licoarc-client` CLI). It layers a TLS 1.3 mailbox carrier, durable spool and
receive loop, obligation ledger, and CLI over the pinned `licoarc = "=0.2.0"`
protocol crate while keeping secret custody, state persistence, trust decisions,
and application effects behind caller-owned [`ports`](../src/ports.rs).

## Modules

- `admission` — fail-closed admission of a supplied `licoarc` authority bundle.
- `carrier` — `licoarc.mailbox-transport.v1` Station carrier: TLS 1.3 WebSocket
  with the `licoarc.mailbox.v1` subprotocol carrying the eight deterministic-CBOR
  frames (`CHALLENGE`/`READY`, `HELLO`, `SEND`/`RESULT`, `DELIVER`/`ACK`,
  `DRAINED`), admission credentials, multiplexed sends, and keepalive.
- `runtime` — receive loop (`DELIVER` → sink verdict → `ACK`, jittered
  reconnect on transient loss, terminal stop on `Superseded`/`Revoked`),
  durable spool, pending-item outbox drain, and endpoint-session sink.
- `providers` — CLI backend implementations: `FileCustody` (atomically replaced
  development custody index) and `MemoryState` (coupled old-or-new store with
  SDK `checkpoint`/`resume` durability).
- `durable_obligation` — opt-in ledger and serialized recovery record for
  caller-admitted delivery obligations.
- `cli` — standalone CLI binary.

## Durable obligation records

`ObligationLedger<Payload>` produces `DurableObligationRecord<Payload>`
envelopes recording admission identities, generation, and delivery attempts;
callers supply the payload type and persist records in their own storage.
An admitted obligation stays owed until the peer accepts delivery.

The serialized schema tag `DURABLE_OBLIGATION_SCHEMA` is
`licoarc.endpoint-obligations.v1` (superseding the `licoup.*` tag from `0.2.0`;
records with the older tag are not read as this schema). Readers validate the
tag with `schema_matches` or `from_durable_record` before recovering owed items.

## CLI

```text
licoarc-client enroll  --station URL --invitation-file PATH --credentials FILE [--ca PATH]
licoarc-client handle  --credentials FILE
licoarc-client send    --credentials FILE --handle TOKEN [--file PATH|-] [--ca PATH]
licoarc-client receive --credentials FILE --spool DIR [--follow] [--ca PATH] [--reconnect-initial-ms N] [--reconnect-multiplier N] [--reconnect-cap-ms N]
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
