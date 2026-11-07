# LicoArc-Client

Standalone Lico Arc endpoint client: a Rust library plus the
`licoarc-client` CLI. The Protocol Line, its definitions, and all
cryptography stay with the LicoArc Rust SDK (consumed at a pinned revision);
secret custody, persistence, trust facts, and application effects stay
caller-owned through [`ports`](../src/ports.rs). This crate composes them:

- `admission` — admits an explicitly supplied authority bundle, fail-closed;
- `carrier` — the `licoarc.https-transport.v1` Station carrier: canonical
  CBOR control records, the six handle operations, strict response
  classification, and same-identifier bounded retries over HTTP/2 + TLS 1.3;
- `runtime` — the mailbox pump (`claim → consume → settle`), the pending-item
  outbox drain, the paced poll loop, and the endpoint-session sink;
- `providers` — the CLI's own backend: `FileCustody` (atomically replaced
  custody index, development-grade) and `MemoryState` (coupled old-or-new
  store; durability comes from the SDK's `checkpoint`/`resume` pair);
- `cli` — the standalone command line.

## CLI

```text
licoarc-client affiliate --station URL --descriptor HEX64 --commitment HEX64 [--ca PATH]
licoarc-client reserve   --station URL --descriptor HEX64 --commitment HEX64 [--class async|first-contact] [--ca PATH]
licoarc-client send      --station URL --handle TOKEN [--file PATH|-] [--ca PATH]
licoarc-client poll      --station URL --handle TOKEN --out DIR|--out - [--max N] [--ca PATH]
licoarc-client daemon    --station URL --handle TOKEN --out DIR|--out - [--idle MS] [--ca PATH]
```

Two processes close the transport loop over one Station: `affiliate` then
`reserve` mints an inbound handle, the peer `send`s packets to it, and `poll`
or `daemon` claims and settles them. The station descriptor digest is an
operator-published input; the affiliation commitment is caller-chosen (e.g.
`openssl rand -hex 32`) and must be reused identically across `affiliate` and
`reserve`. `--ca` adds one development trust root for a locally operated
Station.

Endpoint sessions run over the same carrier:

```text
licoarc-client init        --dir DIR --authority BUNDLE
licoarc-client offer       --dir DIR --authority BUNDLE --handle TOKEN --sequence N [--from T] [--until T] --authority-digest HEX64 [--out FILE|-]
licoarc-client begin       --dir DIR --authority BUNDLE --offer FILE|- --reply-handle TOKEN --authority-digest HEX64 [--out FILE|-]
licoarc-client accept      --dir DIR --authority BUNDLE --peer FILE --authority-digest HEX64 --session-handle TOKEN [--in FILE|-] [--out FILE|-]
licoarc-client finish      --dir DIR --authority BUNDLE [--in FILE|-]
licoarc-client dispatch    --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN [--out DIR] [--ca PATH]
licoarc-client record-send --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN [--file PATH|-] [--ca PATH]
licoarc-client record-poll --dir DIR --role responder|initiator --authority BUNDLE --station URL --handle TOKEN --out DIR|- [--max N] [--ca PATH]
```

`init` mints the endpoint identity into `--dir` (private custody index plus
the shareable `peer-identity.json`). The responder's `offer` advertises a
bootstrap handle; the initiator's `begin` wraps its first packet into a
submission envelope addressed to its own `--reply-handle`; the responder's
`accept` answers on the offered `--session-handle`; `finish` settles the
handshake on the initiator side. Envelope artifacts move over the carrier
with `send`/`poll`; every committed packet also enters the endpoint's
durable pending ledger, so `dispatch` is the settlement step that submits
and clears pending output (an already-submitted envelope replays under its
content-stable operation id and settles without a second delivery). Once
the session is established, `record-send`/`record-poll` move data records.
All session state persists through the SDK's checkpoint/resume pair, so any
step may run in a fresh process.

## Verify

```sh
scripts/verify.sh   # cargo fmt --check, clippy -D warnings, full test suite
```
