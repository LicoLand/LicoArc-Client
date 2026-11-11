# Contributing

The pinned toolchain is Rust 1.95 (`rust-toolchain.toml` selects it).

## Build

```sh
cargo build        # library + the licoarc-client CLI
cargo doc --open   # module-level contract documentation
```

## Test

```sh
cargo test --all-targets
```

The mailbox integration tests (`tests/mailbox.rs`) run against an in-process
Station and need no external services. Two groups of tests are gated on
their environment:

- `#[ignore]`d real-key authority proofs (in `src/`) need
  `LICOARC_AUTHORITY_BUNDLE` naming the pinned authority bundle;
- the devnet acceptance test (`tests/devnet.rs`) needs a live Station via
  `LICOARC_DEVNET_STATION`, `LICOARC_DEVNET_CA`, and
  `LICOARC_DEVNET_INVITATIONS`.

## Verify

```sh
scripts/verify.sh
```

The canonical gate: `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, and the full test
suite. When `LICOARC_AUTHORITY_BUNDLE` is set it also runs the `#[ignore]`d
authority proofs.
