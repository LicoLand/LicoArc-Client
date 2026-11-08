#!/bin/sh
# Canonical engineering verification for licoarc-client.
# Runs the complete gate: format, strict lints, the full test suite.
set -eu
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
# The real-key authority proofs need the pinned bundle; CI always supplies it.
if [ -n "${LICOARC_AUTHORITY_BUNDLE:-}" ]; then
  cargo test --lib -- --ignored
fi
