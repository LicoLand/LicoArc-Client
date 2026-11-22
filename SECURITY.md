# Security Policy

Every protocol and cryptographic decision is delegated to the pinned `licoarc`
crate. `licoarc-client` enforces `#![forbid(unsafe_code)]`, rejects plaintext
transports for the mailbox carrier, writes credential, custody, and checkpoint
files with mode `0600` on Unix, and uses zeroizing buffers for in-memory
custody keys and mailbox credentials.

The bundled `FileCustody` provider is intended for development only. It stores
unencrypted seed material on disk. Production consumers should implement the
custody port backed by platform secure storage.

Local verification does not include an independent cryptographic audit.
Dependencies may contain internal `unsafe` code. Logical deletion provides no
guarantee of physical erasure. Hardware custody, protection from a compromised
process or malicious store, and side-channel resistance are outside the scope
of this library.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting for this repository:

<https://github.com/LicoLand/LicoArc-Client/security/advisories/new>

Do not open a public issue for a suspected vulnerability.

Security reports must omit secrets, private keys, plaintext, ciphertext,
runtime data, local paths, machine identity, and other protected operational
details. Use synthetic, minimum-necessary reproduction material.
