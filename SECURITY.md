# Security Policy

LicoArc owns protocol and cryptographic semantics; this repository never
repairs, extends, or reinterprets them — every protocol decision is delegated
to the pinned `licoarc` SDK. This client keeps local `unsafe_code = "forbid"`,
refuses plaintext transports for the mailbox carrier, stores credential,
custody, and checkpoint material owner-only, and zeroizes secret material it
holds in memory.

The bundled file-backed custody (`FileCustody`) is a development backend, not
a product keystore: secrets on disk are raw seed bytes protected only by file
mode `0600`. Consumers with a real custody requirement implement the custody
port themselves.

Local verification is not an independent cryptographic audit. Dependencies may
contain internal unsafe code, and logical deletion does not claim physical
erasure, protection from a compromised process or malicious store, hardware
custody, or side-channel resistance.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting for this repository:

<https://github.com/LicoLand/LicoArc-Client/security/advisories/new>

Do not open a public issue for a suspected vulnerability.

Security reports must omit secrets, private keys, plaintext, ciphertext,
runtime data, local paths, machine identity, and other protected operational
details. Use synthetic, minimum-necessary reproduction material.
