# Security Policy

## Reporting

If you find a vulnerability, please report it privately. Do **not** open a public GitHub issue for security problems.

- Email: open an issue marked "security: contact request" or use the GitHub Security tab.
- The maintainer will acknowledge within 7 days.
- Coordinated disclosure preferred: please give 30 days before public disclosure unless the issue is already being exploited in the wild.

## Threat Model

See [README — Threat Model](README.md#threat-model) for the full list of what
malphas does and does not protect against.

## Supported Versions

Only the latest released version receives security fixes. Older versions are
unsupported. This project is pre-1.0 and the wire format may change.

| Version | Supported |
|---------|-----------|
| 0.2.x   | yes       |
| < 0.2   | no        |

## Out-of-scope (known design choices, not bugs)

- Physical compromise of a running device (RAM contains plaintext).
- Compromise of the OS (keyloggers, malware).
- Coercion of the peer at the other end of the channel.
- Global passive adversary monitoring both endpoints simultaneously
  (Tor-level limitation, not a malphas-specific weakness).
- Social engineering of the user.

## Known limitations

- SHA1 used for `peer_id` (160-bit identifier, not security-critical).
  Migration to BLAKE2s/SHA-256 planned in 0.3 (wire-breaking).
- Argon2id salt is a public constant. Per-user salt would require disk state;
  trade-off currently weighted toward zero-disk policy.
- Memory not `mlock`ed; sensitive material may end up in swap on systems with
  swap enabled.

## Cryptographic primitives

All from `cryptography.hazmat` (libssl). No custom crypto.
See [README — Cryptographic Stack](README.md#cryptographic-stack).
