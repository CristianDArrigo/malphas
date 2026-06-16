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
unsupported. The project is at its first stable release, `1.0.0`. The wire
format (`WIRE_VERSION = 2`) is frozen and binding; it was bumped 1 → 2 across
the pre-1.0 security audit (handshake + ratchet), so `1.0.0` nodes do not
interoperate with the `v1` wire of `1.0.0-rc6` and earlier.

| Version  | Supported |
|----------|-----------|
| 1.0.0    | yes       |
| < 1.0.0  | no        |

## Out-of-scope (known design choices, not bugs)

- Physical compromise of a running device (RAM contains plaintext).
- Compromise of the OS (keyloggers, malware).
- Coercion of the peer at the other end of the channel.
- Global passive adversary monitoring both endpoints simultaneously
  (Tor-level limitation, not a malphas-specific weakness).
- Social engineering of the user.

## Known limitations

- ~~SHA1 used for `peer_id` (160-bit identifier, not security-critical).~~
  Replaced with `BLAKE2s(ed25519_pub, digest_size=20)` in 0.5.0 (wire-breaking).
- Argon2id salt is a public constant. Per-user salt would require disk state;
  trade-off currently weighted toward zero-disk policy.
- The Argon2 seed is mlock'd best-effort via `malphas.secure_buffer` and
  zeroized after the keypairs are derived. Other sensitive material
  (session keys, ratchet roots, address book master key) is not yet
  wrapped in `SecureBytes`; tightening that surface is tracked work.

## Cryptographic primitives

All from `cryptography.hazmat` (libssl). No custom crypto.
See [README — Cryptographic Stack](README.md#cryptographic-stack).
