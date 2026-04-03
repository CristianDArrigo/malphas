"""
Invite system — shareable credential blobs.

/export generates a signed malphas:// URL containing:
  peer_id, x25519_pub, ed25519_pub, host, port, onion (optional)

/import decodes, verifies the Ed25519 signature, and returns the fields.

The blob is self-signed: the signature proves the invite was generated
by the holder of the Ed25519 private key matching the included pubkey.
It does NOT prove identity to a third party — only integrity.
"""

import base64
import json
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "malphas://"


def generate_invite(
    identity,
    host: str,
    port: int,
    onion: Optional[str] = None,
) -> str:
    """
    Generate a malphas:// invite URL.
    Returns the full URL string ready to share.
    """
    payload = {
        "type": "invite",
        "v": 1,
        "peer_id": identity.peer_id,
        "x25519_pub": identity.x25519_pub_bytes.hex(),
        "ed25519_pub": identity.ed25519_pub_bytes.hex(),
        "host": host,
        "port": port,
    }
    if onion:
        payload["onion"] = onion

    json_bytes = json.dumps(payload, separators=(",", ":")).encode()
    sig = identity.sign(json_bytes)

    blob = base64.urlsafe_b64encode(sig + json_bytes).decode()
    return PREFIX + blob


def parse_invite(url: str) -> dict:
    """
    Parse and verify a malphas:// invite URL.
    Returns the payload dict on success.
    Raises ValueError on any failure (bad format, bad signature, missing fields).
    """
    if not url.startswith(PREFIX):
        raise ValueError("Not a malphas:// invite")

    blob = url[len(PREFIX):]

    try:
        raw = base64.urlsafe_b64decode(blob)
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}") from e

    if len(raw) < 65:
        raise ValueError("Invite too short")

    sig = raw[:64]
    json_bytes = raw[64:]

    try:
        payload = json.loads(json_bytes.decode())
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    # Validate required fields
    required = ["type", "v", "peer_id", "x25519_pub", "ed25519_pub", "host", "port"]
    for field in required:
        if field not in payload:
            raise ValueError(f"Missing field: {field}")

    if payload["type"] != "invite":
        raise ValueError(f"Unknown type: {payload['type']}")

    if payload["v"] != 1:
        raise ValueError(f"Unsupported version: {payload['v']}")

    # Verify signature
    try:
        ed_pub_bytes = bytes.fromhex(payload["ed25519_pub"])
        pub = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
        pub.verify(sig, json_bytes)
    except Exception as e:
        raise ValueError(f"Signature verification failed: {e}") from e

    return payload
