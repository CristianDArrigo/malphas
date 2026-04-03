"""
Tests for the invite system (malphas:// URLs).

Verifies:
- Roundtrip: generate + parse returns same data
- Signature integrity: tampered blobs rejected
- Missing fields rejected
- Invalid format rejected
- Onion field optional
- Version check
"""

import base64
import json
import secrets

import pytest

from malphas.identity import create_identity
from malphas.invite import PREFIX, generate_invite, parse_invite


class TestInviteRoundtrip:
    def test_basic_roundtrip(self, identity_a):
        url = generate_invite(identity_a, "192.168.1.10", 7777)
        data = parse_invite(url)
        assert data["peer_id"] == identity_a.peer_id
        assert data["x25519_pub"] == identity_a.x25519_pub_bytes.hex()
        assert data["ed25519_pub"] == identity_a.ed25519_pub_bytes.hex()
        assert data["host"] == "192.168.1.10"
        assert data["port"] == 7777

    def test_roundtrip_with_onion(self, identity_a):
        onion = "abc123xyz.onion"
        url = generate_invite(identity_a, "10.0.0.1", 8888, onion=onion)
        data = parse_invite(url)
        assert data["onion"] == onion
        assert data["host"] == "10.0.0.1"
        assert data["port"] == 8888

    def test_roundtrip_without_onion(self, identity_a):
        url = generate_invite(identity_a, "10.0.0.1", 8888)
        data = parse_invite(url)
        assert "onion" not in data

    def test_url_starts_with_prefix(self, identity_a):
        url = generate_invite(identity_a, "localhost", 7777)
        assert url.startswith(PREFIX)

    def test_different_identities_different_urls(self, identity_a, identity_b):
        url_a = generate_invite(identity_a, "localhost", 7777)
        url_b = generate_invite(identity_b, "localhost", 7777)
        assert url_a != url_b

    def test_type_and_version(self, identity_a):
        url = generate_invite(identity_a, "localhost", 7777)
        data = parse_invite(url)
        assert data["type"] == "invite"
        assert data["v"] == 1


class TestInviteSignature:
    def test_tampered_json_rejected(self, identity_a):
        url = generate_invite(identity_a, "localhost", 7777)
        blob = url[len(PREFIX):]
        raw = base64.urlsafe_b64decode(blob)
        sig = raw[:64]
        json_bytes = bytearray(raw[64:])
        # Tamper with the JSON
        json_bytes[-5] ^= 0x01
        tampered = base64.urlsafe_b64encode(sig + bytes(json_bytes)).decode()
        with pytest.raises(ValueError, match="Signature verification failed|Invalid JSON"):
            parse_invite(PREFIX + tampered)

    def test_tampered_signature_rejected(self, identity_a):
        url = generate_invite(identity_a, "localhost", 7777)
        blob = url[len(PREFIX):]
        raw = bytearray(base64.urlsafe_b64decode(blob))
        raw[10] ^= 0xFF  # tamper signature
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="Signature verification failed"):
            parse_invite(PREFIX + tampered)

    def test_wrong_identity_signature_rejected(self, identity_a, identity_b):
        """Generate with A's key but replace ed25519_pub with B's — must fail."""
        url = generate_invite(identity_a, "localhost", 7777)
        blob = url[len(PREFIX):]
        raw = base64.urlsafe_b64decode(blob)
        sig = raw[:64]
        payload = json.loads(raw[64:].decode())
        payload["ed25519_pub"] = identity_b.ed25519_pub_bytes.hex()
        new_json = json.dumps(payload, separators=(",", ":")).encode()
        forged = base64.urlsafe_b64encode(sig + new_json).decode()
        with pytest.raises(ValueError, match="Signature verification failed"):
            parse_invite(PREFIX + forged)


class TestInviteValidation:
    def test_missing_prefix(self):
        with pytest.raises(ValueError, match="Not a malphas"):
            parse_invite("http://example.com")

    def test_empty_blob(self):
        with pytest.raises(ValueError):
            parse_invite(PREFIX)

    def test_too_short(self):
        short = base64.urlsafe_b64encode(b"x" * 10).decode()
        with pytest.raises(ValueError, match="too short"):
            parse_invite(PREFIX + short)

    def test_invalid_base64(self):
        with pytest.raises(ValueError, match="Invalid base64"):
            parse_invite(PREFIX + "!!!not-base64!!!")

    def test_missing_field_peer_id(self, identity_a):
        payload = {
            "type": "invite", "v": 1,
            "x25519_pub": identity_a.x25519_pub_bytes.hex(),
            "ed25519_pub": identity_a.ed25519_pub_bytes.hex(),
            "host": "localhost", "port": 7777,
            # no peer_id
        }
        json_bytes = json.dumps(payload, separators=(",", ":")).encode()
        sig = identity_a.sign(json_bytes)
        blob = base64.urlsafe_b64encode(sig + json_bytes).decode()
        with pytest.raises(ValueError, match="Missing field: peer_id"):
            parse_invite(PREFIX + blob)

    def test_wrong_type(self, identity_a):
        payload = {
            "type": "something_else", "v": 1,
            "peer_id": identity_a.peer_id,
            "x25519_pub": identity_a.x25519_pub_bytes.hex(),
            "ed25519_pub": identity_a.ed25519_pub_bytes.hex(),
            "host": "localhost", "port": 7777,
        }
        json_bytes = json.dumps(payload, separators=(",", ":")).encode()
        sig = identity_a.sign(json_bytes)
        blob = base64.urlsafe_b64encode(sig + json_bytes).decode()
        with pytest.raises(ValueError, match="Unknown type"):
            parse_invite(PREFIX + blob)

    def test_wrong_version(self, identity_a):
        payload = {
            "type": "invite", "v": 99,
            "peer_id": identity_a.peer_id,
            "x25519_pub": identity_a.x25519_pub_bytes.hex(),
            "ed25519_pub": identity_a.ed25519_pub_bytes.hex(),
            "host": "localhost", "port": 7777,
        }
        json_bytes = json.dumps(payload, separators=(",", ":")).encode()
        sig = identity_a.sign(json_bytes)
        blob = base64.urlsafe_b64encode(sig + json_bytes).decode()
        with pytest.raises(ValueError, match="Unsupported version"):
            parse_invite(PREFIX + blob)

    def test_garbage_json(self, identity_a):
        sig = identity_a.sign(b"not json at all")
        blob = base64.urlsafe_b64encode(sig + b"not json at all").decode()
        with pytest.raises(ValueError):
            parse_invite(PREFIX + blob)
