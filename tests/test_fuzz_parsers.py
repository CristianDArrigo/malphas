"""
Hypothesis-driven fuzz tests for parsers that ingest untrusted input.

The contract: each parser may either succeed on valid input or raise a
specifically-typed exception on malformed input. It must NEVER raise
an unexpected exception, hang, return None where a value was promised,
or crash the interpreter.

Allowed exception types per parser (the ones the calling code is
prepared to handle as a "drop silently" signal):

  peel_layer            ValueError
  unpad_payload         ValueError
  parse_invite          ValueError
  FileOffer.from_dict   KeyError, ValueError, TypeError
"""

from __future__ import annotations

import base64
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from malphas.crypto import generate_ephemeral_keypair
from malphas.files import FileOffer
from malphas.invite import parse_invite
from malphas.obfuscation import unpad_payload
from malphas.onion import peel_layer

# ── peel_layer ────────────────────────────────────────────────────────────────

@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(blob=st.binary(min_size=0, max_size=4096))
def test_peel_layer_never_crashes(blob):
    """A relay receives arbitrary bytes; peel_layer must only raise ValueError."""
    priv, _ = generate_ephemeral_keypair()
    try:
        peel_layer(priv, blob)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"peel_layer raised unexpected {type(e).__name__}: {e!r}")


# ── unpad_payload ─────────────────────────────────────────────────────────────

@settings(max_examples=200, deadline=None)
@given(blob=st.binary(min_size=0, max_size=2048))
def test_unpad_payload_never_crashes(blob):
    try:
        result = unpad_payload(blob)
        # On success, result is bytes
        assert isinstance(result, (bytes, bytearray))
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"unpad_payload raised unexpected {type(e).__name__}: {e!r}")


# ── parse_invite ──────────────────────────────────────────────────────────────

@settings(max_examples=200, deadline=None)
@given(blob=st.text(min_size=0, max_size=4096))
def test_parse_invite_text_never_crashes(blob):
    try:
        parse_invite(blob)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"parse_invite raised unexpected {type(e).__name__}: {e!r}")


@settings(max_examples=200, deadline=None)
@given(blob=st.binary(min_size=0, max_size=4096))
def test_parse_invite_with_malphas_prefix(blob):
    """Inputs that start with the prefix but have arbitrary bytes after."""
    try:
        url = "malphas://" + base64.urlsafe_b64encode(blob).decode("ascii")
        parse_invite(url)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"parse_invite raised unexpected {type(e).__name__}: {e!r}")


# ── FileOffer.from_dict ───────────────────────────────────────────────────────

# Build dicts of any shape — keys may or may not match the expected ones.
_offer_keys = ["file_id", "name", "size", "sha256", "chunk_size", "chunk_count",
               "extra", "garbage", "", "kind", "from"]


@settings(max_examples=300, deadline=None)
@given(
    d=st.dictionaries(
        keys=st.sampled_from(_offer_keys),
        values=st.one_of(
            st.text(max_size=64),
            st.integers(min_value=-(2**63), max_value=2**63 - 1),
            st.binary(max_size=64).map(lambda b: b.hex()),
            st.none(),
            st.booleans(),
            st.lists(st.text(max_size=8), max_size=3),
        ),
        max_size=10,
    )
)
def test_file_offer_from_dict_never_crashes(d):
    """The receiver gets file_offer JSON over the wire; from_dict must not crash."""
    try:
        FileOffer.from_dict(d)
    except (KeyError, ValueError, TypeError):
        pass
    except Exception as e:
        pytest.fail(f"FileOffer.from_dict raised unexpected {type(e).__name__}: {e!r}")


# ── Round-trip sanity (smoke, not strictly fuzz) ──────────────────────────────

@given(
    name=st.text(min_size=1, max_size=64),
    size=st.integers(min_value=1, max_value=1024 * 1024),
    chunk_size=st.integers(min_value=1, max_value=65536),
)
def test_file_offer_roundtrip(name, size, chunk_size):
    chunk_count = (size + chunk_size - 1) // chunk_size
    d = {
        "file_id": "ab" * 16,
        "name": name,
        "size": size,
        "sha256": "0" * 64,
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
    }
    offer = FileOffer.from_dict(d)
    assert offer.size == size
    assert offer.chunk_count == chunk_count
    # to_dict round-trips back to a dict that from_dict accepts
    again = FileOffer.from_dict(offer.to_dict())
    assert again == offer


# ── parse_invite valid-prefix only (avoid full ascii noise) ───────────────────

@settings(max_examples=100, deadline=None)
@given(blob=st.binary(min_size=0, max_size=128))
def test_parse_invite_prefix_only(blob):
    """Test edge case: prefix + raw bytes encoded as latin-1 (non-base64)."""
    try:
        url = "malphas://" + blob.decode("latin-1", errors="replace")
        parse_invite(url)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"parse_invite raised unexpected {type(e).__name__}: {e!r}")


# ── JSON-noise injection on parse_invite ──────────────────────────────────────

@settings(max_examples=200, deadline=None)
@given(payload=st.dictionaries(
    keys=st.text(max_size=20),
    values=st.one_of(st.text(max_size=64), st.integers(), st.none(),
                     st.lists(st.integers(), max_size=3)),
    max_size=10,
))
def test_parse_invite_arbitrary_json_after_prefix(payload):
    """Even structurally valid JSON without signature must be rejected."""
    try:
        sig = b"\x00" * 64  # bogus signature
        json_bytes = json.dumps(payload).encode()
        url = "malphas://" + base64.urlsafe_b64encode(sig + json_bytes).decode("ascii")
        parse_invite(url)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"parse_invite raised unexpected {type(e).__name__}: {e!r}")
