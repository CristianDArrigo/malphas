"""
Shared pytest fixtures for Malphas test suite.
"""

import asyncio
import os
import secrets
import tempfile
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from malphas.identity import create_identity, create_identity_with_book_key
from malphas.node import MalphasNode
from malphas.addressbook import AddressBook, Contact


# ── Identities ────────────────────────────────────────────────────────────────

@pytest.fixture
def identity_a():
    return create_identity("passphrase-alice-malphas")

@pytest.fixture
def identity_b():
    return create_identity("passphrase-bob-malphas")

@pytest.fixture
def identity_c():
    return create_identity("passphrase-charlie-malphas")

@pytest.fixture
def identity_with_book_a():
    return create_identity_with_book_key("passphrase-alice-malphas")

@pytest.fixture
def identity_with_book_b():
    return create_identity_with_book_key("passphrase-bob-malphas")


# ── Nodes ─────────────────────────────────────────────────────────────────────

@pytest.fixture
async def node_a(identity_a):
    node = MalphasNode(identity_a, host="127.0.0.1", port=17777, cover_traffic=False)
    await node.start()
    yield node
    await node.stop()

@pytest.fixture
async def node_b(identity_b):
    node = MalphasNode(identity_b, host="127.0.0.1", port=17778, cover_traffic=False)
    await node.start()
    yield node
    await node.stop()

@pytest.fixture
async def node_c(identity_c):
    node = MalphasNode(identity_c, host="127.0.0.1", port=17779, cover_traffic=False)
    await node.start()
    yield node
    await node.stop()


# ── Address book ──────────────────────────────────────────────────────────────

@pytest.fixture
def book_path():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".book") as f:
        path = f.name
    os.unlink(path)
    yield path
    if os.path.exists(path):
        os.unlink(path)

@pytest.fixture
def book_key():
    _, key = create_identity_with_book_key("passphrase-alice-malphas")
    return key

@pytest.fixture
def fresh_book(book_path, book_key):
    book = AddressBook(book_path, book_key)
    book.load()
    return book

@pytest.fixture
def sample_contact(identity_b):
    return Contact(
        label="bob",
        peer_id=identity_b.peer_id,
        host="127.0.0.1",
        port=17778,
        x25519_pub=identity_b.x25519_pub_bytes.hex(),
        ed25519_pub=identity_b.ed25519_pub_bytes.hex(),
    )
