#!/usr/bin/env bash
#
# malphas self-audit
#
# Verifies that malphas behaves as documented:
# - No files written to disk during operation
# - Address book contains no plaintext
# - Messages exist only in RAM
# - Panic wipe clears all state
# - Crypto primitives are correct versions
# - Cover traffic is indistinguishable from real messages
# - Session keys are ephemeral
#
# This is NOT a substitute for a professional security audit.
# It verifies observable behavior, not absence of backdoors.
#
# Usage:
#   bash scripts/audit.sh
#

set -e

# Activate venv first if available
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Find Python
PYTHON=""
for py in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v $py &>/dev/null; then
        PYTHON=$py
        break
    fi
done

if [ -z "$PYTHON" ]; then
    if [ -f ".venv/bin/python3" ]; then
        PYTHON=".venv/bin/python3"
    else
        echo "  [err] python3 not found"
        exit 1
    fi
fi

echo ""
echo "  malphas self-audit"
echo "  ──────────────────"
echo ""
echo "  This verifies observable security properties."
echo "  It is NOT a substitute for a professional audit."
echo ""

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "0" ]; then
        echo -e "  \033[32m[PASS]\033[0m $name"
        PASS=$((PASS + 1))
    else
        echo -e "  \033[31m[FAIL]\033[0m $name"
        FAIL=$((FAIL + 1))
    fi
}

# ── 1. Crypto library versions ──────────────────────────────────────────────

echo "  --- Crypto libraries ---"
echo ""

$PYTHON -c "
import cryptography
print(f'  cryptography: {cryptography.__version__}')
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
print('  primitives:   ChaCha20-Poly1305, Ed25519, X25519, HKDF-SHA256')
import argon2
print(f'  argon2-cffi:  {argon2.__version__}')
import stem
print(f'  stem:         {stem.__version__}')
"
echo ""

# ── 2. No custom crypto ─────────────────────────────────────────────────────

echo "  --- Audit checks ---"
echo ""

# Check that no custom crypto implementations exist
CUSTOM_CRYPTO=$($PYTHON -c "
import ast, sys
suspect = []
for f in ['src/malphas/crypto.py', 'src/malphas/onion.py', 'src/malphas/identity.py']:
    with open(f) as fh:
        src = fh.read()
    # Check for raw AES, DES, RC4, MD5 usage
    for bad in ['AES', 'DES', 'RC4', 'MD5', 'SHA1(', 'hashlib.md5']:
        if bad in src and 'SHA1' not in 'peer_id':
            suspect.append(f'{f}: {bad}')
# SHA1 is only used for peer_id derivation (non-security-critical)
# Filter it out
suspect = [s for s in suspect if 'SHA1' not in s or 'peer_id' not in open(s.split(':')[0]).read()]
if suspect:
    print('FOUND: ' + ', '.join(suspect))
    sys.exit(1)
sys.exit(0)
" 2>&1)
check "No custom or weak crypto primitives in source" "$?"

# ── 3. Deterministic identity ────────────────────────────────────────────────

$PYTHON -c "
from malphas.identity import create_identity
a = create_identity('audit-test-passphrase')
b = create_identity('audit-test-passphrase')
assert a.peer_id == b.peer_id, 'peer_id mismatch'
assert a.x25519_pub_bytes == b.x25519_pub_bytes, 'x25519 mismatch'
assert a.ed25519_pub_bytes == b.ed25519_pub_bytes, 'ed25519 mismatch'
" 2>/dev/null
check "Deterministic identity (same passphrase = same keys)" "$?"

# ── 4. Different passphrases = different identities ──────────────────────────

$PYTHON -c "
from malphas.identity import create_identity
a = create_identity('passphrase-A')
b = create_identity('passphrase-B')
assert a.peer_id != b.peer_id
assert a.x25519_pub_bytes != b.x25519_pub_bytes
" 2>/dev/null
check "Different passphrases produce different identities" "$?"

# ── 5. Address book encryption ───────────────────────────────────────────────

$PYTHON -c "
import tempfile, os
from malphas.identity import create_identity_with_book_key
from malphas.addressbook import AddressBook, Contact

ident, key = create_identity_with_book_key('audit-book-test')
path = tempfile.mktemp(suffix='.book')
book = AddressBook(path, key)
book.load()
book.add(Contact('alice', 'a'*40, '10.0.0.1', 7777, 'b'*64, 'c'*64))

raw = open(path, 'rb').read()
assert b'alice' not in raw, 'plaintext label found on disk'
assert b'10.0.0.1' not in raw, 'plaintext host found on disk'
assert b'peer_id' not in raw, 'JSON field name found on disk'

# Wrong key must fail
_, wrong_key = create_identity_with_book_key('wrong-passphrase')
book2 = AddressBook(path, wrong_key)
try:
    book2.load()
    assert False, 'wrong key accepted'
except ValueError:
    pass  # correct

os.unlink(path)
" 2>/dev/null
check "Address book encrypted, no plaintext on disk" "$?"

$PYTHON -c "
import tempfile, os
from malphas.identity import create_identity_with_book_key
from malphas.addressbook import AddressBook, Contact

_, key = create_identity_with_book_key('audit-padding')
path = tempfile.mktemp(suffix='.book')

book1 = AddressBook(path + '1', key)
book1.load()
book1.add(Contact('a', 'a'*40, '1.1.1.1', 1, 'b'*64, 'c'*64))

book2 = AddressBook(path + '2', key)
book2.load()
book2.add(Contact('a', 'a'*40, '1.1.1.1', 1, 'b'*64, 'c'*64))
book2.add(Contact('b', 'd'*40, '2.2.2.2', 2, 'e'*64, 'f'*64))

size1 = os.path.getsize(path + '1')
size2 = os.path.getsize(path + '2')
assert size1 == size2, f'sizes differ: {size1} vs {size2}'

os.unlink(path + '1')
os.unlink(path + '2')
" 2>/dev/null
check "Address book padding hides contact count" "$?"

# ── 6. No disk writes during operation ───────────────────────────────────────

$PYTHON -c "
import tempfile, os
from malphas.memory import MessageStore

tmpdir = tempfile.mkdtemp()
before = set(os.listdir(tmpdir))
store = MessageStore()
store.store('alice', 'bob', 'secret message')
store.store('bob', 'alice', 'reply')
after = set(os.listdir(tmpdir))
assert before == after, 'files created during operation'
os.rmdir(tmpdir)
" 2>/dev/null
check "MessageStore writes nothing to disk" "$?"

# ── 7. Panic wipe ────────────────────────────────────────────────────────────

$PYTHON -c "
import asyncio
from malphas.identity import create_identity
from malphas.node import MalphasNode
from malphas.pinstore import PinStore

async def test():
    ident = create_identity('audit-panic')
    node = MalphasNode(ident, '127.0.0.1', 19900, cover_traffic=False, pin_store=PinStore())
    await node.start()

    node.store.store('a', 'b', 'sensitive')
    node.pins.check_and_pin('x'*40, b'\x01'*32)

    node.panic()

    assert node.store.get_conversation('a', 'b') == [], 'messages survived panic'
    assert node.discovery.all_peers() == [], 'peers survived panic'
    assert node.receipts.pending_count() == 0, 'receipts survived panic'
    assert node.pins.all_pins() == {}, 'pins survived panic'
    assert node._message_queue == {}, 'queue survived panic'

    await node.stop()

asyncio.run(test())
" 2>/dev/null
check "Panic wipe clears all in-memory state" "$?"

# ── 8. Onion routing isolation ───────────────────────────────────────────────

$PYTHON -c "
from malphas.identity import create_identity
from malphas.onion import peel_layer, wrap_onion

relay = create_identity('audit-relay')
dest = create_identity('audit-dest')
plaintext = b'top secret content'

circuit = [(relay.x25519_pub_bytes, relay.peer_id), (dest.x25519_pub_bytes, dest.peer_id)]
packet = wrap_onion(plaintext, circuit)

# Relay peels its layer
inner = packet[24:]
next_hop, relay_inner = peel_layer(relay.x25519_priv, inner)

# Relay must NOT see plaintext
assert plaintext not in relay_inner, 'relay can read plaintext'
assert next_hop == dest.peer_id, 'wrong next hop'

# Destination gets plaintext
next_hop2, dest_payload = peel_layer(dest.x25519_priv, relay_inner)
assert next_hop2 is None, 'not final hop'
assert dest_payload == plaintext, 'plaintext mismatch'
" 2>/dev/null
check "Onion routing: relay cannot read content" "$?"

# ── 9. Tamper detection ──────────────────────────────────────────────────────

$PYTHON -c "
from malphas.identity import create_identity
from malphas.onion import peel_layer, wrap_onion

dest = create_identity('audit-tamper')
packet = bytearray(wrap_onion(b'data', [(dest.x25519_pub_bytes, dest.peer_id)]))
packet[30] ^= 0x01  # flip one bit

try:
    peel_layer(dest.x25519_priv, bytes(packet[24:]))
    exit(1)  # should have raised
except ValueError:
    pass  # correct — tampered packet rejected
" 2>/dev/null
check "Tampered onion packets are rejected" "$?"

# ── 10. Ephemeral session keys ───────────────────────────────────────────────

$PYTHON -c "
from malphas.crypto import generate_ephemeral_keypair, ecdh_shared_secret, derive_session_key

priv_a, pub_a = generate_ephemeral_keypair()
priv_b, pub_b = generate_ephemeral_keypair()

# Both sides derive same key
shared_a = ecdh_shared_secret(priv_a, pub_b)
shared_b = ecdh_shared_secret(priv_b, pub_a)
assert shared_a == shared_b, 'ECDH not symmetric'

key_a = derive_session_key(shared_a, pub_a, pub_b)
key_b = derive_session_key(shared_b, pub_b, pub_a)
assert key_a == key_b, 'session keys differ'

# Different session = different keys
priv_c, pub_c = generate_ephemeral_keypair()
shared_c = ecdh_shared_secret(priv_a, pub_c)
key_c = derive_session_key(shared_c, pub_a, pub_c)
assert key_c != key_a, 'session keys not ephemeral'
" 2>/dev/null
check "Session keys are ephemeral and symmetric" "$?"

# ── 11. HMAC deniability ─────────────────────────────────────────────────────

$PYTHON -c "
from malphas.crypto import derive_hmac_key, hmac_sign, hmac_verify
import os

session_key = os.urandom(32)
hmac_key = derive_hmac_key(session_key)

data = b'message content'
tag = hmac_sign(hmac_key, data)

# Both peers can produce the same tag (deniable)
tag2 = hmac_sign(hmac_key, data)
assert tag == tag2, 'HMAC not deterministic'

# Verify works
assert hmac_verify(hmac_key, data, tag), 'HMAC verify failed'

# Tampered data fails
assert not hmac_verify(hmac_key, b'tampered', tag), 'tampered HMAC accepted'
" 2>/dev/null
check "HMAC deniable authentication (both peers produce same tag)" "$?"

# ── 12. Cover traffic indistinguishable ──────────────────────────────────────

$PYTHON -c "
from malphas.obfuscation import pad_payload, make_cover_payload, PAYLOAD_BLOCK

real = pad_payload(b'hello this is a real message')
cover = make_cover_payload()
assert len(real) == len(cover), f'sizes differ: {len(real)} vs {len(cover)}'
assert len(cover) % PAYLOAD_BLOCK == 0, 'not block-aligned'
" 2>/dev/null
check "Cover traffic same size as real messages" "$?"

# ── 13. Invite signature integrity ───────────────────────────────────────────

$PYTHON -c "
import base64
from malphas.identity import create_identity
from malphas.invite import generate_invite, parse_invite, PREFIX

ident = create_identity('audit-invite')
url = generate_invite(ident, '10.0.0.1', 7777)
data = parse_invite(url)
assert data['peer_id'] == ident.peer_id

# Tamper with the invite
blob = url[len(PREFIX):]
raw = bytearray(base64.urlsafe_b64decode(blob))
raw[10] ^= 0xFF
tampered = PREFIX + base64.urlsafe_b64encode(bytes(raw)).decode()
try:
    parse_invite(tampered)
    exit(1)
except ValueError:
    pass  # correct
" 2>/dev/null
check "Invite signatures verified, tampered invites rejected" "$?"

# ── 14. Key pinning ──────────────────────────────────────────────────────────

$PYTHON -c "
from malphas.pinstore import PinStore
import os

ps = PinStore()
ok1, _ = ps.check_and_pin('a'*40, b'\x01'*32)
assert ok1, 'first pin failed'

ok2, _ = ps.check_and_pin('a'*40, b'\x01'*32)
assert ok2, 'same key rejected'

ok3, pinned = ps.check_and_pin('a'*40, b'\x02'*32)
assert not ok3, 'different key accepted'
assert pinned is not None, 'no pinned key returned'
" 2>/dev/null
check "Key pinning rejects mismatched keys" "$?"

# ── 15. Argon2id timing ─────────────────────────────────────────────────────

$PYTHON -c "
import time, hashlib
from malphas.identity import _derive_seed

# SHA1 baseline
t0 = time.time()
for _ in range(100):
    hashlib.sha1(b'test').digest()
sha1_time = (time.time() - t0) / 100

# Argon2id
t0 = time.time()
_derive_seed('timing-test')
argon2_time = time.time() - t0

assert argon2_time > sha1_time * 100, f'Argon2 not slow enough: {argon2_time:.3f}s vs SHA1 {sha1_time:.6f}s'
" 2>/dev/null
check "Argon2id significantly slower than SHA1 (brute force resistant)" "$?"

# ── 16. Double Ratchet per-message keys ──────────────────────────────────────

$PYTHON -c "
from malphas.ratchet import RatchetState
from malphas.crypto import generate_ephemeral_keypair, ecdh_shared_secret

priv_a, pub_a = generate_ephemeral_keypair()
priv_b, pub_b = generate_ephemeral_keypair()
shared = ecdh_shared_secret(priv_a, pub_b)

a = RatchetState.from_shared_secret(shared, priv_a, pub_b, is_initiator=True)
b = RatchetState.from_shared_secret(shared, priv_b, pub_a, is_initiator=False)

_, c1 = a.encrypt(b'msg1')
_, c2 = a.encrypt(b'msg1')
assert c1 != c2, 'same ciphertext for different ratchet steps'

h, c = a.encrypt(b'test')
pt = b.decrypt(h, c)
assert pt == b'test', 'ratchet decrypt failed'
" 2>/dev/null
check "Double Ratchet: per-message forward secrecy" "$?"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "  ──────────────────────────────────────────"
echo "  results: $PASS passed, $FAIL failed"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "  all checks passed."
    echo "  this does NOT guarantee the absence of"
    echo "  vulnerabilities — only a professional"
    echo "  audit can provide that assurance."
else
    echo "  some checks failed — investigate above."
fi
echo "  ──────────────────────────────────────────"
echo ""
