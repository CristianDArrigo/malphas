"""
Per-user Argon2 salt persistence.

Until v0.6.x, the Argon2 salt was a hardcoded constant
(`malphas-kdf-salt`), the same for every user. That made a single
rainbow table effective against every malphas user in the world.
v0.7.0 replaces the constant with a 16-byte random value persisted in
`~/.malphas/salt`. The file is written once at first run, mode 0600,
and read back unchanged on every subsequent run.

Lose the file → lose the identity (the same passphrase will produce
a fresh seed). Phase 3 (BIP39 mnemonic) gives the user a recoverable
backup of the salt material.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

SALT_LEN = 16


def load_or_create_salt(path: Path) -> bytes:
    """
    Read the salt at `path`, or generate one and write it if absent.

    Raises ValueError if the file exists but has the wrong length —
    we refuse to silently overwrite anything that looks like a salt
    file but isn't ours, since that would replace the user's identity.
    """
    if path.exists():
        if not path.is_file():
            raise ValueError(f"salt path is not a regular file: {path}")
        data = path.read_bytes()
        if len(data) != SALT_LEN:
            raise ValueError(
                f"salt file at {path} has wrong length: {len(data)} != {SALT_LEN}"
            )
        return data

    # File missing — generate a fresh salt and write it atomically
    # with mode 0600. The atomic-rename pattern avoids races where
    # another process might read a half-written file.
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(SALT_LEN)
    tmp = path.with_suffix(".salt-tmp")

    # Open with O_EXCL | O_CREAT so we don't clobber a concurrent
    # writer. Mode 0600 from the start.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(salt)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    # Atomic rename. If two processes race here, only one wins; the
    # loser's tmp file is left behind for cleanup.
    try:
        os.replace(str(tmp), str(path))
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    return salt
