"""API keys: generating, recognizing and hashing them.

A key looks like ``vigil_3f9a0c1d2e4b_<43 random characters>``:

* ``vigil_`` is a fixed prefix, so secret scanners (such as GitHub's) can spot a key
  that was pasted somewhere it should not be.
* ``3f9a0c1d2e4b`` is the key id: public, used to find the key, safe to show in lists.
* The rest is the secret: 256 random bits, shown once when the key is created.

Only a hash of the secret is stored. Passwords need slow hashes (bcrypt, Argon2)
because people choose guessable ones. These secrets are random and 256 bits long,
so nothing can guess them, and a fast SHA-256 keeps every request fast.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum

KEY_PREFIX = "vigil"
KEY_PATTERN = re.compile(
    rf"{KEY_PREFIX}_(?P<key_id>[0-9a-f]{{12}})_(?P<secret>[A-Za-z0-9_-]{{43}})"
)


class Scope(StrEnum):
    """What a key may do. Give each client only what it needs (least privilege)."""

    INGEST = "ingest"  # send log lines in: for log shippers on servers
    READ = "read"  # read alerts out: for analysts and dashboards


@dataclass(frozen=True, slots=True)
class NewKey:
    key_id: str
    secret: str

    @property
    def token(self) -> str:
        return f"{KEY_PREFIX}_{self.key_id}_{self.secret}"


def generate_key() -> NewKey:
    # `secrets`, never `random`: random numbers for security must be unpredictable.
    return NewKey(key_id=secrets.token_hex(6), secret=secrets.token_urlsafe(32))


def parse_key(token: str) -> tuple[str, str] | None:
    """Split a key into (key id, secret), or None if it is not a well-formed key."""
    match = KEY_PATTERN.fullmatch(token)
    return None if match is None else (match["key_id"], match["secret"])


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
