"""Recovery key format.

The key is shown to the user only once, who writes it down on paper.
It is never stored: the vault only keeps the DEK wrapped by a key derived
from it (see `Vault.create_recovery_key`).

Format: 32 characters in 8 groups of 4, Crockford base32 alphabet
(no I, L, O, U: no confusion with 1 and 0):

    30 random characters (150 bits, `secrets` module)
    + 2 check characters (10 bits of the SHA-256 of the first 30)

The check characters protect nothing: they only report a typo immediately,
instead of a "wrong key" after the Argon2id derivation. 150 bits of
randomness make any exhaustive search impossible.
"""

from __future__ import annotations

import hashlib
import secrets

from app.core.exceptions import RecoveryKeyFormatError

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
DATA_LENGTH = 30
CHECK_LENGTH = 2
GROUP = 4
# Tolerated readings (Crockford): O -> 0, I and L -> 1.
_ALIASES = str.maketrans({"O": "0", "I": "1", "L": "1"})


def _check(data: str) -> str:
    digest = int.from_bytes(hashlib.sha256(data.encode("ascii")).digest()[:2], "big") >> 6
    return ALPHABET[digest >> 5] + ALPHABET[digest & 31]


def generate() -> str:
    """New recovery key, formatted for display."""
    data = "".join(secrets.choice(ALPHABET) for _ in range(DATA_LENGTH))
    return format_key(data + _check(data))


def format_key(compact: str) -> str:
    return "-".join(compact[i:i + GROUP] for i in range(0, len(compact), GROUP))


def normalize(text: str) -> str:
    """Secret part (30 characters) of an entered key; tolerates spaces, dashes, case.

    Raises RecoveryKeyFormatError if the length, a character or the check
    does not match.
    """
    compact = "".join(ch for ch in text.upper() if ch not in " -\t\n\r").translate(_ALIASES)
    if len(compact) != DATA_LENGTH + CHECK_LENGTH:
        raise RecoveryKeyFormatError(
            f"A recovery key has {DATA_LENGTH + CHECK_LENGTH} characters "
            f"({len(compact)} entered).")
    if any(ch not in ALPHABET for ch in compact):
        raise RecoveryKeyFormatError("The key contains an invalid character.")
    data, check = compact[:DATA_LENGTH], compact[DATA_LENGTH:]
    if not secrets.compare_digest(_check(data), check):
        raise RecoveryKeyFormatError("Probable typo: check the key you entered.")
    return data
