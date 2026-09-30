"""Cryptographic primitives of the vault.

Security choices (see README > Security model for details):

* Key derivation: **Argon2id** (RFC 9106), through the native implementation
  of `cryptography` (>= 44, `hazmat.primitives.kdf.argon2`) when available,
  otherwise through `argon2-cffi` (Debian package `python3-argon2`, which
  relies on libargon2, the reference implementation by the Argon2 authors).
  Debian 13 ships `cryptography` 43, which lacks Argon2id: this is the case
  of the .deb package. Argon2id being standardized, both produce exactly the
  same key for the same parameters (checked by the tests, which compare them
  byte for byte). No cryptography is reinvented here.
* Encryption: **AES-256-GCM** (authenticated encryption), through the same
  package, OpenSSL backend.
* Randomness: exclusively `secrets` / `os.urandom` (the system CSPRNG),
  never the `random` module.
* Envelope encryption: the master password NEVER encrypts the data directly.
  It is only used to wrap a random data encryption key (DEK) generated when
  the vault is created. This makes it possible to change the master password
  without re-encrypting all the data, and ensures that no vault data is ever
  cryptographically bound to the master password directly.

No function in this module logs sensitive material.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # cryptography >= 44
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _CryptographyArgon2id
except ImportError:  # e.g. Debian 13: cryptography 43
    _CryptographyArgon2id = None

try:  # argon2-cffi (Debian: python3-argon2)
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw
except ImportError:
    _argon2_hash_secret_raw = None

if _CryptographyArgon2id is None and _argon2_hash_secret_raw is None:
    raise ImportError(
        "Argon2id unavailable: install cryptography >= 44 (pip) or the Debian "
        "package python3-argon2 (sudo apt install python3-argon2)."
    )

ARGON2_BACKENDS = tuple(
    name for name, available in (
        ("cryptography", _CryptographyArgon2id is not None),
        ("argon2-cffi", _argon2_hash_secret_raw is not None),
    ) if available
)
ARGON2_BACKEND = ARGON2_BACKENDS[0]  # the one used by default

# --- Sizing constants ------------------------------------------------

SALT_SIZE = 16          # bytes — Argon2id recommendation
NONCE_SIZE = 12          # bytes — standard size for AES-GCM
KEY_SIZE = 32            # bytes — AES-256
TAG_SIZE = 16            # bytes — GCM authentication tag (end of the ciphertext)
FORMAT_VERSION_ENTRY = 1  # format version of individual encrypted blobs

# Bounds for Argon2id parameters read from a file (defaults: 3 / 64 MiB / 4).
MAX_ARGON2_TIME_COST = 64
MAX_ARGON2_MEMORY_KIB = 1024 * 1024  # 1 GiB
MAX_ARGON2_PARALLELISM = 64
# Bounds for a salt read from a file: 8 bytes is the Argon2 minimum
# (RFC 9106); the application always generates SALT_SIZE.
MIN_SALT_SIZE = 8
MAX_SALT_SIZE = 64

# Re-exported so that callers can catch GCM authentication failures
# without importing `cryptography` directly.
AuthenticationFailed = InvalidTag


@dataclass(frozen=True, slots=True)
class Argon2Params:
    """Argon2id parameters associated with a vault.

    Stored in plaintext in the vault metadata (they are not secret) so that
    the default parameters can evolve in the future without breaking
    compatibility with existing vaults.

    The defaults aim for a reasonable security/performance trade-off on a
    desktop computer (~300-600 ms of derivation), consistent with the OWASP
    recommendations for Argon2id.
    """

    time_cost: int = 3          # iterations
    memory_cost: int = 65536    # KiB => 64 MiB
    parallelism: int = 4        # lanes
    hash_len: int = KEY_SIZE

    def to_dict(self) -> dict:
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Argon2Params:
        """Reads parameters stored in a file, within bounds.

        These values come from potentially crafted files (modified vault,
        backup header, received export): without bounds, a file could demand
        terabytes of memory or billions of iterations and freeze the
        application before the password is even checked.
        Raises ValueError if a value is out of bounds.
        """
        params = cls(
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
            hash_len=int(data.get("hash_len", KEY_SIZE)),
        )
        if not (
            1 <= params.time_cost <= MAX_ARGON2_TIME_COST
            and 1 <= params.parallelism <= MAX_ARGON2_PARALLELISM
            and 8 * params.parallelism <= params.memory_cost <= MAX_ARGON2_MEMORY_KIB
            and params.hash_len == KEY_SIZE
        ):
            raise ValueError("Argon2id parameters out of the allowed bounds.")
        return params


def check_salt(salt: object) -> bytes:
    """Validates a salt read from a file (vault, backup, export).

    Raises ValueError, which the caller turns into a corrupted-file error:
    without this check, a salt that is too short would only fail deep inside
    Argon2id.
    """
    if not isinstance(salt, bytes) or not MIN_SALT_SIZE <= len(salt) <= MAX_SALT_SIZE:
        raise ValueError("Invalid Argon2id salt.")
    return salt


# --- Cryptographically secure randomness ------------------------------------


def generate_salt(size: int = SALT_SIZE) -> bytes:
    return secrets.token_bytes(size)


def generate_nonce(size: int = NONCE_SIZE) -> bytes:
    return secrets.token_bytes(size)


def generate_key(size: int = KEY_SIZE) -> bytes:
    """Generates a random key (used in particular for the vault DEK)."""
    return secrets.token_bytes(size)


# --- Key derivation (Argon2id) -------------------------------------------------


def derive_key(password: str, salt: bytes, params: Argon2Params) -> bytes:
    """Derives a key of `params.hash_len` bytes from the master password.

    The password is never kept; only the derived key is, temporarily, in
    memory.
    """
    return _derive_key_with(ARGON2_BACKEND, password, salt, params)


def _derive_key_with(backend: str, password: str, salt: bytes, params: Argon2Params) -> bytes:
    """Argon2id (version 0x13) with the requested implementation."""
    secret = password.encode("utf-8")
    if backend == "cryptography" and _CryptographyArgon2id is not None:
        return _CryptographyArgon2id(
            salt=salt,
            length=params.hash_len,
            iterations=params.time_cost,
            lanes=params.parallelism,
            memory_cost=params.memory_cost,
        ).derive(secret)
    if backend == "argon2-cffi" and _argon2_hash_secret_raw is not None:
        return _argon2_hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=_Argon2Type.ID,
            version=19,
        )
    raise ValueError(f"Argon2id implementation unavailable: {backend}")


def derive_subkey(key: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    """Derives an independent subkey from a master key (HKDF-SHA256, RFC 5869).

    Key separation: for example, the backup key is derived from the DEK with
    its own `info`, instead of reusing the DEK as is.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("The master key must be 32 bytes long.")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


# --- Authenticated encryption (AES-256-GCM) ----------------------------------------


def aes_gcm_encrypt(
    key: bytes, plaintext: bytes, associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypts `plaintext` with an AES-256 key and a unique random nonce.

    Returns (nonce, ciphertext) where `ciphertext` includes the authentication
    tag (standard behavior of AESGCM in the `cryptography` package).

    IMPORTANT: a nonce must NEVER be reused with the same key. This is why a
    random 96-bit nonce is generated on every call: with AES-GCM and a CSPRNG,
    the collision risk is negligible for the amount of data handled by a
    local vault.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("The AES-256-GCM key must be 32 bytes long.")
    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypts and authenticates `ciphertext`.

    Raises `AuthenticationFailed` (= `cryptography.exceptions.InvalidTag`) if
    the key is wrong or the data has been tampered with. It is up to the
    caller (vault layer) to turn this failure into `WrongMasterPasswordError`
    or `VaultCorruptedError` depending on the context, because this crypto
    layer does not know about that domain distinction.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("The AES-256-GCM key must be 32 bytes long.")
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


# --- Versioned blob (nonce + ciphertext) for storage -------------------------


def pack_blob(nonce: bytes, ciphertext: bytes, version: int = FORMAT_VERSION_ENTRY) -> bytes:
    """Serializes (version, nonce, ciphertext) into a single BLOB for SQLite.

    Format: 1 version byte | NONCE_SIZE nonce bytes | rest = ciphertext.
    """
    if not (0 <= version <= 255):
        raise ValueError("Invalid blob version.")
    return bytes([version]) + nonce + ciphertext


def unpack_blob(blob: bytes) -> tuple[int, bytes, bytes]:
    """Inverse of `pack_blob`. Raises ValueError if the blob is truncated or of an
    unknown version (the version byte is not authenticated: only the version written
    by the application is accepted, so that it can never steer decryption).
    """
    if not isinstance(blob, bytes) or len(blob) < 1 + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Invalid or truncated encrypted blob.")
    version = blob[0]
    if version != FORMAT_VERSION_ENTRY:
        raise ValueError("Unsupported encrypted blob version.")
    nonce = blob[1 : 1 + NONCE_SIZE]
    ciphertext = blob[1 + NONCE_SIZE :]
    return version, nonce, ciphertext


def encrypt_field(key: bytes, plaintext: str, associated_data: bytes | None = None) -> bytes:
    """Encrypts a text value to be stored in the database (BLOB)."""
    nonce, ciphertext = aes_gcm_encrypt(key, plaintext.encode("utf-8"), associated_data)
    return pack_blob(nonce, ciphertext)


def decrypt_field(key: bytes, blob: bytes, associated_data: bytes | None = None) -> str:
    """Decrypts a BLOB produced by `encrypt_field`."""
    _version, nonce, ciphertext = unpack_blob(blob)
    plaintext = aes_gcm_decrypt(key, nonce, ciphertext, associated_data)
    return plaintext.decode("utf-8")


def wipe(buffer: bytearray) -> None:
    """Best effort: overwrites a mutable buffer in memory.

    Known limitation: CPython does not guarantee the absence of copies
    (interning, garbage collector, disk swap). This narrows the exposure
    window; it is not an absolute guarantee that memory is erased.
    """
    for i in range(len(buffer)):
        buffer[i] = 0
