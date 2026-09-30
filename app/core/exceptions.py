"""Domain exceptions of the application core (crypto + vault).

Dedicated exceptions let the UI show clear messages without ever exposing
internal cryptographic details, and let the tests check the expected
behavior precisely.
"""

from __future__ import annotations


class VaultError(Exception):
    """Base class for every vault-related error."""


class WrongMasterPasswordError(VaultError):
    """The master password provided cannot decrypt the vault."""


class VaultCorruptedError(VaultError):
    """The vault file/database is corrupted or has been tampered with.

    Raised in particular when AES-GCM authentication fails for a reason other
    than a wrong password (e.g. truncated bytes, file modified by a third
    party).
    """


class UnsupportedVaultVersionError(VaultError):
    """The vault format is a version that this application cannot read."""


class VaultMigrationRequiredError(VaultError):
    """Vault in an older format (v1 to v3): it must be upgraded to v4 before use.

    Raised BEFORE any modification: the vault file is not touched.
    """


class VaultAlreadyExistsError(VaultError):
    """A vault with this name/identifier already exists."""


class VaultNotFoundError(VaultError):
    """The requested vault cannot be found."""


class VaultLockedError(VaultError):
    """Attempt to access the data of a locked vault."""


class InvalidMasterPasswordPolicyError(VaultError):
    """The master password provided does not meet the minimum policy."""


class RecoveryKeyError(VaultError):
    """Wrong recovery key for this vault."""


class RecoveryKeyFormatError(RecoveryKeyError):
    """Input that cannot be a recovery key (typo)."""


class NoRecoveryKeyError(VaultError):
    """The vault has no recovery key."""


class EntryError(VaultError):
    """Generic error related to vault entries."""


class EntryNotFoundError(EntryError):
    """The requested entry does not exist (or no longer exists)."""


class EntryValidationError(EntryError):
    """An entry's data is invalid (missing required field...)."""


class EntryDecryptionError(EntryError):
    """An encrypted field of an entry could not be authenticated/decrypted.

    Indicates tampering with the vault file (or an encrypted blob moved from
    one entry/field to another, detected thanks to the AES-GCM associated
    data).
    """


class CategoryError(VaultError):
    """Category-related error (empty name, duplicate, built-in category...)."""


class CategoryDecryptionError(CategoryError):
    """The encrypted name of a category could not be authenticated/decrypted (tampering)."""
