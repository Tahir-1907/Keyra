"""Encrypted vault backups.

Format of a `.mcfbak` file (encrypted body, readable technical header,
self-contained):

    MAGIC (8 B) | header length (4 B, big-endian) | JSON header
    | nonce (12 B) | AES-256-GCM( zlib( complete SQLite database ) )

* The JSON header is READABLE without the password (not secret, but not
  hidden either): vault identifier and name, backup type and date,
  application version, schema and format versions, and what unlocking
  needs — Argon2id parameters, salt, wrapped DEK, verifier, exactly like
  `vault_meta`. The backup therefore opens with the master password **in
  effect when the backup was made**, even if the original vault is gone.
* Body encryption key: HKDF-SHA256(DEK, "mon-coffre-fort:backup:v1") —
  separate from the data key.
* AES-GCM associated data = MAGIC + header: any change to the header is
  detected.
* The body (the complete database: entries, metadata, history, categories)
  is readable only with the master password; a backup can be copied to
  external media, keeping in mind that its header reveals the information
  above. A backup of a v1 to v3 vault contains the database in its old
  format (plaintext metadata INSIDE the encrypted body).

Restoring a backup always creates a **new** vault: nothing is overwritten.

The backup kinds ("manuelle", "auto", "migration") are written into the
header and the file name: they are persisted values and must never change.
`kind_label()` gives their English display label.
"""

from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import struct
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app import __version__
from app.core import crypto
from app.core.exceptions import VaultCorruptedError, VaultError
from app.core.vault import (
    MAX_VAULT_NAME_LENGTH,
    Vault,
    VaultInfo,
    check_supported_versions,
    generate_vault_id,
    unwrap_data_key,
    validate_vault_name,
)
from app.database import database
from app.database.models import VaultMeta
from app.database.repositories import VaultMetaRepository
from app.i18n import tr
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger
from app.utils.paths import default_backup_dir, vault_path

MAGIC = b"MCFBAK\x00\x01"
BACKUP_SUFFIX = ".mcfbak"
_BACKUP_KEY_INFO = b"mon-coffre-fort:backup:v1"
_MAX_HEADER_SIZE = 64 * 1024
# Write temporaries (".tmp-XXXX.mcfbak"): ignored when listing.
_TEMP_PREFIX = ".tmp-"
DEFAULT_AUTO_BACKUPS_KEPT = 10

KIND_MANUAL = "manuelle"
KIND_AUTO = "auto"
KIND_MIGRATION = "migration"  # made just before a schema migration; never rotated
# Translation keys (app/i18n) of the persisted kinds; the stored values never change.
KIND_LABELS = {KIND_MANUAL: "backup.kind.manual", KIND_AUTO: "backup.kind.auto",
               KIND_MIGRATION: "backup.kind.migration"}


def kind_label(kind: str) -> str:
    """Display label of a persisted backup kind (unknown kinds shown as is)."""
    return tr(KIND_LABELS[kind]) if kind in KIND_LABELS else kind


class BackupError(VaultError):
    """Invalid or unreadable backup file, or restore impossible."""


@dataclass(frozen=True, slots=True)
class BackupInfo:
    """Information readable without the password (header)."""

    path: Path
    vault_id: str
    vault_name: str
    created_at: str
    kind: str
    size: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Base64 value expected.")
    return base64.b64decode(value.encode("ascii"), validate=True)


def _header_for(vault: Vault, kind: str) -> dict:
    meta = VaultMetaRepository(vault.connection).get()
    if meta is None:
        raise VaultCorruptedError(tr("vault.error.meta_missing"))
    return {
        "format": "mon-coffre-fort-backup",
        "version": 1,
        "app_version": __version__,
        "vault_id": vault.vault_id,
        "vault_name": meta.vault_name,
        "kind": kind,
        "created_at": datetime.now(UTC).isoformat(),
        "schema_version": meta.schema_version,
        "format_version": meta.format_version,
        "kdf_name": meta.kdf_name,
        "kdf_params": meta.kdf_params.to_dict(),
        "kdf_salt": _b64(meta.kdf_salt),
        "wrapped_key_blob": _b64(meta.wrapped_key_blob),
        "verifier_blob": _b64(meta.verifier_blob),
    }


def _meta_from_header(header: dict) -> VaultMeta:
    try:
        return VaultMeta(
            # Strict integers: validated by VaultMeta (no "3.7" -> 3 conversion).
            schema_version=header["schema_version"],
            format_version=header["format_version"],
            kdf_name=str(header["kdf_name"]),
            kdf_params=crypto.Argon2Params.from_dict(header["kdf_params"]),
            kdf_salt=_unb64(header["kdf_salt"]),
            wrapped_key_blob=_unb64(header["wrapped_key_blob"]),
            verifier_blob=_unb64(header["verifier_blob"]),
            vault_name=str(header["vault_name"]),
            created_at=str(header["created_at"]),
            updated_at=str(header["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError(tr("backup.error.header_invalid")) from exc


def _read(path: Path) -> tuple[bytes, dict, bytes]:
    """Returns (header bytes, decoded header, rest of the file)."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BackupError(tr("backup.error.cannot_read", name=path.name)) from exc
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise BackupError(tr("backup.error.not_keyra", name=path.name))
    (length,) = struct.unpack(">I", data[len(MAGIC):len(MAGIC) + 4])
    start = len(MAGIC) + 4
    if length > _MAX_HEADER_SIZE or start + length > len(data):
        raise BackupError(tr("backup.error.truncated_or_invalid"))
    header_bytes = data[start:start + length]
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError as exc:
        raise BackupError(tr("backup.error.header_unreadable")) from exc
    if not isinstance(header, dict) or header.get("format") != "mon-coffre-fort-backup":
        raise BackupError(tr("backup.error.unknown_format"))
    version = header.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise BackupError(tr("backup.error.version_invalid"))
    if version > 1:
        raise BackupError(tr("backup.error.newer"))
    return header_bytes, header, data[start + length:]


# --- API ----------------------------------------------------------------------------


def create_backup(vault: Vault, directory: Path | None = None, kind: str = KIND_MANUAL,
                  destination: Path | None = None) -> Path:
    """Creates an encrypted backup of the (unlocked) vault and returns its path."""
    dek = vault._require_unlocked_key()
    header = _header_for(vault, kind)
    header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    database_bytes = vault.connection.serialize()  # consistent snapshot (WAL included)
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    nonce, ciphertext = crypto.aes_gcm_encrypt(
        key, zlib.compress(database_bytes, 9), MAGIC + header_bytes
    )
    if destination is None:
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")  # local time
        directory = directory or default_backup_dir()
        destination = directory / f"{vault.vault_id}_{stamp}_{kind}{BACKUP_SUFFIX}"
        # Two backups in the same second: never a silent overwrite.
        counter = 2
        while destination.exists():
            destination = directory / f"{vault.vault_id}_{stamp}-{counter}_{kind}{BACKUP_SUFFIX}"
            counter += 1
    payload = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + nonce + ciphertext
    write_private_atomic(destination, payload, temp_prefix=_TEMP_PREFIX,
                         temp_suffix=BACKUP_SUFFIX)
    get_logger().info("Backup created (%s): %s", kind, destination.name)
    return destination


def read_backup_info(path: Path) -> BackupInfo:
    _header_bytes, header, _rest = _read(path)
    return BackupInfo(
        path=path,
        vault_id=str(header.get("vault_id", "")),
        vault_name=str(header.get("vault_name", "")),
        created_at=str(header.get("created_at", "")),
        kind=str(header.get("kind", "")),
        size=path.stat().st_size,
    )


def list_backups(directory: Path | None = None, vault_id: str | None = None) -> list[BackupInfo]:
    """Backups present in a folder, most recent first."""
    directory = directory or default_backup_dir()
    infos = []
    for path in directory.glob(f"*{BACKUP_SUFFIX}"):
        if path.name.startswith(_TEMP_PREFIX):  # write in progress or interrupted
            continue
        try:
            info = read_backup_info(path)
        except (BackupError, OSError):  # invalid file, or deleted in the meantime
            continue
        if vault_id is None or info.vault_id == vault_id:
            infos.append(info)
    infos.sort(key=lambda i: i.created_at, reverse=True)
    return infos


def rotate_auto_backups(vault_id: str, directory: Path | None = None,
                        keep: int = DEFAULT_AUTO_BACKUPS_KEPT) -> int:
    """Keeps only the `keep` most recent automatic backups of the vault."""
    autos = [i for i in list_backups(directory, vault_id) if i.kind == KIND_AUTO]
    removed = 0
    for info in autos[keep:]:
        try:
            info.path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def delete_backup(path: Path, vault_id: str) -> None:
    """Deletes ONE backup of vault `vault_id`.

    The header is read first: a file that is not a valid backup of THIS vault
    is never deleted (BackupError).
    """
    path = Path(path)
    if path.suffix != BACKUP_SUFFIX or not path.is_file():
        raise BackupError(tr("backup.error.not_backup"))
    if read_backup_info(path).vault_id != vault_id:
        raise BackupError(tr("backup.error.other_vault"))
    path.unlink()


def delete_backups(vault_id: str, directory: Path | None = None,
                   kind: str | None = None) -> int:
    """Deletes the vault backups (all of them, or of one kind); returns how many."""
    removed = 0
    for info in list_backups(directory, vault_id):
        if kind is not None and info.kind != kind:
            continue
        try:
            delete_backup(info.path, vault_id)
            removed += 1
        except (BackupError, OSError):
            pass
    return removed


def verify_backup(path: Path, dek: bytes) -> None:
    """Checks that a backup is FULLY restorable with the data key `dek`.

    Reads the file back, authenticates and decrypts the body, decompresses the
    database and checks its SQLite integrity, in memory only (no file written).
    Raises BackupError otherwise. Used before a migration: a migration never
    runs without a verified backup.
    """
    header_bytes, header, rest = _read(path)
    meta = _meta_from_header(header)
    if len(rest) < crypto.NONCE_SIZE + crypto.TAG_SIZE:
        raise BackupError(tr("backup.error.truncated"))
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    try:
        image = bytearray(zlib.decompress(crypto.aes_gcm_decrypt(
            key, rest[:crypto.NONCE_SIZE], rest[crypto.NONCE_SIZE:], MAGIC + header_bytes)))
    except (crypto.AuthenticationFailed, zlib.error) as exc:
        raise BackupError(tr("backup.error.wrong_key")) from exc
    if len(image) < 100 or not image.startswith(b"SQLite format 3\x00"):
        raise BackupError(tr("backup.error.not_database"))
    image[18] = image[19] = 1  # classic journal mode (as when restoring)
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(bytes(image))
        if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
            raise BackupError(tr("backup.error.inconsistent"))
        stored = conn.execute("SELECT schema_version FROM vault_meta WHERE id = 1;").fetchone()
        if stored is None or stored[0] != meta.schema_version:
            raise BackupError(tr("backup.error.mismatch"))
    except sqlite3.DatabaseError as exc:
        raise BackupError(tr("backup.error.database_unreadable")) from exc
    finally:
        conn.close()


def restore_backup(path: Path, master_password: str) -> VaultInfo:
    """Restores a backup as a **new** vault.

    Raises WrongMasterPasswordError (wrong password), BackupError or
    VaultCorruptedError (invalid or tampered file).
    """
    header_bytes, header, rest = _read(path)
    meta = _meta_from_header(header)
    check_supported_versions(meta)
    dek = unwrap_data_key(master_password, meta)  # WrongMasterPasswordError if wrong

    if len(rest) < crypto.NONCE_SIZE + 16:
        raise BackupError(tr("backup.error.truncated"))
    nonce, ciphertext = rest[:crypto.NONCE_SIZE], rest[crypto.NONCE_SIZE:]
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    try:
        compressed = crypto.aes_gcm_decrypt(key, nonce, ciphertext, MAGIC + header_bytes)
        database_bytes = zlib.decompress(compressed)
    except (crypto.AuthenticationFailed, zlib.error) as exc:
        raise VaultCorruptedError(tr("backup.error.tampered")) from exc

    # Part of the NEW vault's name, written in the interface language of the moment.
    suffix = tr("backup.restored_suffix", date=f"{datetime.now().astimezone():%Y-%m-%d %H:%M}")
    # The name comes from the header (not authenticated at this point): bounded and cleaned.
    base = (" ".join(meta.vault_name.split())[:MAX_VAULT_NAME_LENGTH - len(suffix)]
            or tr("backup.default_vault_name"))
    restored_name = validate_vault_name(base + suffix)
    new_id = generate_vault_id(meta.vault_name)
    directory = vault_path(new_id)
    db_path = directory / "vault.db"
    try:
        image = bytearray(database_bytes)
        if len(image) < 100 or not image.startswith(b"SQLite format 3\x00"):
            raise BackupError(tr("backup.error.not_database"))
        # Bytes 18-19 of the SQLite header = 2 in WAL mode: switch back to classic
        # journal mode so that the file is readable on its own (without -wal);
        # database.connect() then re-enables WAL.
        image[18] = image[19] = 1
        write_private_atomic(db_path, bytes(image), temp_prefix=_TEMP_PREFIX,
                             temp_suffix=BACKUP_SUFFIX)
        conn = database.connect(db_path)
        try:
            if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
                raise BackupError(tr("backup.error.inconsistent"))
            with conn:
                VaultMetaRepository(conn).rename_vault(
                    restored_name, datetime.now(UTC).isoformat()
                )
        finally:
            conn.close()
        # Full verification: the restored vault must unlock.
        if meta.schema_version < database.SCHEMA_VERSION:
            # Old backup (v1 to v3): vault restored as is, verified WITHOUT being modified;
            # its upgrade will be OFFERED when it is first opened (preflight, explicit
            # confirmation, backup, migration, verification: vault_upgrade).
            Vault.open_for_migration(new_id, master_password).close()
        else:
            Vault.unlock(new_id, master_password).close()
    except Exception as exc:
        shutil.rmtree(directory, ignore_errors=True)
        if isinstance(exc, VaultError):
            raise
        raise BackupError(tr("backup.error.restore_failed")) from exc

    get_logger().info("Backup restored as new vault: %s", new_id)
    return VaultInfo(new_id, restored_name, meta.format_version, meta.created_at, meta.created_at)
