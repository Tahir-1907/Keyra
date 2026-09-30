"""Upgrade of a v1/v2/v3 vault to v4: preflight, migration, verification.

Orchestration around the app.services.migration_v4 engine (all or nothing),
which is not modified:

1. `inspect` (read-only, no password): schema version, old plaintext `.bak`
   copies (reported, never deleted) and STRICT preflight.
2. Preflight: any unexpected SQLite structure (table, view, trigger, index,
   column) REFUSES the upgrade, vault intact. Nothing unknown is ignored or
   deleted: the engine rebuilds the known tables and would leave an unknown
   table as is (possibly with plaintext content) or silently drop an unknown
   column. Reference: the definitions in app.database.database
   (legacy_structure, LEGACY_INDEXES), not a copy.
3. `migrate_to_v4`: verified encrypted backup, single transaction, VACUUM.
4. Full verification AFTER the migration, through a normal opening
   (Vault.unlock): exact v4 structure, SQLite integrity, every metadata record,
   category, secret and history version read back, migration backup verified
   again. Only then is the v4 session opened.

This module never decides on its own: the interface asks for explicit
confirmation before calling `upgrade` or `recover_and_upgrade`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.core.entries import EntryService
from app.core.exceptions import VaultCorruptedError, VaultError, VaultNotFoundError
from app.core.vault import Vault
from app.database import database
from app.database.repositories import VaultMetaRepository
from app.services import backup
from app.services.migration_v4 import MigrationReport, legacy_plaintext_copies, migrate_to_v4
from app.utils.logging import get_logger
from app.utils.paths import vault_path

_DB_FILENAME = "vault.db"


class UpgradeRefusedError(VaultError):
    """Upgrade refused BEFORE any modification (unexpected structure, format)."""


class UpgradeVerificationError(VaultError):
    """The migration was committed but the final verification failed.

    The vault is in the v4 format and was not opened; the migration backup
    (original format, restorable by 1.6) is kept.
    """

    def __init__(self, message: str, backup_path: Path | None = None) -> None:
        super().__init__(message)
        self.backup_path = backup_path
        self.new_recovery_key = ""  # filled in on the "recovery" path


class RecoveredNotUpgradedError(VaultError):
    """Recovery succeeded (new password, NEW key) but the migration failed.

    The vault stayed in its original format, intact, with the new master password
    and the new recovery key (the old one no longer works): the new key MUST be
    shown to the user. To retry: unlock with the new password, and the upgrade is
    offered again.
    """

    def __init__(self, message: str, new_recovery_key: str) -> None:
        super().__init__(message)
        self.new_recovery_key = new_recovery_key


@dataclass(frozen=True, slots=True)
class UpgradeCheck:
    """State of a vault before the upgrade (read without password, without modification)."""

    vault_id: str
    schema_version: int
    problems: tuple[str, ...]
    legacy_plaintext_copies: tuple[Path, ...]

    @property
    def needs_upgrade(self) -> bool:
        return self.schema_version < database.SCHEMA_VERSION

    @property
    def can_upgrade(self) -> bool:
        return self.needs_upgrade and not self.problems


@dataclass(slots=True)
class UpgradeResult:
    vault: Vault  # v4 vault unlocked AND verified
    report: MigrationReport
    legacy_plaintext_copies: tuple[Path, ...] = ()
    warnings: list[str] = field(default_factory=list)


# --- Preflight ---------------------------------------------------------------------------


def unexpected_structures(conn: sqlite3.Connection, schema_version: int) -> list[str]:
    """STRICT differences with the expected structure (empty list: nothing unexpected).

    v1 to v3: tables and columns of legacy_structure, indexes of LEGACY_INDEXES, no
    view and no trigger. v4: exactly a new vault (v4_reference_structure).
    """
    objects = {tuple(row) for row in conn.execute(
        "SELECT type, name, tbl_name FROM sqlite_master;")}
    if schema_version >= database.V4_SCHEMA_VERSION:
        expected_objects, expected_columns = database.v4_reference_structure()
    else:
        expected_columns = database.legacy_structure(schema_version)
        expected_columns["sqlite_sequence"] = {"name", "seq"}
        expected_objects = {("table", name, name) for name in expected_columns}
        expected_objects |= {("index", name, table)
                             for name, (since, table) in database.LEGACY_INDEXES.items()
                             if since <= schema_version and table in expected_columns}
    labels = {"table": "unknown table", "view": "unknown view",
              "trigger": "unknown trigger", "index": "unexpected index"}
    problems = []
    for kind, name, table in sorted(objects - expected_objects):
        problems.append(f"{labels.get(kind, 'unknown ' + kind)}: {name}"
                        + (f" (on {table})" if kind in ("index", "trigger") else ""))
    for kind, name, _table in sorted(expected_objects - objects):
        if kind in ("index", "trigger"):
            problems.append(f"missing {'index' if kind == 'index' else 'trigger'}: {name}")
    for table, expected in sorted(expected_columns.items()):
        if ("table", table, table) not in objects:
            continue
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}
        problems += [f"unexpected column: {table}.{c}" for c in sorted(present - expected)]
    # Missing tables, missing columns and integrity: check already used when opening.
    problems += database.structure_problems(conn, schema_version)
    return problems


def inspect(vault_id: str) -> UpgradeCheck:
    """Read-only (no write lock, no file created); no password."""
    db_path = vault_path(vault_id) / _DB_FILENAME
    if not db_path.is_file():
        raise VaultNotFoundError(f"The vault \"{vault_id}\" cannot be found.")
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row  # expected by the repositories
        try:
            meta = VaultMetaRepository(conn).get()
            if meta is None:
                raise VaultCorruptedError("Vault metadata missing or corrupted.")
            problems = (unexpected_structures(conn, meta.schema_version)
                        if meta.schema_version <= database.V4_SCHEMA_VERSION
                        else ["format newer than the application"])
        finally:
            conn.close()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        raise VaultCorruptedError("The vault file is unreadable or corrupted.") from exc
    copies = tuple(sorted(db_path.parent.glob("vault.db.avant-schema-v*.bak")))
    return UpgradeCheck(vault_id, meta.schema_version, tuple(problems), copies)


def _refusal_message(problems: list[str] | tuple[str, ...]) -> str:
    return ("Upgrade impossible: the vault file contains items that the application "
            "did not create (details: " + "; ".join(problems[:5])
            + ("…" if len(problems) > 5 else "") + "). The vault has not been modified.")


def failure_details(exc: BaseException) -> list[str]:
    """Path and cause of a failure, taken from the exception chain (`__cause__`,
    `__context__`): what the migration engine attaches to "Preliminary backup
    impossible", for example. Only paths and error messages from the system or the
    application are reused, never vault data."""
    seen: set[int] = set()
    pending: list[BaseException | None] = [exc.__cause__, exc.__context__]
    while pending:
        current = pending.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, OSError):
            details = []
            if current.filename:
                # File never created (write temporary refused): its folder is the path that
                # is useful to the user.
                path = Path(current.filename)
                shown = path if path.exists() or not path.parent.exists() else path.parent
                details.append(f"Path: {shown}")
            return [*details, f"Cause: {current.strerror or type(current).__name__}"]
        if isinstance(current, VaultError):
            return [f"Cause: {current}"]
        pending += [current.__cause__, current.__context__]
    return []


def _refuse_if_unexpected(vault: Vault) -> None:
    meta = VaultMetaRepository(vault.connection).get()
    problems = unexpected_structures(vault.connection, meta.schema_version)
    if problems:
        get_logger().error("Upgrade refused, unexpected structure: %s (%d problems)",
                           vault.vault_id, len(problems))
        raise UpgradeRefusedError(_refusal_message(problems))


# --- Verification after the migration ------------------------------------------------------


def verify_upgraded(vault: Vault, report: MigrationReport) -> list[str]:
    """Reads back the WHOLE migrated vault; raises an exception on any discrepancy.

    Returns non-blocking warnings (e.g. VACUUM to be redone).
    """
    conn = vault.connection
    meta = VaultMetaRepository(conn).get()
    if meta.schema_version != database.V4_SCHEMA_VERSION or meta.vault_uuid is None:
        raise VaultError("v4 format not saved")
    problems = unexpected_structures(conn, database.V4_SCHEMA_VERSION)
    if problems:
        raise VaultError("unexpected v4 structure: " + "; ".join(problems))
    if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
        raise VaultError("SQLite integrity check failed")
    if conn.execute("PRAGMA foreign_key_check;").fetchall():
        raise VaultError("inconsistent references between the tables")
    store = vault.metadata
    entries = store.entries()
    if store.unreadable():
        raise VaultError(f"{len(store.unreadable())} unreadable entry(ies)")
    if len(entries) != report.entries:
        raise VaultError("different number of entries")
    store.categories()  # CategoryDecryptionError if a name is unreadable
    service = EntryService(vault)
    versions = 0
    for entry_id in entries:
        service.get_entry(entry_id, include_deleted=True)  # secrets decrypted
        versions += len(service.list_history(entry_id))  # versions decrypted
    if versions != report.history_versions:
        raise VaultError("different number of history versions")
    backup.verify_backup(report.backup_path, vault._require_unlocked_key())
    warnings = []
    if not report.vacuumed:
        try:  # old pages: new attempt at rewriting the file
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.execute("VACUUM;")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            report.vacuumed = True
        except sqlite3.Error:
            get_logger().error("VACUUM after upgrade failed twice: %s", vault.vault_id)
            warnings.append("The final compaction of the file failed (disk space?): "
                            "old unencrypted data may remain in its free pages. "
                            "The vault is usable and verified.")
    return warnings


def _open_verified(vault_id: str, master_password: str,
                   report: MigrationReport) -> UpgradeResult:
    """NORMAL opening of the migrated vault, then full verification."""
    try:
        vault = Vault.unlock(vault_id, master_password)
    except VaultError as exc:
        raise UpgradeVerificationError(
            f"The upgrade was applied but the vault does not open ({exc}). "
            f"The backup {report.backup_path.name} is kept.",
            report.backup_path) from exc
    try:
        warnings = verify_upgraded(vault, report)
    except Exception as exc:
        vault.close()
        get_logger().error("Upgrade verification failed: %s (%s)", vault_id,
                           type(exc).__name__)
        raise UpgradeVerificationError(
            "The upgrade was applied but its verification failed; the vault "
            f"was not opened. The backup {report.backup_path.name} (original "
            "format) is kept to restore it.", report.backup_path) from exc
    return UpgradeResult(vault, report, warnings=warnings)


# --- Entry points -----------------------------------------------------------------------


def upgrade(vault_id: str, master_password: str, backup_dir: Path,
            _fault: Callable[[str], None] | None = None) -> UpgradeResult:
    """Master password -> preflight -> migration -> verification -> v4 vault open.

    Raises WrongMasterPasswordError, VaultCorruptedError, UpgradeRefusedError,
    MigrationError (vault intact in these four cases) or UpgradeVerificationError.
    `_fault`: reserved for tests (passed on to the engine).
    """
    vault = Vault.open_for_migration(vault_id, master_password)
    try:
        _refuse_if_unexpected(vault)
        copies = tuple(legacy_plaintext_copies(vault))
        report = migrate_to_v4(vault, backup_dir, _fault=_fault)
    finally:
        vault.close()
    result = _open_verified(vault_id, master_password, report)
    result.legacy_plaintext_copies = copies
    get_logger().info("Vault upgraded and verified: %s", vault_id)
    return result


def recover_and_upgrade(vault_id: str, recovery_key: str, new_master_password: str,
                        backup_dir: Path, _fault: Callable[[str], None] | None = None,
                        ) -> tuple[UpgradeResult, str]:
    """v1 to v3 vault, forgotten password: recovery -> migration -> verification.

    The preflight happens BEFORE the recovery: a vault that cannot be upgraded is
    not modified at all. The recovery comes before the migration so that the
    migration backup opens with the NEW password.
    Returns (result, new recovery key).
    """
    check = inspect(vault_id)
    if not check.needs_upgrade:
        raise UpgradeRefusedError("This vault is already in the current format.")
    if check.problems:
        raise UpgradeRefusedError(_refusal_message(check.problems))
    vault, new_key = Vault.recover(vault_id, recovery_key, new_master_password,
                                   allow_legacy=True)
    try:
        _refuse_if_unexpected(vault)
        report = migrate_to_v4(vault, backup_dir, _fault=_fault)
    except Exception as exc:
        get_logger().error("Recovered vault not upgraded: %s (%s)", vault_id,
                           type(exc).__name__)
        raise RecoveredNotUpgradedError(
            "The new master password is saved, but the upgrade failed"
            f" ({exc}). The vault was not modified otherwise. Write down the new recovery "
            "key, then unlock the vault with the new password to "
            "try again.", new_key) from exc
    finally:
        vault.close()
    try:
        result = _open_verified(vault_id, new_master_password, report)
    except UpgradeVerificationError as exc:
        exc.new_recovery_key = new_key
        raise
    result.legacy_plaintext_copies = check.legacy_plaintext_copies
    return result, new_key
