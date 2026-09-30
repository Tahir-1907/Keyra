"""Migration of a v1/v2/v3 vault to schema v4 (encrypted metadata).

Standalone engine, called by app.services.vault_upgrade (strict structure
preflight, explicit confirmation in the interface, full verification after
the migration); it is never triggered automatically.

Sequence (all or nothing):

1. Before any modification: ENCRYPTED `.mcfbak` backup ("migration" kind),
   verified by full decryption. Never a plaintext `.bak` copy; the old
   plaintext copies `vault.db.avant-schema-v*.bak` are only reported, never
   used or deleted.
2. A single transaction (BEGIN IMMEDIATE ... COMMIT):
   a. v1/v2 -> v3 structural steps if needed (reused as they are);
   b. v4 structures added, `vault_uuid` generated;
   c. categories: technical key (built-in) or encrypted name (custom);
   d. tags inherited from `entry_tags`;
   e. entries: encrypted metadata JSON, written, READ BACK, decrypted and
      compared field by field with the v3 source; secrets checked (decryptable);
   f. history: every version decrypted and validated (format v1);
   g. global validation: search summaries (hence every search and every
      filter), categories and counters identical before/after;
   h. rebuild of the tables WITHOUT the plaintext columns or `entry_tags`,
      AUTOINCREMENT counters kept, then full re-validation (structure,
      foreign_key_check, integrity, secret bytes unchanged);
   i. `schema_version = 4` LAST.
   Any error: ROLLBACK — the vault remains an intact v1/v2/v3 vault.
3. After COMMIT: WAL checkpoint, VACUUM (the file is rewritten without the
   old pages), another checkpoint.

`PRAGMA foreign_keys`: disabled just before BEGIN and re-enabled in a finally.
This is the table rebuild procedure documented by SQLite ("Making other kinds
of table schema changes"): with foreign keys enabled, DROP TABLE entries
would trigger the ON DELETE CASCADE and DELETE the whole history. Referential
integrity is checked with PRAGMA foreign_key_check before validation: a
single discrepancy cancels the migration.

The v4 view built here (`load_v4_view`) names built-in categories with their
LEGACY French names, because it is compared with the plaintext v3 state; it
is used by the migration and its tests only, never displayed.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.core import crypto
from app.core.builtin_categories import builtin_key_for_v3_row, legacy_builtin_name
from app.core.entries import (
    UNCATEGORIZED,
    EntryFilter,
    EntrySummary,
    normalize_for_search,
    summary_matches,
)
from app.core.exceptions import EntryValidationError, VaultError
from app.core.metadata import (
    CategoryMetadata,
    EntryMetadata,
    MetadataCipher,
    new_vault_uuid,
    normalize_tags,
)
from app.core.snapshots import parse_snapshot
from app.core.vault import Vault
from app.database import database
from app.database.repositories import (
    CategoryRepository,
    EntryRepository,
    VaultMetaRepository,
)
from app.services import backup
from app.utils.logging import get_logger

_SECRET_COLUMNS = ("email", "password", "notes", "extra")
_REBUILT_TABLES = ("vault_meta", "categories", "entries", "entry_history")
_COPY_SQL = {
    "vault_meta": "id, schema_version, format_version, kdf_name, kdf_params_json, kdf_salt, "
                  "wrapped_key_blob, verifier_blob, vault_uuid, vault_name, created_at, "
                  "updated_at",
    "categories": "id, builtin_key, name_enc",
    "entries": "id, metadata_enc, email_enc, password_enc, notes_enc, extra_fields_enc",
    "entry_history": "id, entry_id, snapshot_enc, created_at",
}


class MigrationError(VaultError):
    """The migration failed; the vault was not modified (full rollback)."""


@dataclass(slots=True)
class MigrationReport:
    from_version: int
    backup_path: Path
    legacy_plaintext_copies: list[Path]
    entries: int = 0
    categories: int = 0
    tags: int = 0
    history_versions: int = 0
    vacuumed: bool = False
    seconds: float = 0.0


@dataclass(slots=True)
class V4View:
    """Decrypted v4 content (in memory): metadata and category names."""

    entries: dict[int, EntryMetadata] = field(default_factory=dict)
    categories: dict[int, tuple[str, bool]] = field(default_factory=dict)  # id -> (name, built-in)


def legacy_plaintext_copies(vault: Vault) -> list[Path]:
    """Old plaintext copies left by the v1.x migrations (to be reported only)."""
    return sorted(Path(vault._db_path).parent.glob("vault.db.avant-schema-v*.bak"))


# --- Reading the v4 content ----------------------------------------------------------------


def load_v4_view(conn: sqlite3.Connection, cipher: MetadataCipher) -> V4View:
    """Decrypts all metadata and categories (v4 structures required).

    Built-in categories get their legacy (v1.x) name, to match the v3 reference.
    """
    view = V4View()
    for entry_id, blob in EntryRepository(conn).list_metadata_blobs():
        view.entries[entry_id] = cipher.decrypt_entry(entry_id, blob)
    for row in conn.execute("SELECT id, builtin_key, name_enc FROM categories ORDER BY id;"):
        if row[1] is not None:
            view.categories[row[0]] = (legacy_builtin_name(row[1]), True)
        else:
            view.categories[row[0]] = (cipher.decrypt_category(row[0], row[2]).name, False)
    return view


def summaries_v4(view: V4View, flt: EntryFilter | None = None) -> list[EntrySummary]:
    """Same summaries, filters and sorting as EntryService.list_entries, from the v4 content."""
    flt = flt or EntryFilter()
    result = []
    for entry_id, meta in view.entries.items():
        if (meta.deleted_at is not None) != flt.in_trash:
            continue
        category = view.categories.get(meta.category_id) if meta.category_id else None
        summary = EntrySummary(
            id=entry_id, entry_type=meta.entry_type, service_name=meta.name,
            username=meta.username, url=meta.url, category_id=meta.category_id,
            category_name=category[0] if category else "", is_favorite=meta.is_favorite,
            updated_at=meta.updated_at, deleted_at=meta.deleted_at or "",
        )
        if summary_matches(summary, flt):
            result.append(summary)
    if flt.in_trash:
        result.sort(key=lambda s: (s.deleted_at, s.id), reverse=True)
    else:
        result.sort(key=lambda s: (normalize_for_search(s.service_name), s.id))
    return result


# --- Migration ---------------------------------------------------------------------------


def migrate_to_v4(vault: Vault, backup_dir: Path,
                  _fault: Callable[[str], None] | None = None) -> MigrationReport:
    """Migrates an UNLOCKED vault (v1 to v3) to v4. All or nothing.

    `_fault`: reserved for tests (injects an error at a given step).
    Raises MigrationError (the vault is then intact); the encrypted migration
    backup, created before any modification, is kept in every case.
    """
    started = time.monotonic()
    step = _fault or (lambda _name: None)
    logger = get_logger()
    dek = vault._require_unlocked_key()
    conn = vault.connection
    meta = VaultMetaRepository(conn).get()
    if meta is None or not 1 <= meta.schema_version < database.V4_SCHEMA_VERSION:
        raise MigrationError("This vault cannot be migrated to the v4 format.")
    report = MigrationReport(meta.schema_version, Path(), legacy_plaintext_copies(vault))
    if report.legacy_plaintext_copies:
        logger.warning("Legacy plaintext copies next to vault %s: %d (not used, not deleted)",
                       vault.vault_id, len(report.legacy_plaintext_copies))

    # 1. Encrypted, verified backup, BEFORE any modification.
    try:
        report.backup_path = backup.create_backup(vault, directory=backup_dir,
                                                  kind=backup.KIND_MIGRATION)
        backup.verify_backup(report.backup_path, dek)
    except (VaultError, OSError, sqlite3.Error) as exc:
        logger.error("Migration backup failed, vault untouched: %s (%s)", vault.vault_id,
                     type(exc).__name__)
        raise MigrationError("Preliminary backup impossible: the vault has not been "
                             "modified.") from exc

    # 2. Single transaction.
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF;")
    try:
        if conn.execute("PRAGMA foreign_keys;").fetchone()[0] != 0:
            raise MigrationError("Cannot prepare the table rebuild.")
        conn.execute("BEGIN IMMEDIATE;")
        try:
            _migrate(vault, conn, dek, meta.schema_version, step, report)
            conn.execute("COMMIT;")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise
    except MigrationError:
        logger.error("Vault migration to v4 failed, rolled back: %s", vault.vault_id)
        raise
    except Exception as exc:  # any error cancels the migration (chained cause)
        logger.error("Vault migration to v4 failed, rolled back: %s (%s)",
                     vault.vault_id, type(exc).__name__)
        raise MigrationError(
            "The migration to the v4 format failed; the vault has not been modified.") from exc
    finally:
        conn.execute("PRAGMA foreign_keys = ON;")

    # 3. Old pages: out of the file (the WAL and free pages keep nothing).
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.execute("VACUUM;")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        report.vacuumed = True
    except sqlite3.Error as exc:  # migration already committed: report it, without cancelling it
        logger.error("VACUUM after migration failed: %s (%s)", vault.vault_id,
                     type(exc).__name__)
    report.seconds = time.monotonic() - started
    logger.info("Vault migrated to v4: %s (%d entries, %d categories, %d versions, %.1fs)",
                vault.vault_id, report.entries, report.categories, report.history_versions,
                report.seconds)
    return report


def _fail(message: str) -> MigrationError:
    return MigrationError(f"Migration impossible: {message}")


def _sha(blob: bytes | None) -> str:
    return hashlib.sha256(blob or b"").hexdigest()


def _migrate(vault: Vault, conn: sqlite3.Connection, dek: bytes, from_version: int,
             step: Callable[[str], None], report: MigrationReport) -> None:
    step("start")
    if from_version < 3:
        database.apply_legacy_steps(conn, from_version)
    database.add_v4_structures(conn)
    step("structures")
    VaultMetaRepository(conn).set_vault_uuid(new_vault_uuid())
    cipher = MetadataCipher(dek, VaultMetaRepository(conn).get().vault_uuid)

    # Reference v3 state, read from the v3 columns BEFORE any metadata is written.
    entries_repo, categories_repo = EntryRepository(conn), CategoryRepository(conn)
    records = sorted(entries_repo.list_active() + entries_repo.list_deleted(),
                     key=lambda r: r.id)
    old_active, old_trash, old_categories = _v3_reference(conn, records)

    # c. Categories.
    category_ids = set()
    for category in categories_repo.list_all_v4():
        category_ids.add(category.id)
        try:
            key = builtin_key_for_v3_row(category.name, category.is_builtin)
        except ValueError as exc:
            raise _fail("unknown built-in category.") from exc
        if key is not None:
            if not categories_repo.set_builtin_key(category.id, key):
                raise _fail("built-in category not saved.")
        else:
            source = CategoryMetadata(name=category.name, created_at=category.created_at)
            if not categories_repo.set_name_blob(
                    category.id, cipher.encrypt_category(category.id, source)):
                raise _fail("custom category not saved.")
        step("category")
    for category in categories_repo.list_all_v4():  # read back
        if category.builtin_key is not None:
            if legacy_builtin_name(category.builtin_key) != category.name:
                raise _fail("built-in category read back differently.")
        elif cipher.decrypt_category(category.id, category.name_enc) != CategoryMetadata(
                category.name, category.created_at):
            raise _fail("custom category read back differently.")
    report.categories = len(category_ids)

    # d. Inherited tags (entry_tags table, never filled by the application so far).
    entry_ids = {r.id for r in records}
    raw_tags: dict[int, list[str]] = {}
    for entry_id, tag in conn.execute("SELECT entry_id, tag FROM entry_tags ORDER BY rowid;"):
        if entry_id not in entry_ids:
            raise _fail("tag attached to a non-existent entry.")
        raw_tags.setdefault(entry_id, []).append(tag)
    tags: dict[int, tuple[str, ...]] = {}
    for entry_id, values in raw_tags.items():
        try:
            tags[entry_id] = normalize_tags(values)
        except EntryValidationError as exc:
            raise _fail(f"invalid tags for entry {entry_id}.") from exc
    report.tags = sum(len(t) for t in tags.values())
    step("tags")

    # e. Entries: encryption, read-back, field-by-field comparison.
    expected: dict[int, EntryMetadata] = {}
    secrets_sha: dict[int, tuple[str, ...]] = {}
    for record in records:
        if record.category_id is not None and record.category_id not in category_ids:
            raise _fail(f"category not found for entry {record.id}.")
        if record.is_deleted != (record.deleted_at is not None):
            raise _fail(f"inconsistent Trash state for entry {record.id}.")
        source = EntryMetadata(
            name=record.service_name, url=record.url or "", username=record.username or "",
            entry_type=record.entry_type, category_id=record.category_id,
            is_favorite=record.is_favorite, tags=tags.get(record.id, ()),
            created_at=record.created_at, updated_at=record.updated_at,
            # Same fallback as the v3 read (EntryService.get_entry).
            password_changed_at=record.password_changed_at or record.updated_at,
            deleted_at=record.deleted_at if record.is_deleted else None,
        )
        try:
            blob = cipher.encrypt_entry(record.id, source)
        except EntryValidationError as exc:
            raise _fail(f"invalid metadata for entry {record.id}.") from exc
        if not entries_repo.set_metadata_blob(record.id, blob):
            raise _fail(f"entry {record.id} not saved.")
        reread = cipher.decrypt_entry(record.id, entries_repo.get_metadata_blob(record.id))
        if reread != source or (reread.name, reread.url, reread.username, reread.entry_type,
                                reread.category_id, reread.is_favorite) != (
                record.service_name, record.url or "", record.username or "",
                record.entry_type, record.category_id, record.is_favorite):
            raise _fail(f"metadata read back differently for entry {record.id}.")
        expected[record.id] = source
        blobs = (record.email_enc, record.password_enc, record.notes_enc,
                 record.extra_fields_enc)
        for column, secret in zip(_SECRET_COLUMNS, blobs, strict=True):
            if secret is None:
                raise _fail(f"missing secret field for entry {record.id}.")
            try:
                crypto.decrypt_field(dek, secret,
                                     f"mon-coffre-fort:entry:{record.id}:{column}".encode())
            except (ValueError, crypto.AuthenticationFailed) as exc:
                raise _fail(f"unreadable secret field for entry {record.id}.") from exc
        secrets_sha[record.id] = tuple(_sha(b) for b in blobs)
        step("entry")
    report.entries = len(records)

    # f. History (format v1 kept as is, only checked).
    history_sha: dict[int, tuple[int, str, str]] = {}
    for hid, entry_id, snapshot, created_at in conn.execute(
            "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history ORDER BY id;"):
        if entry_id not in entry_ids or snapshot is None:
            raise _fail(f"history version {hid} orphaned or empty.")
        try:
            parse_snapshot(json.loads(crypto.decrypt_field(
                dek, snapshot, f"mon-coffre-fort:history:{entry_id}:{hid}".encode())))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise _fail(f"history version {hid} unreadable.") from exc
        history_sha[hid] = (entry_id, _sha(snapshot), created_at)
        step("history")
    report.history_versions = len(history_sha)

    # g. Global validation before the rebuild.
    view = load_v4_view(conn, cipher)
    _check_view(view, expected, old_active, old_trash, old_categories)
    step("validation")

    # h. Rebuild of the tables without any plaintext column.
    _rebuild(conn, step)
    view = load_v4_view(conn, cipher)
    _check_view(view, expected, old_active, old_trash, old_categories)
    for record_id, *blobs in conn.execute(
            "SELECT id, email_enc, password_enc, notes_enc, extra_fields_enc FROM entries;"):
        if tuple(_sha(b) for b in blobs) != secrets_sha.get(record_id):
            raise _fail("secret fields changed by the rebuild.")
    rebuilt_history = {hid: (entry_id, _sha(snapshot), created_at)
                       for hid, entry_id, snapshot, created_at in conn.execute(
                           "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history;")}
    if rebuilt_history != history_sha:
        raise _fail("history changed by the rebuild.")
    problems = database.structure_problems(conn, database.V4_SCHEMA_VERSION)
    if problems:
        raise _fail("invalid v4 structure (" + "; ".join(problems) + ").")
    if conn.execute("PRAGMA foreign_key_check;").fetchall():
        raise _fail("inconsistent references between the tables.")
    if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
        raise _fail("SQLite integrity check failed.")
    step("before_version")

    # i. The schema number, last.
    conn.execute("UPDATE vault_meta SET schema_version = ? WHERE id = 1;",
                 (database.V4_SCHEMA_VERSION,))
    if VaultMetaRepository(conn).get().schema_version != database.V4_SCHEMA_VERSION:
        raise _fail("schema number not saved.")
    step("before_commit")


def _v3_reference(conn: sqlite3.Connection, records: list) -> tuple[
        list[EntrySummary], list[EntrySummary], list[tuple]]:
    """Summaries (active, Trash) and categories as version 1.6 computed them
    (v3 EntryService.list_entries / CategoryService.list_categories), from the v3
    columns alone: the migration does not depend on the services, which are v4."""
    categories = CategoryRepository(conn).list_all()
    names = {c.id: c.name for c in categories}
    summaries = [
        EntrySummary(
            id=r.id, entry_type=r.entry_type, service_name=r.service_name,
            username=r.username or "", url=r.url or "", category_id=r.category_id,
            category_name=names.get(r.category_id, "") if r.category_id else "",
            is_favorite=r.is_favorite, updated_at=r.updated_at, deleted_at=r.deleted_at or "",
        )
        for r in records
    ]
    active = sorted((s for s, r in zip(summaries, records, strict=True) if not r.is_deleted),
                    key=lambda s: (normalize_for_search(s.service_name), s.id))
    trash = sorted((s for s, r in zip(summaries, records, strict=True) if r.is_deleted),
                   key=lambda s: (s.deleted_at, s.id), reverse=True)
    counts = CategoryRepository(conn).count_entries_by_category()
    return active, trash, sorted((c.id, c.name, c.is_builtin, counts.get(c.id, 0))
                                 for c in categories)


def _check_view(view: V4View, expected: dict[int, EntryMetadata],
                old_active: list[EntrySummary], old_trash: list[EntrySummary],
                old_categories: list[tuple]) -> None:
    """The decrypted v4 content matches the reference v3 state exactly."""
    if view.entries != expected:
        raise _fail("metadata differs from the source.")
    # Identical summaries (same fields, same order) => identical searches and filters.
    if summaries_v4(view) != old_active:
        raise _fail("entry list differs.")
    if summaries_v4(view, EntryFilter(in_trash=True)) != old_trash:
        raise _fail("Trash differs.")
    counts: dict[int, int] = {}
    for meta in view.entries.values():
        if meta.deleted_at is None and meta.category_id is not None:
            counts[meta.category_id] = counts.get(meta.category_id, 0) + 1
    new_categories = sorted((cid, name, builtin, counts.get(cid, 0))
                            for cid, (name, builtin) in view.categories.items())
    if new_categories != old_categories:
        raise _fail("categories differ.")
    if UNCATEGORIZED in view.categories:
        raise _fail("reserved category identifier.")


def _rebuild(conn: sqlite3.Connection, step: Callable[[str], None]) -> None:
    """Final v4 tables, copied from the validated tables (foreign keys disabled)."""
    sequences = {name: seq for name, seq in conn.execute(
        "SELECT name, seq FROM sqlite_sequence;")}
    tables_sql = database.v4_tables_sql(suffix="_v4")
    for table in _REBUILT_TABLES:
        conn.execute(tables_sql[table])
        columns = _COPY_SQL[table]  # table and column names: module constants
        sql = f"INSERT INTO {table}_v4 ({columns}) SELECT {columns} FROM {table};"  # noqa: S608
        conn.execute(sql)
    step("rebuild")
    conn.execute("DROP TABLE entry_tags;")
    for table in _REBUILT_TABLES:
        conn.execute(f"DROP TABLE {table};")
        conn.execute(f"ALTER TABLE {table}_v4 RENAME TO {table};")
    for statement in database.V4_POST_REBUILD_SQL:
        conn.execute(statement)
    # AUTOINCREMENT: a deleted identifier must never be reassigned (AAD).
    for table in ("categories", "entries", "entry_history"):
        if table in sequences:
            conn.execute("DELETE FROM sqlite_sequence WHERE name = ?;", (table,))
            conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?);",
                         (table, sequences[table]))
    step("rebuilt")
