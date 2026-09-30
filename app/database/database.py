"""SQLite connection and schema of a vault.

Each vault = one independent SQLite file
(~/.local/share/mon-coffre/vaults/<vault_id>/vault.db).

Choice: a "clean" SQLite access layer using `sqlite3` (standard library)
rather than an ORM, to limit external dependencies and keep explicit control
over the queries that touch sensitive data. The architecture
(repositories.py) isolates this choice: migrating to SQLAlchemy later would
be possible without changing the rest of the application.

Columns holding sensitive data (passwords, notes, card numbers, etc.) are
always encrypted BLOBs (AES-256-GCM), never plaintext. Since schema v4, the
entry metadata (tags included) and the names of custom categories are
encrypted too (`metadata_enc`, `name_enc`); `entry_tags` only exists in v1 to
v3 vaults, read by the migration. What stays readable by design: the
`vault_meta` parameters (including the vault name), the technical keys of the
built-in categories and `entry_history.created_at` (decision D3: order and
cap of the history). This layer knows no encryption key: it stores opaque
bytes.

Note: the SQL statements below (including their `--` comments and the
trigger message) are stored verbatim in `sqlite_master` of every vault they
create, so they are kept exactly as they were written.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 4

# Schema version history:
#   1 — Phase 1: vault_meta, categories, entries, entry_tags.
#   2 — Phase 4: entries.password_changed_at, entry_history table.
#   3 — v1.2: vault_recovery table (optional recovery key).
#   4 — v1.7: encrypted metadata (see v4_tables_sql and app/services/migration_v4).

# DEK wrapped a second time, by the recovery key (Argon2id then
# AES-256-GCM). Missing row = no recovery key. The key itself is never
# stored.
_RECOVERY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vault_recovery (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),  -- ligne unique
    kdf_params_json     TEXT NOT NULL,
    kdf_salt            BLOB NOT NULL,
    wrapped_key_blob    BLOB NOT NULL,             -- DEK chiffrée par la clé de récupération
    created_at          TEXT NOT NULL
);
"""

# The v1 to v3 schema (plaintext metadata, entry_tags table) is never created anymore:
# it is only READ by the migration (_REQUIRED_STRUCTURE, apply_legacy_steps). Reference:
# commit a99f821 (v1.6.0) and the real vaults in tests/fixtures.


def connect(db_path: Path) -> sqlite3.Connection:
    """Opens an SQLite connection with the usual security/reliability pragmas."""
    # check_same_thread=False: unlocking (Argon2id, ~0.5 s) runs in a worker
    # thread to keep the interface responsive; the connection is then handed
    # over to the main thread. It is never used by two threads at the same
    # time (sequential hand-over), which SQLite allows.
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # First real access to the file: a file that is not an SQLite database
        # fails here (sqlite3.connect opens nothing until something is read).
        conn.execute("PRAGMA journal_mode = WAL;")
        # Freed pages (deleted entry, modified field) are overwritten with zeros
        # instead of remaining readable in the file.
        conn.execute("PRAGMA secure_delete = ON;")
    except BaseException:
        conn.close()  # no connection left open for the garbage collector
        raise
    conn.row_factory = sqlite3.Row
    return conn


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Schema of a NEW vault: v4 directly (no plaintext metadata)."""
    with conn:
        for sql in v4_tables_sql().values():
            conn.execute(sql)
        conn.execute(_RECOVERY_TABLE_SQL)
        for sql in V4_POST_REBUILD_SQL:
            conn.execute(sql)


# Required columns per table, and the schema version that introduced them.
_REQUIRED_STRUCTURE: dict[str, tuple[int, set[str]]] = {
    "vault_meta": (1, {"id", "schema_version", "format_version", "kdf_name", "kdf_params_json",
                       "kdf_salt", "wrapped_key_blob", "verifier_blob", "vault_name",
                       "created_at", "updated_at"}),
    "categories": (1, {"id", "name", "is_builtin", "created_at"}),
    "entries": (1, {"id", "entry_type", "category_id", "is_favorite", "is_deleted",
                    "deleted_at", "service_name", "url", "username", "email_enc",
                    "password_enc", "notes_enc", "extra_fields_enc", "created_at",
                    "updated_at", "last_used_at"}),
    "entry_tags": (1, {"entry_id", "tag"}),
    "entry_history": (2, {"id", "entry_id", "snapshot_enc", "created_at"}),
    "vault_recovery": (3, {"id", "kdf_params_json", "kdf_salt", "wrapped_key_blob",
                           "created_at"}),
}
_REQUIRED_ENTRY_COLUMNS_V2 = {"password_changed_at"}

# Indexes present in v1 to v3 vaults, and the version that introduced them (taken from
# the real vaults produced by 1.0.0 and 1.6.0, tests/fixtures). The
# "sqlite_autoindex_*" indexes are created by SQLite for UNIQUE / PRIMARY KEY constraints.
LEGACY_INDEXES: dict[str, tuple[int, str]] = {
    "idx_entries_service_name": (1, "entries"),
    "idx_entries_is_deleted": (1, "entries"),
    "idx_entries_category": (1, "entries"),
    "sqlite_autoindex_categories_1": (1, "categories"),
    "sqlite_autoindex_entry_tags_1": (1, "entry_tags"),
    "idx_entry_history_entry": (2, "entry_history"),
}


def legacy_structure(schema_version: int) -> dict[str, set[str]]:
    """EXACT columns of each table of a v1 to v3 vault (source: _REQUIRED_STRUCTURE)."""
    return {
        table: columns | (_REQUIRED_ENTRY_COLUMNS_V2
                          if table == "entries" and schema_version >= 2 else set())
        for table, (since, columns) in _REQUIRED_STRUCTURE.items() if schema_version >= since
    }


def v4_reference_structure() -> tuple[set[tuple[str, str, str]], dict[str, set[str]]]:
    """SQLite objects (type, name, table) and columns of a NEW v4 vault.

    Built in memory by initialize_schema: the reference is the creation code
    itself, never a second definition of the schema.
    """
    conn = sqlite3.connect(":memory:")
    try:
        initialize_schema(conn)
        objects = {tuple(row) for row in conn.execute(
            "SELECT type, name, tbl_name FROM sqlite_master;")}
        columns = {name: _columns(conn, name) for kind, name, _ in objects if kind == "table"}
    finally:
        conn.close()
    return objects, columns

# --- Final v4 schema (encrypted metadata; see app/core/metadata.py) ---------------
#
# Created directly for a new vault (initialize_schema), or written by the v3 -> v4
# migration (table rebuild); also used by the structure check.
V4_SCHEMA_VERSION = 4

_V4_REQUIRED: dict[str, set[str]] = {
    "vault_meta": _REQUIRED_STRUCTURE["vault_meta"][1] | {"vault_uuid"},
    "entries": {"id", "metadata_enc", "email_enc", "password_enc", "notes_enc",
                "extra_fields_enc"},
    "categories": {"id", "builtin_key", "name_enc"},
    "entry_history": _REQUIRED_STRUCTURE["entry_history"][1],
    "vault_recovery": _REQUIRED_STRUCTURE["vault_recovery"][1],
}
# Plaintext v3 columns that must NO LONGER exist in a v4 vault.
_V4_FORBIDDEN: dict[str, set[str]] = {
    "entries": {"service_name", "url", "username", "entry_type", "category_id",
                "is_favorite", "is_deleted", "deleted_at", "created_at", "updated_at",
                "last_used_at", "password_changed_at"},
    "categories": {"name", "is_builtin", "created_at"},
}


def v4_tables_sql(suffix: str = "") -> dict[str, str]:
    """CREATE TABLE statements of the final v4 schema (`suffix`: rebuild tables).

    No plaintext metadata anymore: everything is in metadata_enc / name_enc.
    Secrets are unchanged (same columns, same encryption under the DEK).
    """
    from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS  # dependency-free module

    keys = ", ".join(f"'{key}'" for key in BUILTIN_CATEGORY_KEYS)

    def blob(column: str) -> str:
        return f"{column} BLOB NOT NULL CHECK (typeof({column}) = 'blob')"

    return {
        "vault_meta": f"""
            CREATE TABLE vault_meta{suffix} (
                id                  INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version      INTEGER NOT NULL,
                format_version      INTEGER NOT NULL,
                kdf_name            TEXT NOT NULL,
                kdf_params_json     TEXT NOT NULL,
                kdf_salt            BLOB NOT NULL,
                wrapped_key_blob    BLOB NOT NULL,
                verifier_blob       BLOB NOT NULL,
                vault_uuid          BLOB NOT NULL
                                    CHECK (typeof(vault_uuid) = 'blob' AND length(vault_uuid) = 16),
                vault_name          TEXT NOT NULL,   -- public : écran de verrouillage
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            );""",
        "entries": f"""
            CREATE TABLE entries{suffix} (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                {blob("metadata_enc")},
                {blob("email_enc")},
                {blob("password_enc")},
                {blob("notes_enc")},
                {blob("extra_fields_enc")}
            );""",
        "categories": f"""
            CREATE TABLE categories{suffix} (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                builtin_key         TEXT UNIQUE CHECK (builtin_key IN ({keys})),
                name_enc            BLOB CHECK (name_enc IS NULL OR typeof(name_enc) = 'blob'),
                CHECK ((builtin_key IS NULL) <> (name_enc IS NULL))
            );""",
        "entry_history": f"""
            CREATE TABLE entry_history{suffix} (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id            INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                {blob("snapshot_enc")},
                created_at          TEXT NOT NULL    -- en clair (D3) : ordre et plafond
            );""",
    }


V4_POST_REBUILD_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_entry_history_entry ON entry_history(entry_id);",
    """CREATE TRIGGER IF NOT EXISTS trg_vault_uuid_immutable
       BEFORE UPDATE OF vault_uuid ON vault_meta
       WHEN NEW.vault_uuid IS NULL OR NEW.vault_uuid != OLD.vault_uuid
       BEGIN SELECT RAISE(ABORT, 'vault_uuid est immuable'); END;""",
)


def structure_problems(conn: sqlite3.Connection, schema_version: int) -> list[str]:
    """Differences between the database and schema `schema_version` (empty list: sound structure).

    Checks the required tables and columns, then `PRAGMA quick_check` (page and
    index consistency, read-only). A vault with a deleted or truncated table
    must not pass as unlocked.
    """
    problems = []
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table';")}
    if schema_version >= V4_SCHEMA_VERSION:
        required = {table: columns for table, columns in _V4_REQUIRED.items()}
    else:
        required = legacy_structure(schema_version)
    for table, expected in required.items():
        if table not in tables:
            problems.append(f"table {table} missing")
            continue
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}
        if expected - present:
            problems.append(f"columns missing in {table}")
        if schema_version >= V4_SCHEMA_VERSION and present & _V4_FORBIDDEN.get(table, set()):
            # A plaintext v3 column in a v4 vault: metadata potentially exposed.
            problems.append(f"plaintext v3 columns present in {table}")
    if schema_version >= V4_SCHEMA_VERSION and "entry_tags" in tables:
        problems.append("entry_tags table (v3) present")
    check = [row[0] for row in conn.execute("PRAGMA quick_check;")]
    if check != ["ok"]:
        problems.append("SQLite integrity check failed")
    return problems


# --- v4 schema structures (additions only) -------------------------------------------
#
# v4 encrypts the metadata (see app/core/metadata.py). These additions prepare the
# v3 -> v4 migration: NULLABLE columns during the transition (a v3 vault has no value
# yet), old columns intact. They are applied ONLY by the migration, never when a
# vault is opened. The final constraints (NOT NULL, removal of the plaintext
# columns) come with the final rebuild of the tables, after the migrated data
# has been validated.

_V4_COLUMNS: tuple[tuple[str, str, str], ...] = (
    # Stable vault identity (16 bytes), used in the metadata AAD.
    ("vault_meta", "vault_uuid",
     "BLOB CHECK (vault_uuid IS NULL"
     " OR (typeof(vault_uuid) = 'blob' AND length(vault_uuid) = 16))"),
    # Encrypted entry metadata (name, URL, username, type, category, tags…).
    ("entries", "metadata_enc",
     "BLOB CHECK (metadata_enc IS NULL OR typeof(metadata_enc) = 'blob')"),
    # Technical key of a built-in category (generic, identical in every vault).
    ("categories", "builtin_key",
     "TEXT CHECK (builtin_key IS NULL OR builtin_key IN ({keys}))"),
    # Encrypted name of a custom category.
    ("categories", "name_enc",
     "BLOB CHECK (name_enc IS NULL OR typeof(name_enc) = 'blob')"),
)

_V4_EXTRA_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_builtin_key ON categories(builtin_key);",
    # vault_uuid is immutable once set (rename, password change, restore…).
    """CREATE TRIGGER IF NOT EXISTS trg_vault_uuid_immutable
       BEFORE UPDATE OF vault_uuid ON vault_meta
       WHEN OLD.vault_uuid IS NOT NULL AND (NEW.vault_uuid IS NULL
                                             OR NEW.vault_uuid != OLD.vault_uuid)
       BEGIN SELECT RAISE(ABORT, 'vault_uuid est immuable'); END;""",
)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}


def has_v4_structures(conn: sqlite3.Connection) -> bool:
    return all(column in _columns(conn, table) for table, column, _ in _V4_COLUMNS)


def add_v4_structures(conn: sqlite3.Connection) -> None:
    """Adds the v4 columns, index and trigger, without removing or committing anything.

    Idempotent. Reserved for the v3 -> v4 migration (which delimits the
    transaction): never called when a vault is opened, and generates no value.
    """
    from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS  # dependency-free module

    keys = ", ".join(f"'{key}'" for key in BUILTIN_CATEGORY_KEYS)
    for table, column, definition in _V4_COLUMNS:
        if column not in _columns(conn, table):
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition.format(keys=keys)};")
    for statement in _V4_EXTRA_SQL:
        conn.execute(statement)


def vault_meta_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT 1 FROM vault_meta WHERE id = 1;").fetchone()
    return row is not None


def apply_legacy_steps(conn: sqlite3.Connection, from_version: int) -> None:
    """v1/v2 -> v3 structures, WITHOUT a transaction or a schema_version change.

    Reused by `migrate` (v3) and by the v4 migration, which includes it in its
    own transaction. No encrypted data is touched.
    """
    if from_version < 2:
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(entries);")}
        if "password_changed_at" not in columns:
            conn.execute("ALTER TABLE entries ADD COLUMN password_changed_at TEXT;")
        # Real date unknown: the last modification is used (the most recent
        # possible value, so that no password is wrongly reported as old).
        conn.execute(
            "UPDATE entries SET password_changed_at = updated_at "
            "WHERE password_changed_at IS NULL;"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entry_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id        INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                snapshot_enc    BLOB,
                created_at      TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entry_history_entry ON entry_history(entry_id);"
        )
    if from_version < 3:
        conn.execute(_RECOVERY_TABLE_SQL)
