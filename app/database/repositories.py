"""Data access layer (repository pattern).

Isolates the rest of the application from the SQL queries. Only handles
bytes that are already encrypted for sensitive fields: no key and no
plaintext password ever passes through here.
"""

from __future__ import annotations

import json
import sqlite3

from app.core.crypto import Argon2Params
from app.database.models import (
    VAULT_UUID_SIZE,
    CategoryRecord,
    EntryRecord,
    HistoryRecord,
    RecoveryRecord,
    VaultMeta,
)


class VaultMetaRepository:
    """CRUD on the single row of `vault_meta`."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert(self, meta: VaultMeta) -> None:
        self._conn.execute(
            """
            INSERT INTO vault_meta (
                id, schema_version, format_version, kdf_name, kdf_params_json,
                kdf_salt, wrapped_key_blob, verifier_blob, vault_uuid, vault_name,
                created_at, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meta.schema_version,
                meta.format_version,
                meta.kdf_name,
                json.dumps(meta.kdf_params.to_dict()),
                meta.kdf_salt,
                meta.wrapped_key_blob,
                meta.verifier_blob,
                meta.vault_uuid,
                meta.vault_name,
                meta.created_at,
                meta.updated_at,
            ),
        )
        self._conn.commit()

    def get(self) -> VaultMeta | None:
        row = self._conn.execute(
            "SELECT * FROM vault_meta WHERE id = 1;"
        ).fetchone()
        if row is None:
            return None
        # sqlite3.Row: "in row" tests the VALUES; only keys() gives the columns.
        columns = row.keys()
        return VaultMeta(
            schema_version=row["schema_version"],
            format_version=row["format_version"],
            kdf_name=row["kdf_name"],
            kdf_params=Argon2Params.from_dict(json.loads(row["kdf_params_json"])),
            kdf_salt=row["kdf_salt"],
            wrapped_key_blob=row["wrapped_key_blob"],
            verifier_blob=row["verifier_blob"],
            vault_name=row["vault_name"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            # v4 column: missing from a v3 vault -> None (never generated here).
            vault_uuid=row["vault_uuid"] if "vault_uuid" in columns else None,
        )

    def set_vault_uuid(self, vault_uuid: bytes) -> None:
        """v4: sets the vault identity, ONCE only (migration or v4 creation).

        No commit (the caller delimits the transaction). ValueError if the identity
        is malformed or already set: it is immutable (the SQL trigger guarantees it too).
        """
        if not isinstance(vault_uuid, bytes) or len(vault_uuid) != VAULT_UUID_SIZE:
            raise ValueError("Invalid vault identity.")
        cur = self._conn.execute(
            "UPDATE vault_meta SET vault_uuid = ? WHERE id = 1 AND vault_uuid IS NULL;",
            (vault_uuid,),
        )
        if cur.rowcount != 1:
            raise ValueError("The vault identity is already set (immutable).")

    def update_wrapped_key(
        self, wrapped_key_blob: bytes, verifier_blob: bytes,
        kdf_salt: bytes, kdf_params: Argon2Params, updated_at: str, commit: bool = True,
    ) -> None:
        """Used when the master password changes (re-wrap of the DEK).

        `commit=False`: the caller includes it in a larger transaction.
        """
        self._conn.execute(
            """
            UPDATE vault_meta
            SET wrapped_key_blob = ?, verifier_blob = ?, kdf_salt = ?,
                kdf_params_json = ?, updated_at = ?
            WHERE id = 1;
            """,
            (
                wrapped_key_blob,
                verifier_blob,
                kdf_salt,
                json.dumps(kdf_params.to_dict()),
                updated_at,
            ),
        )
        if commit:
            self._conn.commit()

    def rename_vault(self, new_name: str, updated_at: str) -> None:
        self._conn.execute(
            "UPDATE vault_meta SET vault_name = ?, updated_at = ? WHERE id = 1;",
            (new_name, updated_at),
        )
        self._conn.commit()


class RecoveryRepository:
    """Single row of `vault_recovery` (missing = no recovery key).

    Like `update_wrapped_key`, writes accept `commit=False` so that they can be
    grouped with the update of the password envelope.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self) -> RecoveryRecord | None:
        try:
            row = self._conn.execute("SELECT * FROM vault_recovery WHERE id = 1;").fetchone()
        except sqlite3.OperationalError as exc:  # vault with schema < 3: no table yet
            if "no such table" in str(exc):
                return None
            raise
        if row is None:
            return None
        return RecoveryRecord(
            kdf_params=Argon2Params.from_dict(json.loads(row["kdf_params_json"])),
            kdf_salt=row["kdf_salt"],
            wrapped_key_blob=row["wrapped_key_blob"],
            created_at=row["created_at"],
        )

    def set(self, record: RecoveryRecord, commit: bool = True) -> None:
        self._conn.execute(
            """
            INSERT INTO vault_recovery (id, kdf_params_json, kdf_salt, wrapped_key_blob, created_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kdf_params_json = excluded.kdf_params_json, kdf_salt = excluded.kdf_salt,
                wrapped_key_blob = excluded.wrapped_key_blob, created_at = excluded.created_at;
            """,
            (json.dumps(record.kdf_params.to_dict()), record.kdf_salt,
             record.wrapped_key_blob, record.created_at),
        )
        if commit:
            self._conn.commit()

    def delete(self) -> None:
        self._conn.execute("DELETE FROM vault_recovery WHERE id = 1;")
        self._conn.commit()


# --- Entries -------------------------------------------------------------------
#
# Unlike VaultMetaRepository, the repositories below do not commit
# themselves: the core layer delimits the transactions (`with conn:`),
# because creating an entry takes two steps (insert to get the
# identifier, then write the encrypted fields bound to that identifier)
# and must remain atomic.

# Only code constants (columns, fixed conditions) are interpolated into the
# queries (hence the "noqa: S608"); values always go through "?".
_ENTRY_COLUMNS = (
    "id, entry_type, category_id, is_favorite, service_name, url, username, "
    "email_enc, password_enc, notes_enc, extra_fields_enc, "
    "created_at, updated_at, last_used_at, password_changed_at, is_deleted, deleted_at"
)


def _row_to_entry(row: sqlite3.Row) -> EntryRecord:
    return EntryRecord(
        id=row["id"],
        entry_type=row["entry_type"],
        category_id=row["category_id"],
        is_favorite=bool(row["is_favorite"]),
        service_name=row["service_name"] or "",
        url=row["url"],
        username=row["username"],
        email_enc=row["email_enc"],
        password_enc=row["password_enc"],
        notes_enc=row["notes_enc"],
        extra_fields_enc=row["extra_fields_enc"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_used_at=row["last_used_at"],
        password_changed_at=row["password_changed_at"],
        is_deleted=bool(row["is_deleted"]),
        deleted_at=row["deleted_at"],
    )


class EntryRepository:
    """Access to the `entries` table (active entries and Trash)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # --- Legacy v1 to v3: reading the plaintext columns, for the migration ONLY
    # (app.services.migration_v4). The v4 runtime never calls them.

    def list_active(self) -> list[EntryRecord]:
        rows = self._conn.execute(
            f"SELECT {_ENTRY_COLUMNS} FROM entries WHERE is_deleted = 0;"  # noqa: S608
        ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def list_deleted(self) -> list[EntryRecord]:
        rows = self._conn.execute(
            f"SELECT {_ENTRY_COLUMNS} FROM entries WHERE is_deleted = 1;"  # noqa: S608
        ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def delete_permanently(self, entry_id: int) -> bool:
        # The history follows (entry_history: ON DELETE CASCADE).
        cur = self._conn.execute("DELETE FROM entries WHERE id = ?;", (entry_id,))
        return cur.rowcount > 0

    # --- v4: row = id + encrypted blobs (metadata and secrets) -------------------

    def insert_v4_placeholder(self) -> int:
        """Reserves an identifier (no commit). The empty x'' blobs are invalid: the
        caller replaces them in the same transaction (the AAD depends on the id)."""
        cur = self._conn.execute(
            "INSERT INTO entries (metadata_enc, email_enc, password_enc, notes_enc, "
            "extra_fields_enc) VALUES (x'', x'', x'', x'', x'');")
        return int(cur.lastrowid)

    def get_secret_blobs(self, entry_id: int) -> tuple[bytes | None, ...] | None:
        """Encrypted (email, password, notes, extra), or None if the entry does not exist."""
        row = self._conn.execute(
            "SELECT email_enc, password_enc, notes_enc, extra_fields_enc FROM entries "
            "WHERE id = ?;", (entry_id,)).fetchone()
        return None if row is None else tuple(row)

    def set_secret_blobs(self, entry_id: int, email: bytes, password: bytes, notes: bytes,
                         extra: bytes) -> bool:
        cur = self._conn.execute(
            "UPDATE entries SET email_enc = ?, password_enc = ?, notes_enc = ?, "
            "extra_fields_enc = ? WHERE id = ?;", (email, password, notes, extra, entry_id))
        return cur.rowcount == 1

    # --- v4: encrypted metadata (columns added by add_v4_structures) ------

    def list_metadata_blobs(self) -> list[tuple[int, bytes | None]]:
        """(id, metadata_enc) of ALL entries (active and Trash), by id."""
        rows = self._conn.execute("SELECT id, metadata_enc FROM entries ORDER BY id;").fetchall()
        return [(r["id"], r["metadata_enc"]) for r in rows]

    def get_metadata_blob(self, entry_id: int) -> bytes | None:
        """metadata_enc of an entry; KeyError if the entry does not exist."""
        row = self._conn.execute(
            "SELECT metadata_enc FROM entries WHERE id = ?;", (entry_id,)).fetchone()
        if row is None:
            raise KeyError(entry_id)
        return row["metadata_enc"]

    def set_metadata_blob(self, entry_id: int, blob: bytes) -> bool:
        """Writes metadata_enc (no commit). Never NULL: missing = corruption in v4."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Encrypted metadata expected.")
        cur = self._conn.execute(
            "UPDATE entries SET metadata_enc = ? WHERE id = ?;", (blob, entry_id))
        return cur.rowcount == 1


# --- History ---------------------------------------------------------------------


class HistoryRepository:
    """Previous versions of the entries (opaque encrypted content)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert_placeholder(self, entry_id: int, created_at: str) -> int:
        # x'': empty marker (snapshot_enc is NOT NULL in v4), replaced within the transaction.
        cur = self._conn.execute(
            "INSERT INTO entry_history (entry_id, snapshot_enc, created_at) VALUES (?, x'', ?);",
            (entry_id, created_at),
        )
        return int(cur.lastrowid)

    def set_snapshot(self, history_id: int, snapshot_enc: bytes) -> None:
        self._conn.execute(
            "UPDATE entry_history SET snapshot_enc = ? WHERE id = ?;", (snapshot_enc, history_id)
        )

    def list_for_entry(self, entry_id: int) -> list[HistoryRecord]:
        """Most recent first."""
        rows = self._conn.execute(
            "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history "
            "WHERE entry_id = ? ORDER BY id DESC;",
            (entry_id,),
        ).fetchall()
        return [HistoryRecord(r["id"], r["entry_id"], r["snapshot_enc"], r["created_at"])
                for r in rows]

    def get(self, history_id: int) -> HistoryRecord | None:
        r = self._conn.execute(
            "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history WHERE id = ?;",
            (history_id,),
        ).fetchone()
        if r is None:
            return None
        return HistoryRecord(r["id"], r["entry_id"], r["snapshot_enc"], r["created_at"])

    def list_recent_meta(self, limit: int = 200) -> list[HistoryRecord]:
        """Dates of the latest versions, across all entries (without the encrypted content)."""
        rows = self._conn.execute(
            "SELECT id, entry_id, created_at FROM entry_history ORDER BY created_at DESC LIMIT ?;",
            (limit,),
        ).fetchall()
        return [HistoryRecord(r["id"], r["entry_id"], None, r["created_at"]) for r in rows]

    def count_for_entry(self, entry_id: int) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) FROM entry_history WHERE entry_id = ?;", (entry_id,)
        ).fetchone()[0])

    def delete_ids(self, ids: list[int]) -> None:
        self._conn.executemany("DELETE FROM entry_history WHERE id = ?;", [(i,) for i in ids])

    def delete_for_entry(self, entry_id: int) -> int:
        cur = self._conn.execute("DELETE FROM entry_history WHERE entry_id = ?;", (entry_id,))
        return cur.rowcount


# --- Categories ----------------------------------------------------------------


class CategoryRepository:
    """Access to the `categories` table (no sensitive data)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # --- Legacy v1 to v3 (list_all, list_all_v4, set_builtin_key, set_name_blob,
    # count_entries_by_category): v3 -> v4 migration ONLY.

    def list_all(self) -> list[CategoryRecord]:
        rows = self._conn.execute(
            "SELECT id, name, is_builtin, created_at FROM categories;"
        ).fetchall()
        return [
            CategoryRecord(
                id=r["id"], name=r["name"],
                is_builtin=bool(r["is_builtin"]), created_at=r["created_at"],
            )
            for r in rows
        ]

    def delete(self, category_id: int) -> None:
        # v4: no foreign key; CategoryService first removes the category from the
        # encrypted metadata of the entries, in the same transaction.
        self._conn.execute("DELETE FROM categories WHERE id = ?;", (category_id,))

    # --- v4: key of built-in categories, encrypted name of custom ones -----------

    def list_all_v4(self) -> list[CategoryRecord]:
        """Like list_all, with builtin_key and name_enc (v4 structures required)."""
        rows = self._conn.execute(
            "SELECT id, name, is_builtin, created_at, builtin_key, name_enc "
            "FROM categories ORDER BY id;"
        ).fetchall()
        return [
            CategoryRecord(
                id=r["id"], name=r["name"], is_builtin=bool(r["is_builtin"]),
                created_at=r["created_at"], builtin_key=r["builtin_key"],
                name_enc=r["name_enc"],
            )
            for r in rows
        ]

    def set_builtin_key(self, category_id: int, key: str) -> bool:
        """Assigns its technical key to a built-in category (no commit)."""
        from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS

        if key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Unknown built-in category key.")
        cur = self._conn.execute(
            "UPDATE categories SET builtin_key = ? WHERE id = ? AND is_builtin = 1;",
            (key, category_id))
        return cur.rowcount == 1

    def set_name_blob(self, category_id: int, blob: bytes) -> bool:
        """Writes the encrypted name of a CUSTOM category (no commit)."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Encrypted name expected.")
        cur = self._conn.execute(
            "UPDATE categories SET name_enc = ? WHERE id = ? AND is_builtin = 0;",
            (blob, category_id))
        return cur.rowcount == 1

    # --- final v4 (rebuilt tables: id, builtin_key, name_enc) --------------

    def list_v4_rows(self) -> list[tuple[int, str | None, bytes | None]]:
        """(id, builtin_key, name_enc) of each category of a v4 vault, by id."""
        rows = self._conn.execute(
            "SELECT id, builtin_key, name_enc FROM categories ORDER BY id;").fetchall()
        return [(r["id"], r["builtin_key"], r["name_enc"]) for r in rows]

    def insert_v4_custom_placeholder(self) -> int:
        """Reserves the id of a custom category (encrypted name written next, same txn)."""
        cur = self._conn.execute("INSERT INTO categories (name_enc) VALUES (x'');")
        return int(cur.lastrowid)

    def ensure_v4_builtin(self, key: str) -> None:
        """Creates the built-in category `key` if it does not exist (no commit)."""
        from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS

        if key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Unknown built-in category key.")
        self._conn.execute("INSERT OR IGNORE INTO categories (builtin_key) VALUES (?);", (key,))

    def set_v4_name_blob(self, category_id: int, blob: bytes) -> bool:
        """Encrypted name of a CUSTOM category of a v4 vault (no commit)."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Encrypted name expected.")
        cur = self._conn.execute(
            "UPDATE categories SET name_enc = ? WHERE id = ? AND builtin_key IS NULL;",
            (blob, category_id))
        return cur.rowcount == 1

    def count_entries_by_category(self) -> dict[int | None, int]:
        """Active entries only (the Trash is not counted)."""
        rows = self._conn.execute(
            "SELECT category_id, COUNT(*) AS n FROM entries "
            "WHERE is_deleted = 0 GROUP BY category_id;"
        ).fetchall()
        return {r["category_id"]: r["n"] for r in rows}
