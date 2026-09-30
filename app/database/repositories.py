"""Couche d'accès aux données (pattern repository).

Isole le reste de l'application des requêtes SQL. Ne manipule que des
octets déjà chiffrés pour les champs sensibles : aucune clé, aucun mot de
passe en clair, ne transite ici.
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
    """CRUD sur la ligne unique de `vault_meta`."""

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
        # sqlite3.Row : « in row » teste les VALEURS ; seul keys() donne les colonnes.
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
            # Colonne v4 : absente d'un coffre v3 -> None (jamais générée ici).
            vault_uuid=row["vault_uuid"] if "vault_uuid" in columns else None,
        )

    def set_vault_uuid(self, vault_uuid: bytes) -> None:
        """v4 : fixe l'identité du coffre, UNE seule fois (migration ou création v4).

        Sans commit (l'appelant délimite la transaction). ValueError si l'identité est
        malformée ou déjà fixée : elle est immuable (le déclencheur SQL le garantit aussi).
        """
        if not isinstance(vault_uuid, bytes) or len(vault_uuid) != VAULT_UUID_SIZE:
            raise ValueError("Identité de coffre invalide.")
        cur = self._conn.execute(
            "UPDATE vault_meta SET vault_uuid = ? WHERE id = 1 AND vault_uuid IS NULL;",
            (vault_uuid,),
        )
        if cur.rowcount != 1:
            raise ValueError("L'identité du coffre est déjà fixée (immuable).")

    def update_wrapped_key(
        self, wrapped_key_blob: bytes, verifier_blob: bytes,
        kdf_salt: bytes, kdf_params: Argon2Params, updated_at: str, commit: bool = True,
    ) -> None:
        """Utilisé lors d'un changement de mot de passe maître (re-wrap de la DEK).

        `commit=False` : l'appelant l'inclut dans une transaction plus large.
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
    """Ligne unique de `vault_recovery` (absente = pas de clé de récupération).

    Comme `update_wrapped_key`, les écritures acceptent `commit=False` pour
    être regroupées avec la mise à jour de l'enveloppe du mot de passe.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self) -> RecoveryRecord | None:
        try:
            row = self._conn.execute("SELECT * FROM vault_recovery WHERE id = 1;").fetchone()
        except sqlite3.OperationalError as exc:  # coffre au schéma < 3 : pas encore de table
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


# --- Entrées -------------------------------------------------------------------
#
# Contrairement à VaultMetaRepository, les repositories ci-dessous ne
# committent pas eux-mêmes : c'est la couche cœur qui délimite les
# transactions (`with conn:`), car la création d'une entrée se fait en deux
# temps (insertion pour obtenir l'identifiant, puis écriture des champs
# chiffrés liés à cet identifiant) et doit rester atomique.

# Seules des constantes du code (colonnes, conditions fixes) sont interpolées dans
# les requêtes (d'où les « noqa: S608 ») ; les valeurs passent toujours par « ? ».
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
    """Accès à la table `entries` (entrées actives et corbeille)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # --- Legacy v1 à v3 : lecture des colonnes en clair, pour la migration UNIQUEMENT
    # (app.services.migration_v4). Le runtime v4 ne les appelle jamais.

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
        # L'historique suit (entry_history : ON DELETE CASCADE).
        cur = self._conn.execute("DELETE FROM entries WHERE id = ?;", (entry_id,))
        return cur.rowcount > 0

    # --- v4 : ligne = id + blobs chiffrés (métadonnées et secrets) -------------------

    def insert_v4_placeholder(self) -> int:
        """Réserve un identifiant (sans commit). Les blobs vides x'' sont invalides :
        l'appelant les remplace dans la même transaction (l'AAD dépend de l'id)."""
        cur = self._conn.execute(
            "INSERT INTO entries (metadata_enc, email_enc, password_enc, notes_enc, "
            "extra_fields_enc) VALUES (x'', x'', x'', x'', x'');")
        return int(cur.lastrowid)

    def get_secret_blobs(self, entry_id: int) -> tuple[bytes | None, ...] | None:
        """(email, password, notes, extra) chiffrés, ou None si l'entrée n'existe pas."""
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

    # --- v4 : métadonnées chiffrées (colonnes ajoutées par add_v4_structures) ------

    def list_metadata_blobs(self) -> list[tuple[int, bytes | None]]:
        """(id, metadata_enc) de TOUTES les entrées (actives et corbeille), par id."""
        rows = self._conn.execute("SELECT id, metadata_enc FROM entries ORDER BY id;").fetchall()
        return [(r["id"], r["metadata_enc"]) for r in rows]

    def get_metadata_blob(self, entry_id: int) -> bytes | None:
        """metadata_enc d'une entrée ; KeyError si l'entrée n'existe pas."""
        row = self._conn.execute(
            "SELECT metadata_enc FROM entries WHERE id = ?;", (entry_id,)).fetchone()
        if row is None:
            raise KeyError(entry_id)
        return row["metadata_enc"]

    def set_metadata_blob(self, entry_id: int, blob: bytes) -> bool:
        """Écrit metadata_enc (sans commit). Jamais NULL : absent = corruption en v4."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Métadonnées chiffrées attendues.")
        cur = self._conn.execute(
            "UPDATE entries SET metadata_enc = ? WHERE id = ?;", (blob, entry_id))
        return cur.rowcount == 1


# --- Historique ---------------------------------------------------------------------


class HistoryRepository:
    """Versions précédentes des entrées (contenu chiffré opaque)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert_placeholder(self, entry_id: int, created_at: str) -> int:
        # x'' : marque vide (snapshot_enc est NOT NULL en v4), remplacée dans la transaction.
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
        """Du plus récent au plus ancien."""
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
        """Dates des dernières versions, toutes entrées confondues (sans le contenu chiffré)."""
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


# --- Catégories ----------------------------------------------------------------


class CategoryRepository:
    """Accès à la table `categories` (aucune donnée sensible)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # --- Legacy v1 à v3 (list_all, list_all_v4, set_builtin_key, set_name_blob,
    # count_entries_by_category) : migration v3 -> v4 UNIQUEMENT.

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
        # v4 : aucune clé étrangère ; CategoryService retire d'abord la catégorie des
        # métadonnées chiffrées des entrées, dans la même transaction.
        self._conn.execute("DELETE FROM categories WHERE id = ?;", (category_id,))

    # --- v4 : clé des catégories intégrées, nom chiffré des personnelles -----------

    def list_all_v4(self) -> list[CategoryRecord]:
        """Comme list_all, avec builtin_key et name_enc (structures v4 requises)."""
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
        """Associe sa clé technique à une catégorie intégrée (sans commit)."""
        from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS

        if key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Clé de catégorie intégrée inconnue.")
        cur = self._conn.execute(
            "UPDATE categories SET builtin_key = ? WHERE id = ? AND is_builtin = 1;",
            (key, category_id))
        return cur.rowcount == 1

    def set_name_blob(self, category_id: int, blob: bytes) -> bool:
        """Écrit le nom chiffré d'une catégorie PERSONNELLE (sans commit)."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Nom chiffré attendu.")
        cur = self._conn.execute(
            "UPDATE categories SET name_enc = ? WHERE id = ? AND is_builtin = 0;",
            (blob, category_id))
        return cur.rowcount == 1

    # --- v4 définitif (tables reconstruites : id, builtin_key, name_enc) --------------

    def list_v4_rows(self) -> list[tuple[int, str | None, bytes | None]]:
        """(id, builtin_key, name_enc) de chaque catégorie d'un coffre v4, par id."""
        rows = self._conn.execute(
            "SELECT id, builtin_key, name_enc FROM categories ORDER BY id;").fetchall()
        return [(r["id"], r["builtin_key"], r["name_enc"]) for r in rows]

    def insert_v4_custom_placeholder(self) -> int:
        """Réserve l'id d'une catégorie personnelle (nom chiffré écrit ensuite, même txn)."""
        cur = self._conn.execute("INSERT INTO categories (name_enc) VALUES (x'');")
        return int(cur.lastrowid)

    def ensure_v4_builtin(self, key: str) -> None:
        """Crée la catégorie intégrée `key` si elle n'existe pas (sans commit)."""
        from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS

        if key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Clé de catégorie intégrée inconnue.")
        self._conn.execute("INSERT OR IGNORE INTO categories (builtin_key) VALUES (?);", (key,))

    def set_v4_name_blob(self, category_id: int, blob: bytes) -> bool:
        """Nom chiffré d'une catégorie PERSONNELLE d'un coffre v4 (sans commit)."""
        if not isinstance(blob, bytes) or not blob:
            raise ValueError("Nom chiffré attendu.")
        cur = self._conn.execute(
            "UPDATE categories SET name_enc = ? WHERE id = ? AND builtin_key IS NULL;",
            (blob, category_id))
        return cur.rowcount == 1

    def count_entries_by_category(self) -> dict[int | None, int]:
        """Entrées actives uniquement (la corbeille n'est pas comptée)."""
        rows = self._conn.execute(
            "SELECT category_id, COUNT(*) AS n FROM entries "
            "WHERE is_deleted = 0 GROUP BY category_id;"
        ).fetchall()
        return {r["category_id"]: r["n"] for r in rows}
