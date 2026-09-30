"""Migration d'un coffre v1/v2/v3 vers le schéma v4 (métadonnées chiffrées).

Moteur autonome, appelé par app.services.vault_upgrade (préflight strict des
structures, confirmation explicite dans l'interface, vérification complète
après migration) ; il n'est jamais déclenché automatiquement.

Déroulement (tout ou rien) :

1. Avant toute modification : sauvegarde CHIFFRÉE `.mcfbak` (type « migration »),
   vérifiée par déchiffrement complet. Jamais de copie `.bak` en clair ; les
   anciennes copies `vault.db.avant-schema-v*.bak` (en clair) sont seulement
   signalées, jamais utilisées ni supprimées.
2. Une seule transaction (BEGIN IMMEDIATE ... COMMIT) :
   a. étapes structurelles v1/v2 -> v3 si besoin (réutilisées telles quelles) ;
   b. structures v4 ajoutées, `vault_uuid` généré ;
   c. catégories : clé technique (intégrées) ou nom chiffré (personnelles) ;
   d. tags hérités de `entry_tags` ;
   e. entrées : JSON de métadonnées chiffré, écrit, RELU, déchiffré et comparé
      champ par champ à la source v3 ; secrets vérifiés (déchiffrables) ;
   f. historique : chaque version déchiffrée et validée (format v1) ;
   g. validation globale : résumés de recherche (donc toutes les recherches et
      tous les filtres), catégories et compteurs identiques avant/après ;
   h. reconstruction des tables SANS les colonnes en clair ni `entry_tags`,
      compteurs AUTOINCREMENT conservés, puis revalidation complète
      (structure, foreign_key_check, intégrité, octets des secrets inchangés) ;
   i. `schema_version = 4` en DERNIER.
   Toute erreur : ROLLBACK — le coffre reste un coffre v1/v2/v3 intact.
3. Après COMMIT : checkpoint du WAL, VACUUM (réécriture du fichier sans les
   anciennes pages), nouveau checkpoint.

`PRAGMA foreign_keys` : désactivé juste avant BEGIN et réactivé dans un finally.
C'est la procédure de reconstruction de tables documentée par SQLite (« Making
other kinds of table schema changes ») : avec les clés étrangères actives,
DROP TABLE entries déclencherait le ON DELETE CASCADE et SUPPRIMERAIT tout
l'historique. L'intégrité référentielle est vérifiée par PRAGMA
foreign_key_check avant validation : un seul écart annule la migration.
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
from app.core.builtin_categories import builtin_key_for_v3_row, builtin_name
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
    """La migration a échoué ; le coffre n'a pas été modifié (retour arrière complet)."""


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
    """Contenu v4 déchiffré (en mémoire) : métadonnées et noms de catégories."""

    entries: dict[int, EntryMetadata] = field(default_factory=dict)
    categories: dict[int, tuple[str, bool]] = field(default_factory=dict)  # id -> (nom, intégrée)


def legacy_plaintext_copies(vault: Vault) -> list[Path]:
    """Anciennes copies en clair laissées par les migrations v1.x (à signaler seulement)."""
    return sorted(Path(vault._db_path).parent.glob("vault.db.avant-schema-v*.bak"))


# --- Lecture du contenu v4 ----------------------------------------------------------------


def load_v4_view(conn: sqlite3.Connection, cipher: MetadataCipher) -> V4View:
    """Déchiffre toutes les métadonnées et catégories (structures v4 requises)."""
    view = V4View()
    for entry_id, blob in EntryRepository(conn).list_metadata_blobs():
        view.entries[entry_id] = cipher.decrypt_entry(entry_id, blob)
    for row in conn.execute("SELECT id, builtin_key, name_enc FROM categories ORDER BY id;"):
        if row[1] is not None:
            view.categories[row[0]] = (builtin_name(row[1]), True)
        else:
            view.categories[row[0]] = (cipher.decrypt_category(row[0], row[2]).name, False)
    return view


def summaries_v4(view: V4View, flt: EntryFilter | None = None) -> list[EntrySummary]:
    """Mêmes résumés, filtres et tri que EntryService.list_entries, à partir du v4."""
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
    """Migre un coffre DÉVERROUILLÉ (v1 à v3) vers v4. Tout ou rien.

    `_fault` : réservé aux tests (injection d'une erreur à une étape donnée).
    Lève MigrationError (le coffre est alors intact) ; la sauvegarde chiffrée de
    migration, créée avant toute modification, est conservée dans tous les cas.
    """
    started = time.monotonic()
    step = _fault or (lambda _name: None)
    logger = get_logger()
    dek = vault._require_unlocked_key()
    conn = vault.connection
    meta = VaultMetaRepository(conn).get()
    if meta is None or not 1 <= meta.schema_version < database.V4_SCHEMA_VERSION:
        raise MigrationError("Ce coffre ne peut pas être migré vers le format v4.")
    report = MigrationReport(meta.schema_version, Path(), legacy_plaintext_copies(vault))
    if report.legacy_plaintext_copies:
        logger.warning("Legacy plaintext copies next to vault %s: %d (not used, not deleted)",
                       vault.vault_id, len(report.legacy_plaintext_copies))

    # 1. Sauvegarde chiffrée, vérifiée, AVANT toute modification.
    try:
        report.backup_path = backup.create_backup(vault, directory=backup_dir,
                                                  kind=backup.KIND_MIGRATION)
        backup.verify_backup(report.backup_path, dek)
    except (VaultError, OSError, sqlite3.Error) as exc:
        logger.error("Migration backup failed, vault untouched: %s (%s)", vault.vault_id,
                     type(exc).__name__)
        raise MigrationError("Sauvegarde préalable impossible : le coffre n'a pas été "
                             "modifié.") from exc

    # 2. Transaction unique.
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF;")
    try:
        if conn.execute("PRAGMA foreign_keys;").fetchone()[0] != 0:
            raise MigrationError("Impossible de préparer la reconstruction des tables.")
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
    except Exception as exc:  # toute erreur annule la migration (cause chaînée)
        logger.error("Vault migration to v4 failed, rolled back: %s (%s)",
                     vault.vault_id, type(exc).__name__)
        raise MigrationError(
            "La migration vers le format v4 a échoué ; le coffre n'a pas été modifié.") from exc
    finally:
        conn.execute("PRAGMA foreign_keys = ON;")

    # 3. Anciennes pages : hors du fichier (le WAL et les pages libres ne gardent rien).
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.execute("VACUUM;")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        report.vacuumed = True
    except sqlite3.Error as exc:  # migration déjà validée : on le signale, sans l'annuler
        logger.error("VACUUM after migration failed: %s (%s)", vault.vault_id,
                     type(exc).__name__)
    report.seconds = time.monotonic() - started
    logger.info("Vault migrated to v4: %s (%d entries, %d categories, %d versions, %.1fs)",
                vault.vault_id, report.entries, report.categories, report.history_versions,
                report.seconds)
    return report


def _fail(message: str) -> MigrationError:
    return MigrationError(f"Migration impossible : {message}")


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

    # État v3 de référence, lu dans les colonnes v3 AVANT toute écriture de métadonnées.
    entries_repo, categories_repo = EntryRepository(conn), CategoryRepository(conn)
    records = sorted(entries_repo.list_active() + entries_repo.list_deleted(),
                     key=lambda r: r.id)
    old_active, old_trash, old_categories = _v3_reference(conn, records)

    # c. Catégories.
    category_ids = set()
    for category in categories_repo.list_all_v4():
        category_ids.add(category.id)
        try:
            key = builtin_key_for_v3_row(category.name, category.is_builtin)
        except ValueError as exc:
            raise _fail("catégorie intégrée inconnue.") from exc
        if key is not None:
            if not categories_repo.set_builtin_key(category.id, key):
                raise _fail("catégorie intégrée non enregistrée.")
        else:
            source = CategoryMetadata(name=category.name, created_at=category.created_at)
            if not categories_repo.set_name_blob(
                    category.id, cipher.encrypt_category(category.id, source)):
                raise _fail("catégorie personnelle non enregistrée.")
        step("category")
    for category in categories_repo.list_all_v4():  # relecture
        if category.builtin_key is not None:
            if builtin_name(category.builtin_key) != category.name:
                raise _fail("catégorie intégrée relue différente.")
        elif cipher.decrypt_category(category.id, category.name_enc) != CategoryMetadata(
                category.name, category.created_at):
            raise _fail("catégorie personnelle relue différente.")
    report.categories = len(category_ids)

    # d. Tags hérités (table entry_tags, jamais alimentée par l'application jusqu'ici).
    entry_ids = {r.id for r in records}
    raw_tags: dict[int, list[str]] = {}
    for entry_id, tag in conn.execute("SELECT entry_id, tag FROM entry_tags ORDER BY rowid;"):
        if entry_id not in entry_ids:
            raise _fail("tag rattaché à une entrée inexistante.")
        raw_tags.setdefault(entry_id, []).append(tag)
    tags: dict[int, tuple[str, ...]] = {}
    for entry_id, values in raw_tags.items():
        try:
            tags[entry_id] = normalize_tags(values)
        except EntryValidationError as exc:
            raise _fail(f"tags invalides pour l'entrée {entry_id}.") from exc
    report.tags = sum(len(t) for t in tags.values())
    step("tags")

    # e. Entrées : chiffrement, relecture, comparaison champ par champ.
    expected: dict[int, EntryMetadata] = {}
    secrets_sha: dict[int, tuple[str, ...]] = {}
    for record in records:
        if record.category_id is not None and record.category_id not in category_ids:
            raise _fail(f"catégorie introuvable pour l'entrée {record.id}.")
        if record.is_deleted != (record.deleted_at is not None):
            raise _fail(f"état de corbeille incohérent pour l'entrée {record.id}.")
        source = EntryMetadata(
            name=record.service_name, url=record.url or "", username=record.username or "",
            entry_type=record.entry_type, category_id=record.category_id,
            is_favorite=record.is_favorite, tags=tags.get(record.id, ()),
            created_at=record.created_at, updated_at=record.updated_at,
            # Même repli que la lecture v3 (EntryService.get_entry).
            password_changed_at=record.password_changed_at or record.updated_at,
            deleted_at=record.deleted_at if record.is_deleted else None,
        )
        try:
            blob = cipher.encrypt_entry(record.id, source)
        except EntryValidationError as exc:
            raise _fail(f"métadonnées invalides pour l'entrée {record.id}.") from exc
        if not entries_repo.set_metadata_blob(record.id, blob):
            raise _fail(f"entrée {record.id} non enregistrée.")
        reread = cipher.decrypt_entry(record.id, entries_repo.get_metadata_blob(record.id))
        if reread != source or (reread.name, reread.url, reread.username, reread.entry_type,
                                reread.category_id, reread.is_favorite) != (
                record.service_name, record.url or "", record.username or "",
                record.entry_type, record.category_id, record.is_favorite):
            raise _fail(f"métadonnées relues différentes pour l'entrée {record.id}.")
        expected[record.id] = source
        blobs = (record.email_enc, record.password_enc, record.notes_enc,
                 record.extra_fields_enc)
        for column, secret in zip(_SECRET_COLUMNS, blobs, strict=True):
            if secret is None:
                raise _fail(f"champ secret absent pour l'entrée {record.id}.")
            try:
                crypto.decrypt_field(dek, secret,
                                     f"mon-coffre-fort:entry:{record.id}:{column}".encode())
            except (ValueError, crypto.AuthenticationFailed) as exc:
                raise _fail(f"champ secret illisible pour l'entrée {record.id}.") from exc
        secrets_sha[record.id] = tuple(_sha(b) for b in blobs)
        step("entry")
    report.entries = len(records)

    # f. Historique (format v1 conservé tel quel, seulement vérifié).
    history_sha: dict[int, tuple[int, str, str]] = {}
    for hid, entry_id, snapshot, created_at in conn.execute(
            "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history ORDER BY id;"):
        if entry_id not in entry_ids or snapshot is None:
            raise _fail(f"version d'historique {hid} orpheline ou vide.")
        try:
            parse_snapshot(json.loads(crypto.decrypt_field(
                dek, snapshot, f"mon-coffre-fort:history:{entry_id}:{hid}".encode())))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise _fail(f"version d'historique {hid} illisible.") from exc
        history_sha[hid] = (entry_id, _sha(snapshot), created_at)
        step("history")
    report.history_versions = len(history_sha)

    # g. Validation globale avant reconstruction.
    view = load_v4_view(conn, cipher)
    _check_view(view, expected, old_active, old_trash, old_categories)
    step("validation")

    # h. Reconstruction des tables sans aucune colonne en clair.
    _rebuild(conn, step)
    view = load_v4_view(conn, cipher)
    _check_view(view, expected, old_active, old_trash, old_categories)
    for record_id, *blobs in conn.execute(
            "SELECT id, email_enc, password_enc, notes_enc, extra_fields_enc FROM entries;"):
        if tuple(_sha(b) for b in blobs) != secrets_sha.get(record_id):
            raise _fail("champs secrets modifiés par la reconstruction.")
    rebuilt_history = {hid: (entry_id, _sha(snapshot), created_at)
                       for hid, entry_id, snapshot, created_at in conn.execute(
                           "SELECT id, entry_id, snapshot_enc, created_at FROM entry_history;")}
    if rebuilt_history != history_sha:
        raise _fail("historique modifié par la reconstruction.")
    problems = database.structure_problems(conn, database.V4_SCHEMA_VERSION)
    if problems:
        raise _fail("structure v4 invalide (" + "; ".join(problems) + ").")
    if conn.execute("PRAGMA foreign_key_check;").fetchall():
        raise _fail("références incohérentes entre les tables.")
    if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
        raise _fail("contrôle d'intégrité SQLite en échec.")
    step("before_version")

    # i. Le numéro de schéma, en dernier.
    conn.execute("UPDATE vault_meta SET schema_version = ? WHERE id = 1;",
                 (database.V4_SCHEMA_VERSION,))
    if VaultMetaRepository(conn).get().schema_version != database.V4_SCHEMA_VERSION:
        raise _fail("numéro de schéma non enregistré.")
    step("before_commit")


def _v3_reference(conn: sqlite3.Connection, records: list) -> tuple[
        list[EntrySummary], list[EntrySummary], list[tuple]]:
    """Résumés (actifs, corbeille) et catégories tels que la version 1.6 les calculait
    (EntryService.list_entries / CategoryService.list_categories v3), à partir des
    seules colonnes v3 : la migration ne dépend pas des services, qui sont v4."""
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
    """Le contenu v4 déchiffré correspond exactement à l'état v3 de référence."""
    if view.entries != expected:
        raise _fail("métadonnées différentes de la source.")
    # Résumés identiques (mêmes champs, même ordre) => recherches et filtres identiques.
    if summaries_v4(view) != old_active:
        raise _fail("liste des entrées différente.")
    if summaries_v4(view, EntryFilter(in_trash=True)) != old_trash:
        raise _fail("corbeille différente.")
    counts: dict[int, int] = {}
    for meta in view.entries.values():
        if meta.deleted_at is None and meta.category_id is not None:
            counts[meta.category_id] = counts.get(meta.category_id, 0) + 1
    new_categories = sorted((cid, name, builtin, counts.get(cid, 0))
                            for cid, (name, builtin) in view.categories.items())
    if new_categories != old_categories:
        raise _fail("catégories différentes.")
    if UNCATEGORIZED in view.categories:
        raise _fail("identifiant de catégorie réservé.")


def _rebuild(conn: sqlite3.Connection, step: Callable[[str], None]) -> None:
    """Tables v4 définitives, copiées depuis les tables validées (clés étrangères désactivées)."""
    sequences = {name: seq for name, seq in conn.execute(
        "SELECT name, seq FROM sqlite_sequence;")}
    tables_sql = database.v4_tables_sql(suffix="_v4")
    for table in _REBUILT_TABLES:
        conn.execute(tables_sql[table])
        columns = _COPY_SQL[table]  # noms de tables et de colonnes : constantes du module
        sql = f"INSERT INTO {table}_v4 ({columns}) SELECT {columns} FROM {table};"  # noqa: S608
        conn.execute(sql)
    step("rebuild")
    conn.execute("DROP TABLE entry_tags;")
    for table in _REBUILT_TABLES:
        conn.execute(f"DROP TABLE {table};")
        conn.execute(f"ALTER TABLE {table}_v4 RENAME TO {table};")
    for statement in database.V4_POST_REBUILD_SQL:
        conn.execute(statement)
    # AUTOINCREMENT : un identifiant supprimé ne doit jamais être réattribué (AAD).
    for table in ("categories", "entries", "entry_history"):
        if table in sequences:
            conn.execute("DELETE FROM sqlite_sequence WHERE name = ?;", (table,))
            conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?);",
                         (table, sequences[table]))
    step("rebuilt")
