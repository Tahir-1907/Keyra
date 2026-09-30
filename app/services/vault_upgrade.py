"""Mise à niveau d'un coffre v1/v2/v3 vers v4 : préflight, migration, vérification.

Orchestration autour du moteur app.services.migration_v4 (tout ou rien), qui
n'est pas modifié :

1. `inspect` (lecture seule, sans mot de passe) : version du schéma, anciennes
   copies `.bak` en clair (signalées, jamais supprimées) et préflight STRICT.
2. Préflight : toute structure SQLite inattendue (table, vue, déclencheur, index,
   colonne) REFUSE la mise à niveau, coffre intact. Rien d'inconnu n'est ignoré
   ni supprimé : le moteur reconstruit les tables connues et laisserait une table
   inconnue telle quelle (contenu éventuellement en clair) ou effacerait en
   silence une colonne inconnue. Référence : les définitions de
   app.database.database (legacy_structure, LEGACY_INDEXES), pas une copie.
3. `migrate_to_v4` : sauvegarde chiffrée vérifiée, transaction unique, VACUUM.
4. Vérification complète APRÈS migration, par une ouverture normale (Vault.unlock) :
   structure v4 exacte, intégrité SQLite, toutes les métadonnées, catégories,
   secrets et versions d'historique relus, sauvegarde de migration revérifiée.
   La session v4 ne s'ouvre qu'ensuite.

Ce module ne décide jamais seul : l'interface demande une confirmation
explicite avant d'appeler `upgrade` ou `recover_and_upgrade`.
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
    """Mise à niveau refusée AVANT toute modification (structure inattendue, format)."""


class UpgradeVerificationError(VaultError):
    """La migration a été validée mais la vérification finale a échoué.

    Le coffre est au format v4 et n'a pas été ouvert ; la sauvegarde de migration
    (format d'origine, restaurable par la 1.6) est conservée.
    """

    def __init__(self, message: str, backup_path: Path | None = None) -> None:
        super().__init__(message)
        self.backup_path = backup_path
        self.new_recovery_key = ""  # renseignée dans le chemin « récupération »


class RecoveredNotUpgradedError(VaultError):
    """Récupération réussie (nouveau mot de passe, NOUVELLE clé) mais migration échouée.

    Le coffre est resté à son format d'origine, intact, avec le nouveau mot de passe
    maître et la nouvelle clé de récupération (l'ancienne ne fonctionne plus) : la
    nouvelle clé DOIT être montrée à l'utilisateur. Nouvel essai : déverrouiller avec
    le nouveau mot de passe, la mise à niveau est proposée de nouveau.
    """

    def __init__(self, message: str, new_recovery_key: str) -> None:
        super().__init__(message)
        self.new_recovery_key = new_recovery_key


@dataclass(frozen=True, slots=True)
class UpgradeCheck:
    """État d'un coffre avant mise à niveau (lu sans mot de passe, sans modification)."""

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
    vault: Vault  # coffre v4 déverrouillé ET vérifié
    report: MigrationReport
    legacy_plaintext_copies: tuple[Path, ...] = ()
    warnings: list[str] = field(default_factory=list)


# --- Préflight ---------------------------------------------------------------------------


def unexpected_structures(conn: sqlite3.Connection, schema_version: int) -> list[str]:
    """Écarts STRICTS avec la structure attendue (liste vide : rien d'inattendu).

    v1 à v3 : tables et colonnes de legacy_structure, index de LEGACY_INDEXES, aucune
    vue ni aucun déclencheur. v4 : exactement un coffre neuf (v4_reference_structure).
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
    labels = {"table": "table inconnue", "view": "vue inconnue",
              "trigger": "déclencheur inconnu", "index": "index inattendu"}
    problems = []
    for kind, name, table in sorted(objects - expected_objects):
        problems.append(f"{labels.get(kind, kind + ' inconnu')} : {name}"
                        + (f" (sur {table})" if kind in ("index", "trigger") else ""))
    for kind, name, _table in sorted(expected_objects - objects):
        if kind in ("index", "trigger"):
            problems.append(f"{'index' if kind == 'index' else 'déclencheur'} absent : {name}")
    for table, expected in sorted(expected_columns.items()):
        if ("table", table, table) not in objects:
            continue
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}
        problems += [f"colonne inattendue : {table}.{c}" for c in sorted(present - expected)]
    # Tables manquantes, colonnes absentes et intégrité : contrôle déjà utilisé à l'ouverture.
    problems += database.structure_problems(conn, schema_version)
    return problems


def inspect(vault_id: str) -> UpgradeCheck:
    """Lecture seule (aucun verrou d'écriture, aucun fichier créé) ; sans mot de passe."""
    db_path = vault_path(vault_id) / _DB_FILENAME
    if not db_path.is_file():
        raise VaultNotFoundError(f"Le coffre « {vault_id} » est introuvable.")
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row  # attendu par les repositories
        try:
            meta = VaultMetaRepository(conn).get()
            if meta is None:
                raise VaultCorruptedError("Métadonnées du coffre absentes ou corrompues.")
            problems = (unexpected_structures(conn, meta.schema_version)
                        if meta.schema_version <= database.V4_SCHEMA_VERSION
                        else ["format plus récent que l'application"])
        finally:
            conn.close()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        raise VaultCorruptedError("Le fichier du coffre est illisible ou corrompu.") from exc
    copies = tuple(sorted(db_path.parent.glob("vault.db.avant-schema-v*.bak")))
    return UpgradeCheck(vault_id, meta.schema_version, tuple(problems), copies)


def _refusal_message(problems: list[str] | tuple[str, ...]) -> str:
    return ("Mise à niveau impossible : le fichier du coffre contient des éléments que Mon "
            "Coffre-Fort n'a pas créés (détail : " + "; ".join(problems[:5])
            + ("…" if len(problems) > 5 else "") + "). Le coffre n'a pas été modifié.")


def failure_details(exc: BaseException) -> list[str]:
    """Chemin et cause d'un échec, tirés de la chaîne d'exceptions (`__cause__`,
    `__context__`) : ce que le moteur de migration attache à « Sauvegarde préalable
    impossible », par exemple. Seuls des chemins et des messages d'erreur du système ou
    de l'application sont repris, jamais une donnée du coffre."""
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
                # Fichier jamais créé (temporaire d'écriture refusé) : son dossier est le
                # chemin utile à l'utilisateur.
                path = Path(current.filename)
                shown = path if path.exists() or not path.parent.exists() else path.parent
                details.append(f"Chemin : {shown}")
            return [*details, f"Cause : {current.strerror or type(current).__name__}"]
        if isinstance(current, VaultError):
            return [f"Cause : {current}"]
        pending += [current.__cause__, current.__context__]
    return []


def _refuse_if_unexpected(vault: Vault) -> None:
    meta = VaultMetaRepository(vault.connection).get()
    problems = unexpected_structures(vault.connection, meta.schema_version)
    if problems:
        get_logger().error("Upgrade refused, unexpected structure: %s (%d problems)",
                           vault.vault_id, len(problems))
        raise UpgradeRefusedError(_refusal_message(problems))


# --- Vérification après migration ------------------------------------------------------


def verify_upgraded(vault: Vault, report: MigrationReport) -> list[str]:
    """Relit TOUT le coffre migré ; lève une exception au moindre écart.

    Retourne des avertissements non bloquants (ex. VACUUM à refaire).
    """
    conn = vault.connection
    meta = VaultMetaRepository(conn).get()
    if meta.schema_version != database.V4_SCHEMA_VERSION or meta.vault_uuid is None:
        raise VaultError("format v4 non enregistré")
    problems = unexpected_structures(conn, database.V4_SCHEMA_VERSION)
    if problems:
        raise VaultError("structure v4 inattendue : " + "; ".join(problems))
    if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
        raise VaultError("contrôle d'intégrité SQLite en échec")
    if conn.execute("PRAGMA foreign_key_check;").fetchall():
        raise VaultError("références incohérentes entre les tables")
    store = vault.metadata
    entries = store.entries()
    if store.unreadable():
        raise VaultError(f"{len(store.unreadable())} entrée(s) illisible(s)")
    if len(entries) != report.entries:
        raise VaultError("nombre d'entrées différent")
    store.categories()  # CategoryDecryptionError si un nom est illisible
    service = EntryService(vault)
    versions = 0
    for entry_id in entries:
        service.get_entry(entry_id, include_deleted=True)  # secrets déchiffrés
        versions += len(service.list_history(entry_id))  # versions déchiffrées
    if versions != report.history_versions:
        raise VaultError("nombre de versions d'historique différent")
    backup.verify_backup(report.backup_path, vault._require_unlocked_key())
    warnings = []
    if not report.vacuumed:
        try:  # anciennes pages : nouvel essai de réécriture du fichier
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.execute("VACUUM;")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            report.vacuumed = True
        except sqlite3.Error:
            get_logger().error("VACUUM after upgrade failed twice: %s", vault.vault_id)
            warnings.append("Le compactage final du fichier a échoué (espace disque ?) : "
                            "d'anciennes données non chiffrées peuvent subsister dans ses "
                            "pages libres. Le coffre est utilisable et vérifié.")
    return warnings


def _open_verified(vault_id: str, master_password: str,
                   report: MigrationReport) -> UpgradeResult:
    """Ouverture NORMALE du coffre migré, puis vérification complète."""
    try:
        vault = Vault.unlock(vault_id, master_password)
    except VaultError as exc:
        raise UpgradeVerificationError(
            f"La mise à niveau a été appliquée mais le coffre ne s'ouvre pas ({exc}). "
            f"La sauvegarde {report.backup_path.name} est conservée.",
            report.backup_path) from exc
    try:
        warnings = verify_upgraded(vault, report)
    except Exception as exc:
        vault.close()
        get_logger().error("Upgrade verification failed: %s (%s)", vault_id,
                           type(exc).__name__)
        raise UpgradeVerificationError(
            "La mise à niveau a été appliquée mais sa vérification a échoué ; le coffre "
            f"n'a pas été ouvert. La sauvegarde {report.backup_path.name} (format "
            "d'origine) est conservée pour le restaurer.", report.backup_path) from exc
    return UpgradeResult(vault, report, warnings=warnings)


# --- Points d'entrée -----------------------------------------------------------------------


def upgrade(vault_id: str, master_password: str, backup_dir: Path,
            _fault: Callable[[str], None] | None = None) -> UpgradeResult:
    """Mot de passe maître -> préflight -> migration -> vérification -> coffre v4 ouvert.

    Lève WrongMasterPasswordError, VaultCorruptedError, UpgradeRefusedError,
    MigrationError (coffre intact dans ces quatre cas) ou UpgradeVerificationError.
    `_fault` : réservé aux tests (transmis au moteur).
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
    """Coffre v1 à v3, mot de passe oublié : récupération -> migration -> vérification.

    Le préflight a lieu AVANT la récupération : un coffre qui ne peut pas être mis à
    niveau n'est pas modifié du tout. La récupération précède la migration pour que
    la sauvegarde de migration s'ouvre avec le NOUVEAU mot de passe.
    Retourne (résultat, nouvelle clé de récupération).
    """
    check = inspect(vault_id)
    if not check.needs_upgrade:
        raise UpgradeRefusedError("Ce coffre est déjà au format actuel.")
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
            "Le nouveau mot de passe maître est enregistré, mais la mise à niveau a échoué"
            f" ({exc}). Le coffre n'a pas été modifié autrement. Notez la nouvelle clé de "
            "récupération, puis déverrouillez le coffre avec le nouveau mot de passe pour "
            "réessayer.", new_key) from exc
    finally:
        vault.close()
    try:
        result = _open_verified(vault_id, new_master_password, report)
    except UpgradeVerificationError as exc:
        exc.new_recovery_key = new_key
        raise
    result.legacy_plaintext_copies = check.legacy_plaintext_copies
    return result, new_key
