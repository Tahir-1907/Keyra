"""Connexion SQLite et schéma d'un coffre.

Chaque coffre = un fichier SQLite indépendant
(~/.local/share/mon-coffre/vaults/<vault_id>/vault.db).

Choix : une couche d'accès SQLite « propre » en `sqlite3` (bibliothèque
standard) plutôt qu'un ORM, pour limiter les dépendances externes et garder
un contrôle explicite sur les requêtes touchant des données sensibles.
L'architecture (repositories.py) isole ce choix : il serait possible de
migrer vers SQLAlchemy plus tard sans changer le reste de l'application.

Les colonnes contenant des données sensibles (mots de passe, notes,
numéros de carte, etc.) sont toujours des BLOB
chiffrés (AES-256-GCM), jamais du texte en clair. Depuis le schéma v4, les
métadonnées des entrées (dont les tags) et les noms de catégories personnelles
le sont aussi (`metadata_enc`, `name_enc`) ; `entry_tags` n'existe plus que dans
les coffres v1 à v3, lus par la migration. Restent lisibles par conception : les
paramètres de `vault_meta` (dont le nom du coffre), les clés techniques des
catégories intégrées et `entry_history.created_at` (décision D3 : ordre et
plafond de l'historique). Cette couche ne connaît aucune clé de chiffrement :
elle stocke des octets opaques.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 4

# Historique des versions de schéma :
#   1 — Phase 1 : vault_meta, categories, entries, entry_tags.
#   2 — Phase 4 : entries.password_changed_at, table entry_history.
#   3 — v1.2 : table vault_recovery (clé de récupération, facultative).
#   4 — v1.7 : métadonnées chiffrées (voir v4_tables_sql et app/services/migration_v4).

# DEK enveloppée une seconde fois, par la clé de récupération (Argon2id puis
# AES-256-GCM). Ligne absente = pas de clé de récupération. La clé elle-même
# n'est jamais stockée.
_RECOVERY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vault_recovery (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),  -- ligne unique
    kdf_params_json     TEXT NOT NULL,
    kdf_salt            BLOB NOT NULL,
    wrapped_key_blob    BLOB NOT NULL,             -- DEK chiffrée par la clé de récupération
    created_at          TEXT NOT NULL
);
"""

# Le schéma v1 à v3 (métadonnées en clair, table entry_tags) n'est plus jamais créé :
# il n'est que LU par la migration (_REQUIRED_STRUCTURE, apply_legacy_steps). Référence :
# commit a99f821 (v1.6.0) et les coffres réels de tests/fixtures.


def connect(db_path: Path) -> sqlite3.Connection:
    """Ouvre une connexion SQLite avec les pragmas de sécurité/fiabilité usuels."""
    # check_same_thread=False : le déverrouillage (Argon2id, ~0,5 s) s'exécute
    # dans un fil de travail pour garder l'interface animée ; la connexion est
    # ensuite remise au fil principal. Elle n'est jamais utilisée par deux fils
    # en même temps (relais séquentiel), ce que SQLite autorise.
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        # Premier accès réel au fichier : un fichier qui n'est pas une base
        # SQLite échoue ici (sqlite3.connect n'ouvre rien tant qu'on ne lit pas).
        conn.execute("PRAGMA journal_mode = WAL;")
        # Les pages libérées (entrée supprimée, champ modifié) sont écrasées par
        # des zéros au lieu de rester lisibles dans le fichier.
        conn.execute("PRAGMA secure_delete = ON;")
    except BaseException:
        conn.close()  # pas de connexion laissée ouverte au ramasse-miettes
        raise
    conn.row_factory = sqlite3.Row
    return conn


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Schéma d'un NOUVEAU coffre : directement v4 (aucune métadonnée en clair)."""
    with conn:
        for sql in v4_tables_sql().values():
            conn.execute(sql)
        conn.execute(_RECOVERY_TABLE_SQL)
        for sql in V4_POST_REBUILD_SQL:
            conn.execute(sql)


# Colonnes indispensables par table, et version du schéma qui les a introduites.
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

# Index présents dans les coffres v1 à v3, et version qui les a introduits (relevés dans
# les coffres réels produits par 1.0.0 et 1.6.0, tests/fixtures). Les index
# « sqlite_autoindex_* » sont créés par SQLite pour les contraintes UNIQUE / PRIMARY KEY.
LEGACY_INDEXES: dict[str, tuple[int, str]] = {
    "idx_entries_service_name": (1, "entries"),
    "idx_entries_is_deleted": (1, "entries"),
    "idx_entries_category": (1, "entries"),
    "sqlite_autoindex_categories_1": (1, "categories"),
    "sqlite_autoindex_entry_tags_1": (1, "entry_tags"),
    "idx_entry_history_entry": (2, "entry_history"),
}


def legacy_structure(schema_version: int) -> dict[str, set[str]]:
    """Colonnes EXACTES de chaque table d'un coffre v1 à v3 (source : _REQUIRED_STRUCTURE)."""
    return {
        table: columns | (_REQUIRED_ENTRY_COLUMNS_V2
                          if table == "entries" and schema_version >= 2 else set())
        for table, (since, columns) in _REQUIRED_STRUCTURE.items() if schema_version >= since
    }


def v4_reference_structure() -> tuple[set[tuple[str, str, str]], dict[str, set[str]]]:
    """Objets SQLite (type, nom, table) et colonnes d'un coffre v4 NEUF.

    Construit en mémoire par initialize_schema : la référence est le code de création
    lui-même, jamais une seconde définition du schéma.
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

# --- Schéma v4 définitif (métadonnées chiffrées ; voir app/core/metadata.py) ---------------
#
# Créé directement pour un nouveau coffre (initialize_schema), ou écrit par la migration
# v3 -> v4 (reconstruction des tables) ; utilisé aussi par la vérification de structure.
V4_SCHEMA_VERSION = 4

_V4_REQUIRED: dict[str, set[str]] = {
    "vault_meta": _REQUIRED_STRUCTURE["vault_meta"][1] | {"vault_uuid"},
    "entries": {"id", "metadata_enc", "email_enc", "password_enc", "notes_enc",
                "extra_fields_enc"},
    "categories": {"id", "builtin_key", "name_enc"},
    "entry_history": _REQUIRED_STRUCTURE["entry_history"][1],
    "vault_recovery": _REQUIRED_STRUCTURE["vault_recovery"][1],
}
# Colonnes v3 en clair qui ne doivent PLUS exister dans un coffre v4.
_V4_FORBIDDEN: dict[str, set[str]] = {
    "entries": {"service_name", "url", "username", "entry_type", "category_id",
                "is_favorite", "is_deleted", "deleted_at", "created_at", "updated_at",
                "last_used_at", "password_changed_at"},
    "categories": {"name", "is_builtin", "created_at"},
}


def v4_tables_sql(suffix: str = "") -> dict[str, str]:
    """CREATE TABLE du schéma v4 définitif (`suffix` : tables de reconstruction).

    Plus aucune métadonnée en clair : tout est dans metadata_enc / name_enc.
    Les secrets sont inchangés (mêmes colonnes, même chiffrement sous la DEK).
    """
    from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS  # module sans dépendance

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
    """Écarts entre la base et le schéma `schema_version` (liste vide : structure saine).

    Vérifie les tables et colonnes indispensables, puis `PRAGMA quick_check`
    (cohérence des pages et des index, en lecture seule). Un coffre dont une
    table a été supprimée ou tronquée ne doit pas passer pour déverrouillé.
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
            problems.append(f"table {table} absente")
            continue
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}
        if expected - present:
            problems.append(f"colonnes absentes dans {table}")
        if schema_version >= V4_SCHEMA_VERSION and present & _V4_FORBIDDEN.get(table, set()):
            # Une colonne v3 en clair dans un coffre v4 : métadonnées potentiellement exposées.
            problems.append(f"colonnes v3 en clair présentes dans {table}")
    if schema_version >= V4_SCHEMA_VERSION and "entry_tags" in tables:
        problems.append("table entry_tags (v3) présente")
    check = [row[0] for row in conn.execute("PRAGMA quick_check;")]
    if check != ["ok"]:
        problems.append("contrôle d'intégrité SQLite en échec")
    return problems


# --- Structures du schéma v4 (ajouts seulement) -------------------------------------------
#
# v4 chiffre les métadonnées (voir app/core/metadata.py). Ces ajouts préparent la
# migration v3 -> v4 : colonnes NULLABLES pendant la transition (un coffre v3 n'a
# encore aucune valeur), anciennes colonnes intactes. Ils ne sont appliqués QUE par
# la migration, jamais à l'ouverture d'un coffre. Les contraintes définitives
# (NOT NULL, suppression des colonnes en clair) viendront avec la reconstruction
# finale des tables, après validation des données migrées.

_V4_COLUMNS: tuple[tuple[str, str, str], ...] = (
    # Identité stable du coffre (16 octets), utilisée dans les AAD des métadonnées.
    ("vault_meta", "vault_uuid",
     "BLOB CHECK (vault_uuid IS NULL"
     " OR (typeof(vault_uuid) = 'blob' AND length(vault_uuid) = 16))"),
    # Métadonnées chiffrées de l'entrée (nom, URL, identifiant, type, catégorie, tags…).
    ("entries", "metadata_enc",
     "BLOB CHECK (metadata_enc IS NULL OR typeof(metadata_enc) = 'blob')"),
    # Clé technique d'une catégorie intégrée (générique, identique dans tous les coffres).
    ("categories", "builtin_key",
     "TEXT CHECK (builtin_key IS NULL OR builtin_key IN ({keys}))"),
    # Nom chiffré d'une catégorie personnelle.
    ("categories", "name_enc",
     "BLOB CHECK (name_enc IS NULL OR typeof(name_enc) = 'blob')"),
)

_V4_EXTRA_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_builtin_key ON categories(builtin_key);",
    # vault_uuid est immuable une fois défini (renommage, mot de passe, restauration…).
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
    """Ajoute les colonnes, l'index et le déclencheur v4, sans rien retirer ni committer.

    Idempotent. Réservé à la migration v3 -> v4 (qui délimite la transaction) :
    n'est jamais appelé à l'ouverture d'un coffre, et ne génère aucune valeur.
    """
    from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS  # module sans dépendance

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
    """Structures v1/v2 -> v3, SANS transaction ni changement de schema_version.

    Réutilisé par `migrate` (v3) et par la migration v4, qui l'inclut dans sa
    propre transaction. Aucune donnée chiffrée n'est touchée.
    """
    if from_version < 2:
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(entries);")}
        if "password_changed_at" not in columns:
            conn.execute("ALTER TABLE entries ADD COLUMN password_changed_at TEXT;")
        # Date réelle inconnue : on prend la dernière modification (valeur
        # la plus récente possible, pour ne pas signaler à tort un mot de passe ancien).
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
