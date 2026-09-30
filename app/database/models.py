"""Modèles de données (dataclasses typées).

Ces dataclasses reflètent les tables SQLite telles qu'elles sont stockées :
les champs sensibles y sont des BLOB chiffrés opaques. Les objets
« déchiffrés » manipulés par l'application (Entry, EntrySummary) vivent
dans app/core/entries.py, car seule la couche cœur connaît la clé.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS
from app.core.crypto import Argon2Params, check_salt

VAULT_UUID_SIZE = 16  # identique à app.core.metadata.VAULT_UUID_SIZE (vérifié par un test)


def _check_blob(value: object, what: str) -> None:
    if not isinstance(value, bytes):
        raise ValueError(f"{what} invalide.")


def _check_version(value: object, what: str) -> None:
    # bool est un int en Python : exclu explicitement.
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{what} invalide.")


@dataclass(slots=True)
class RecoveryRecord:
    """Ligne de `vault_recovery` : la DEK enveloppée par la clé de récupération.

    Ne contient ni la clé de récupération, ni la DEK en clair.
    """

    kdf_params: Argon2Params
    kdf_salt: bytes
    wrapped_key_blob: bytes
    created_at: str

    def __post_init__(self) -> None:
        """Valeurs relues d'un fichier : ValueError si elles sont malformées."""
        check_salt(self.kdf_salt)
        _check_blob(self.wrapped_key_blob, "Enveloppe de récupération")


@dataclass(slots=True)
class VaultMeta:
    """Représentation en mémoire de la table `vault_meta`.

    `wrapped_key_blob` et `verifier_blob` sont des BLOB chiffrés opaques
    (voir app.core.crypto.pack_blob) : cette dataclass ne contient jamais
    de clé en clair.
    """

    schema_version: int
    format_version: int
    kdf_name: str
    kdf_params: Argon2Params
    kdf_salt: bytes
    wrapped_key_blob: bytes
    verifier_blob: bytes
    vault_name: str
    created_at: str
    updated_at: str
    # v4 : identité stable du coffre (AAD des métadonnées). None pour un coffre v3 :
    # jamais générée à la lecture, seulement par la migration ou la création v4.
    vault_uuid: bytes | None = None

    def __post_init__(self) -> None:
        """Valeurs relues d'un fichier (coffre, en-tête de sauvegarde) : ValueError si
        elles sont malformées, traduite en « coffre corrompu » par les appelants."""
        _check_version(self.schema_version, "Version de schéma")
        _check_version(self.format_version, "Version de format")
        if self.kdf_name != "argon2id":
            raise ValueError("Fonction de dérivation inconnue.")
        check_salt(self.kdf_salt)
        _check_blob(self.wrapped_key_blob, "Clé enveloppée")
        _check_blob(self.verifier_blob, "Vérificateur")
        if self.vault_uuid is not None and (
                not isinstance(self.vault_uuid, bytes) or len(self.vault_uuid) != VAULT_UUID_SIZE):
            raise ValueError("Identité de coffre invalide.")


@dataclass(slots=True)
class EntryRecord:
    """Ligne de la table `entries` d'un coffre v1 à v3 (métadonnées en clair).

    Legacy : lue par la migration v3 -> v4 uniquement ; le runtime v4 ne manipule
    que des blobs (EntryRepository, méthodes v4). Les attributs `*_enc` sont des BLOB
    AES-256-GCM (voir app.core.crypto.pack_blob) ou None si le champ est vide.
    """

    id: int | None
    entry_type: str
    category_id: int | None
    is_favorite: bool
    service_name: str
    url: str | None
    username: str | None
    email_enc: bytes | None
    password_enc: bytes | None
    notes_enc: bytes | None
    extra_fields_enc: bytes | None
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    password_changed_at: str | None = None
    is_deleted: bool = False
    deleted_at: str | None = None


@dataclass(slots=True)
class CategoryRecord:
    """Ligne de la table `categories` pendant la migration (legacy, voir EntryRecord).

    v3 : `name` en clair. v4 (colonnes ajoutées) : `builtin_key` pour une catégorie
    intégrée, OU `name_enc` (nom chiffré) pour une catégorie personnelle.
    """

    id: int
    name: str
    is_builtin: bool
    created_at: str
    builtin_key: str | None = None
    name_enc: bytes | None = None

    def __post_init__(self) -> None:
        if self.builtin_key is not None and self.builtin_key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Clé de catégorie intégrée inconnue.")
        if self.name_enc is not None:
            _check_blob(self.name_enc, "Nom de catégorie chiffré")
        if self.builtin_key is not None and self.name_enc is not None:
            raise ValueError("Catégorie à la fois intégrée et personnelle.")


@dataclass(slots=True)
class HistoryRecord:
    """Ligne de `entry_history` : une version précédente, chiffrée, d'une entrée."""

    id: int
    entry_id: int
    snapshot_enc: bytes | None
    created_at: str
