"""Le coffre (Vault) : création, déverrouillage, verrouillage.

Modèle de sécurité (chiffrement en enveloppe) :

    mot de passe maître --Argon2id(salt)--> KEK (clé de chiffrement de clé)
    KEK --AES-256-GCM--> déchiffre/chiffre la DEK (clé de données, aléatoire)
    DEK --AES-256-GCM--> chiffre/déchiffre chaque champ sensible d'une entrée

La DEK n'existe jamais sur disque en clair. Le mot de passe maître
n'existe jamais sur disque, même dérivé (seul son résultat de dérivation
sert de KEK éphémère, en mémoire, le temps de dé-envelopper la DEK).

Clé de récupération (facultative) : une SECONDE enveloppe de la même DEK.

    clé de récupération --Argon2id(salt)--> KEK de récupération
    KEK de récupération --AES-256-GCM--> DEK   (table vault_recovery)

Elle ouvre donc le coffre à elle seule. Elle n'est jamais stockée (affichée
une fois, voir app.core.recovery). Après usage, elle est remplacée : la
clé tapée a pu être vue, elle ne doit plus rien ouvrir.

Limite connue et assumée (documentée dans le README) : comme pour tout
gestionnaire de mots de passe basé sur un chiffrement authentifié, un échec
d'authentification GCM lors du dé-enveloppement de la DEK est traité comme
un « mauvais mot de passe maître », car ce cas est cryptographiquement
indissociable d'une corruption ciblée du blob de clé enveloppée. Les autres
formes de corruption (structure de fichier, version de format) sont, elles,
détectées et rapportées distinctement.
"""

from __future__ import annotations

import re
import secrets
import shutil
import sqlite3
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core import crypto, recovery
from app.core.exceptions import (
    InvalidMasterPasswordPolicyError,
    NoRecoveryKeyError,
    RecoveryKeyError,
    UnsupportedVaultVersionError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultError,
    VaultLockedError,
    VaultMigrationRequiredError,
    VaultNotFoundError,
    WrongMasterPasswordError,
)
from app.core.metadata import new_vault_uuid
from app.core.metadata_store import MetadataStore
from app.database import database
from app.database.models import RecoveryRecord, VaultMeta
from app.database.repositories import RecoveryRepository, VaultMetaRepository
from app.utils.logging import get_logger
from app.utils.paths import vault_path, vaults_dir

CURRENT_FORMAT_VERSION = 1
MIN_MASTER_PASSWORD_LENGTH = 8
MAX_VAULT_NAME_LENGTH = 60

# Valeur constante utilisée uniquement pour vérifier, après dé-enveloppement,
# que la DEK obtenue est bien exploitable. Ce n'est pas un secret.
_VERIFIER_PLAINTEXT = b"MON-COFFRE-FORT-VERIFIER-V1"
_VERIFIER_AAD = b"mon-coffre-fort:verifier"
_WRAPPED_KEY_AAD = b"mon-coffre-fort:wrapped-dek"
# Donnée associée distincte : une enveloppe ne peut pas être prise pour l'autre.
_RECOVERY_KEY_AAD = b"mon-coffre-fort:recovery-wrapped-dek"

_DB_FILENAME = "vault.db"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _validate_master_password_policy(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            f"Le mot de passe maître doit contenir au moins "
            f"{MIN_MASTER_PASSWORD_LENGTH} caractères."
        )


@dataclass(slots=True)
class VaultInfo:
    """Informations non sensibles sur un coffre, utilisables coffre verrouillé."""

    vault_id: str
    vault_name: str
    format_version: int
    created_at: str
    updated_at: str


def check_supported_versions(meta: VaultMeta) -> None:
    if meta.format_version > CURRENT_FORMAT_VERSION:
        raise UnsupportedVaultVersionError(
            f"Ce coffre utilise un format plus récent "
            f"(v{meta.format_version}) que celui supporté par l'application "
            f"(v{CURRENT_FORMAT_VERSION})."
        )
    if meta.schema_version > database.SCHEMA_VERSION:
        raise UnsupportedVaultVersionError(
            f"Ce coffre a été créé par une version plus récente de l'application "
            f"(schéma v{meta.schema_version}, supporté : v{database.SCHEMA_VERSION})."
        )


def unwrap_data_key(master_password: str, meta: VaultMeta) -> bytes:
    """Dérive la KEK et dé-enveloppe la DEK décrite par `meta`.

    Utilisé au déverrouillage, pour revérifier le mot de passe maître
    (export, changement de mot de passe) et pour restaurer une sauvegarde
    (dont l'en-tête contient les mêmes métadonnées).
    """
    kek = crypto.derive_key(master_password, meta.kdf_salt, meta.kdf_params)

    try:
        _version, nonce, ciphertext = crypto.unpack_blob(meta.wrapped_key_blob)
    except ValueError as exc:
        raise VaultCorruptedError("Clé de coffre enveloppée invalide.") from exc

    try:
        dek = crypto.aes_gcm_decrypt(kek, nonce, ciphertext, _WRAPPED_KEY_AAD)
    except crypto.AuthenticationFailed as exc:
        raise WrongMasterPasswordError("Mot de passe maître incorrect.") from exc
    _check_verifier(dek, meta)
    return dek


def _check_verifier(dek: bytes, meta: VaultMeta) -> None:
    """Défense en profondeur : la DEK obtenue doit déchiffrer le vérificateur du coffre."""
    try:
        _v_version, v_nonce, v_ciphertext = crypto.unpack_blob(meta.verifier_blob)
        plaintext = crypto.aes_gcm_decrypt(dek, v_nonce, v_ciphertext, _VERIFIER_AAD)
    except (ValueError, crypto.AuthenticationFailed) as exc:
        raise VaultCorruptedError(
            "La vérification d'intégrité du coffre a échoué après déverrouillage."
        ) from exc

    if plaintext != _VERIFIER_PLAINTEXT:
        raise VaultCorruptedError("Vérificateur de coffre invalide.")


def _wrap_for_password(dek: bytes, password: str) -> dict:
    """Nouvelle enveloppe de la DEK pour `password` (sel et paramètres neufs)."""
    salt = crypto.generate_salt()
    params = crypto.Argon2Params()
    kek = crypto.derive_key(password, salt, params)
    nonce, ciphertext = crypto.aes_gcm_encrypt(kek, dek, _WRAPPED_KEY_AAD)
    v_nonce, v_ciphertext = crypto.aes_gcm_encrypt(dek, _VERIFIER_PLAINTEXT, _VERIFIER_AAD)
    return {"wrapped_key_blob": crypto.pack_blob(nonce, ciphertext),
            "verifier_blob": crypto.pack_blob(v_nonce, v_ciphertext),
            "kdf_salt": salt, "kdf_params": params}


def _new_recovery(dek: bytes) -> tuple[str, RecoveryRecord]:
    """Tire une clé de récupération et enveloppe la DEK avec : (clé affichable, ligne)."""
    key = recovery.generate()
    salt = crypto.generate_salt()
    params = crypto.Argon2Params()
    kek = crypto.derive_key(recovery.normalize(key), salt, params)
    nonce, ciphertext = crypto.aes_gcm_encrypt(kek, dek, _RECOVERY_KEY_AAD)
    return key, RecoveryRecord(kdf_params=params, kdf_salt=salt,
                               wrapped_key_blob=crypto.pack_blob(nonce, ciphertext),
                               created_at=_utc_now_iso())


def _unwrap_with_recovery(secret: str, record: RecoveryRecord, meta: VaultMeta) -> bytes:
    kek = crypto.derive_key(secret, record.kdf_salt, record.kdf_params)
    try:
        _version, nonce, ciphertext = crypto.unpack_blob(record.wrapped_key_blob)
    except ValueError as exc:
        raise VaultCorruptedError("Enveloppe de récupération invalide.") from exc
    try:
        dek = crypto.aes_gcm_decrypt(kek, nonce, ciphertext, _RECOVERY_KEY_AAD)
    except crypto.AuthenticationFailed as exc:
        raise RecoveryKeyError("Clé de récupération incorrecte pour ce coffre.") from exc
    _check_verifier(dek, meta)
    return dek


def _require_current_schema(meta: VaultMeta) -> None:
    """Un coffre v1 à v3 doit d'abord être migré (app.services.migration_v4) ; rien
    n'est modifié ici. Plus aucune copie .bak en clair n'est jamais créée."""
    if meta.schema_version < database.SCHEMA_VERSION:
        raise VaultMigrationRequiredError(
            f"Ce coffre utilise un ancien format (v{meta.schema_version}) : il doit être mis "
            "à niveau vers le format de la version 1.7 avant d'être ouvert. "
            "Il n'a pas été modifié.")


def _read_recovery(conn: sqlite3.Connection) -> RecoveryRecord | None:
    """Enveloppe de récupération, ou None ; VaultCorruptedError si elle est malformée."""
    try:
        return RecoveryRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        raise VaultCorruptedError("L'enveloppe de récupération du coffre est corrompue.") from exc


def _open_existing(vault_id: str) -> tuple[sqlite3.Connection, Path, VaultMeta]:
    """Connexion au fichier d'un coffre existant et lecture de ses métadonnées."""
    db_path = vault_path(vault_id) / _DB_FILENAME
    if not db_path.exists():
        raise VaultNotFoundError(f"Le coffre « {vault_id} » est introuvable.")
    try:
        conn = database.connect(db_path)
    except sqlite3.DatabaseError as exc:
        raise VaultCorruptedError("Impossible d'ouvrir le fichier du coffre.") from exc
    try:
        meta = VaultMetaRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        conn.close()
        raise VaultCorruptedError("Le fichier du coffre est corrompu.") from exc
    if meta is None:
        conn.close()
        raise VaultCorruptedError("Métadonnées du coffre absentes ou corrompues.")
    try:
        # Un schéma plus récent que tous ceux connus ne peut pas être vérifié ici :
        # check_supported_versions le refusera explicitement (version non prise en charge).
        problems = (database.structure_problems(conn, meta.schema_version)
                    if meta.schema_version <= database.V4_SCHEMA_VERSION else [])
    except sqlite3.DatabaseError:
        problems = ["base illisible"]
    if problems:
        conn.close()
        get_logger().error("Vault structure invalid: %s (%s)", vault_id, "; ".join(problems))
        raise VaultCorruptedError("La structure du fichier du coffre est endommagée.")
    return conn, db_path, meta


class Vault:
    """Représente un coffre, verrouillé ou déverrouillé.

    Instancier cette classe directement n'est pas prévu : utiliser
    `Vault.create(...)` ou `Vault.unlock(...)`.
    """

    def __init__(self, vault_id: str, db_path: Path, conn: sqlite3.Connection) -> None:
        self.vault_id = vault_id
        self._db_path = db_path
        self._conn = conn
        self._meta_repo = VaultMetaRepository(conn)
        self._dek: bytearray | None = None  # None => verrouillé
        self._metadata: MetadataStore | None = None  # cache v4, détruit au verrouillage
        self._logger = get_logger()

    # --- Propriétés ----------------------------------------------------------

    @property
    def is_locked(self) -> bool:
        return self._dek is None

    @property
    def info(self) -> VaultInfo:
        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Métadonnées du coffre introuvables.")
        return VaultInfo(
            vault_id=self.vault_id,
            vault_name=meta.vault_name,
            format_version=meta.format_version,
            created_at=meta.created_at,
            updated_at=meta.updated_at,
        )

    # --- Cycle de vie ----------------------------------------------------------

    @classmethod
    def create(cls, vault_id: str, vault_name: str, master_password: str) -> Vault:
        """Crée un nouveau coffre chiffré et le retourne déverrouillé."""
        vault_name = validate_vault_name(vault_name)
        _validate_master_password_policy(master_password)

        directory = vault_path(vault_id)
        db_path = directory / _DB_FILENAME
        if db_path.exists():
            raise VaultAlreadyExistsError(f"Le coffre « {vault_id} » existe déjà.")

        conn = database.connect(db_path)
        database.initialize_schema(conn)

        dek = crypto.generate_key()
        envelope = _wrap_for_password(dek, master_password)

        now = _utc_now_iso()
        meta = VaultMeta(
            schema_version=database.SCHEMA_VERSION,
            format_version=CURRENT_FORMAT_VERSION,
            kdf_name="argon2id",
            **envelope,
            vault_name=vault_name,
            created_at=now,
            updated_at=now,
            vault_uuid=new_vault_uuid(),  # identité du coffre, immuable (AAD des métadonnées)
        )
        repo = VaultMetaRepository(conn)
        repo.insert(meta)

        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault created: %s", vault_id)
        return vault

    @classmethod
    def create_with_recovery(cls, vault_id: str, vault_name: str,
                             master_password: str) -> tuple[Vault, str]:
        """Crée le coffre et sa clé de récupération (retournée pour affichage unique)."""
        vault = cls.create(vault_id, vault_name, master_password)
        try:
            return vault, vault._install_recovery_key(vault._require_unlocked_key())
        except Exception:
            vault.close()
            raise

    @classmethod
    def unlock(cls, vault_id: str, master_password: str) -> Vault:
        """Ouvre un coffre existant. Lève une exception métier explicite en cas d'échec."""
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            dek = unwrap_data_key(master_password, meta)
            _require_current_schema(meta)
        except Exception:
            conn.close()
            raise

        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault unlocked: %s", vault_id)
        return vault

    @classmethod
    def open_for_migration(cls, vault_id: str, master_password: str) -> Vault:
        """Ouvre un coffre v1 à v3 SANS mise à niveau automatique (donc sans copie .bak).

        Réservé à la migration v4 (app.services.migration_v4), qui fait d'abord une
        sauvegarde CHIFFRÉE puis inclut les étapes v1/v2 -> v3 dans sa propre
        transaction. Le schéma du fichier n'est pas modifié ici.
        """
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            if meta.schema_version >= database.V4_SCHEMA_VERSION:
                raise VaultError("Ce coffre est déjà au format v4.")
            dek = unwrap_data_key(master_password, meta)
        except Exception:
            conn.close()
            raise
        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault opened for migration: %s", vault_id)
        return vault

    @property
    def metadata(self) -> MetadataStore:
        """Cache des métadonnées déchiffrées (coffre v4 déverrouillé uniquement).

        Créé au premier accès après le déverrouillage ; détruit par `lock()`.
        """
        dek = self._require_unlocked_key()
        if self._metadata is None:
            meta = self._meta_repo.get()
            if (meta is None or meta.schema_version < database.V4_SCHEMA_VERSION
                    or meta.vault_uuid is None):
                raise VaultError("Métadonnées chiffrées indisponibles : coffre non migré (v4).")
            self._metadata = MetadataStore(self._conn, dek, meta.vault_uuid)
        return self._metadata

    def lock(self) -> None:
        """Efface la DEK et le cache des métadonnées (best-effort), verrouille le coffre."""
        if self._metadata is not None:
            self._metadata.clear()
            self._metadata = None
        if self._dek is not None:
            crypto.wipe(self._dek)
            self._dek = None
            self._logger.info("Vault locked: %s", self.vault_id)

    def close(self) -> None:
        """Verrouille le coffre et ferme la connexion à la base."""
        self.lock()
        self._conn.close()

    # --- Accès à la clé de données (réservé aux couches internes) --------------

    def _require_unlocked_key(self) -> bytes:
        if self._dek is None:
            raise VaultLockedError("Le coffre est verrouillé.")
        return bytes(self._dek)

    @property
    def connection(self) -> sqlite3.Connection:
        """Connexion SQLite brute, utilisée par les repositories et services.

        Accessible même verrouillé, pour ce que le fichier garde lisible par
        conception (`vault_meta` : nom du coffre, paramètres de dérivation ; dates
        `entry_history.created_at`, D3). Les métadonnées d'entrées et les noms de
        catégories, eux, sont chiffrés (v4) : les services qui les lisent passent
        par `_require_unlocked_key()` ou le cache `metadata`.
        """
        return self._conn

    # --- Nom du coffre ---------------------------------------------------------------

    def rename(self, new_name: str) -> None:
        self._require_unlocked_key()
        self._meta_repo.rename_vault(validate_vault_name(new_name), _utc_now_iso())
        self._logger.info("Vault renamed: %s", self.vault_id)

    # --- Revérification du mot de passe maître -----------------------------------

    def verify_master_password(self, password: str, log_failure: bool = True) -> bool:
        """Revérifie le mot de passe maître indépendamment de l'état déverrouillé.

        Exigé avant les opérations sensibles (export, changement de mot de
        passe) : une session laissée ouverte ne suffit pas pour les réaliser.
        """
        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Métadonnées du coffre absentes.")
        try:
            unwrap_data_key(password, meta)
        except WrongMasterPasswordError:
            if log_failure:  # False : simple comparaison (ex. mot de passe d'un PDF)
                self._logger.warning("Master password re-verification failed: %s",
                                     self.vault_id)
            return False
        return True

    # --- Changement de mot de passe maître --------------------------------------

    def change_master_password(self, current_password: str, new_password: str) -> None:
        """Ré-enveloppe la DEK existante sous un nouveau mot de passe maître.

        Les données déjà chiffrées avec la DEK n'ont pas besoin d'être
        touchées : seule l'enveloppe (KEK) change. C'est l'intérêt du
        chiffrement en enveloppe.
        """
        _validate_master_password_policy(new_password)
        dek = self._require_unlocked_key()

        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Métadonnées du coffre absentes.")

        # On revérifie l'ancien mot de passe indépendamment de l'état déverrouillé
        # en mémoire, pour éviter qu'une session laissée ouverte ne permette de
        # changer le mot de passe sans le connaître.
        if not self.verify_master_password(current_password):
            raise WrongMasterPasswordError("Le mot de passe maître actuel est incorrect.")

        self._meta_repo.update_wrapped_key(**_wrap_for_password(dek, new_password),
                                           updated_at=_utc_now_iso())
        self._logger.info("Master password changed for vault: %s", self.vault_id)

    # --- Clé de récupération ---------------------------------------------------------

    @property
    def recovery_created_at(self) -> str | None:
        """Date de création de la clé de récupération (ISO), ou None s'il n'y en a pas."""
        record = _read_recovery(self._conn)
        return record.created_at if record else None

    @property
    def has_recovery_key(self) -> bool:
        return self.recovery_created_at is not None

    def create_recovery_key(self, master_password: str) -> str:
        """Crée (ou remplace) la clé de récupération et la retourne, pour affichage UNIQUE.

        Le mot de passe maître est exigé : une session laissée ouverte ne doit
        pas permettre de se fabriquer un accès permanent au coffre.
        """
        dek = self._require_unlocked_key()
        if not self.verify_master_password(master_password):
            raise WrongMasterPasswordError("Mot de passe maître incorrect.")
        return self._install_recovery_key(dek)

    def _install_recovery_key(self, dek: bytes) -> str:
        key, record = _new_recovery(dek)
        RecoveryRepository(self._conn).set(record)
        self._logger.info("Recovery key created for vault: %s", self.vault_id)
        return key

    def remove_recovery_key(self, master_password: str) -> None:
        self._require_unlocked_key()
        if not self.verify_master_password(master_password):
            raise WrongMasterPasswordError("Mot de passe maître incorrect.")
        RecoveryRepository(self._conn).delete()
        self._logger.info("Recovery key removed for vault: %s", self.vault_id)

    def discard_recovery_key(self) -> None:
        """Supprime une clé que l'utilisateur n'a pas confirmé avoir notée.

        Sans mot de passe : supprimer une clé ne fait que RETIRER un accès.
        """
        self._require_unlocked_key()
        RecoveryRepository(self._conn).delete()
        self._logger.info("Unconfirmed recovery key discarded for vault: %s", self.vault_id)

    @classmethod
    def recover(cls, vault_id: str, recovery_key: str,
                new_master_password: str, allow_legacy: bool = False) -> tuple[Vault, str]:
        """Ouvre le coffre avec sa clé de récupération et fixe un nouveau mot de passe maître.

        Retourne le coffre déverrouillé et la NOUVELLE clé de récupération (l'ancienne
        ne fonctionne plus). Enveloppe du mot de passe et enveloppe de récupération
        sont remplacées dans une même transaction : jamais l'une sans l'autre.

        `allow_legacy` : accepte un coffre v1 à v3, pour le seul enchaînement
        « récupération puis mise à niveau » (app.services.vault_upgrade). Seules les
        deux enveloppes sont réécrites, comme en 1.6 ; le coffre rendu n'est
        utilisable que par la migration, jamais par les services v4.
        """
        _validate_master_password_policy(new_master_password)
        secret = recovery.normalize(recovery_key)  # RecoveryKeyFormatError : faute de frappe
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            if not allow_legacy:
                _require_current_schema(meta)
            elif meta.schema_version >= database.SCHEMA_VERSION:
                raise VaultError("Ce coffre est déjà au format actuel.")
            record = _read_recovery(conn)
            if record is None:
                raise NoRecoveryKeyError("Ce coffre n'a pas de clé de récupération.")
            dek = _unwrap_with_recovery(secret, record, meta)
            new_key, new_record = _new_recovery(dek)
            password_envelope = _wrap_for_password(dek, new_master_password)
            with conn:  # une seule transaction
                VaultMetaRepository(conn).update_wrapped_key(
                    **password_envelope, updated_at=_utc_now_iso(), commit=False)
                RecoveryRepository(conn).set(new_record, commit=False)
        except Exception:
            conn.close()
            raise
        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.warning("Vault recovered with its recovery key: %s", vault_id)
        return vault, new_key


# --- Découverte des coffres (sans mot de passe) --------------------------------------


def generate_vault_id(vault_name: str) -> str:
    """Identifiant de coffre sûr pour le système de fichiers, dérivé du nom.

    Ex. « Coffre Perso » -> « coffre-perso-3fa9c1 ». Le suffixe aléatoire
    (CSPRNG) évite les collisions entre coffres de même nom.
    """
    ascii_name = (
        unicodedata.normalize("NFKD", vault_name).encode("ascii", "ignore").decode("ascii")
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:32] or "coffre"
    return f"{slug}-{secrets.token_hex(3)}"


def list_vaults() -> list[VaultInfo]:
    """Liste les coffres présents localement, avec leurs métadonnées non sensibles.

    Un coffre illisible est tout de même listé (sous son identifiant) : c'est
    au déverrouillage qu'une erreur explicite sera présentée à l'utilisateur.
    """
    infos: list[VaultInfo] = []
    for directory in sorted(vaults_dir().iterdir()):
        db_path = directory / _DB_FILENAME
        if not directory.is_dir() or not db_path.is_file():
            continue
        vault_id = directory.name
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                meta = VaultMetaRepository(conn).get()
            finally:
                conn.close()
        except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
            meta = None
        if meta is None:
            get_logger().warning("Unreadable vault metadata: %s", vault_id)
            infos.append(VaultInfo(vault_id, vault_id, 0, "", ""))
        else:
            infos.append(
                VaultInfo(
                    vault_id=vault_id,
                    vault_name=meta.vault_name,
                    format_version=meta.format_version,
                    created_at=meta.created_at,
                    updated_at=meta.updated_at,
                )
            )
    return infos


def vault_has_recovery_key(vault_id: str) -> bool:
    """Le coffre a-t-il une clé de récupération ? (lecture seule, sans mot de passe)"""
    db_path = vaults_dir() / vault_id / _DB_FILENAME
    if not re.fullmatch(r"[A-Za-z0-9._-]+", vault_id) or not db_path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            return RecoveryRepository(conn).get() is not None
        finally:
            conn.close()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
        return False


def validate_vault_name(name: str) -> str:
    clean = " ".join(name.split())
    if not clean:
        raise VaultError("Le nom du coffre est obligatoire.")
    if len(clean) > MAX_VAULT_NAME_LENGTH:
        raise VaultError(
            f"Le nom du coffre ne doit pas dépasser {MAX_VAULT_NAME_LENGTH} caractères."
        )
    return clean


def delete_vault(vault_id: str, master_password: str) -> None:
    """Supprime définitivement un coffre (répertoire complet), mot de passe maître exigé.

    Le coffre ne doit pas être ouvert. Les sauvegardes .mcfbak, stockées
    ailleurs, ne sont pas touchées.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]+", vault_id) or vault_id in (".", ".."):
        raise VaultNotFoundError("Identifiant de coffre invalide.")
    directory = vaults_dir() / vault_id
    db_path = directory / _DB_FILENAME
    if not db_path.is_file():
        raise VaultNotFoundError(f"Le coffre « {vault_id} » est introuvable.")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        meta = VaultMetaRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
        meta = None
    finally:
        conn.close()
    if meta is None:
        # Coffre illisible : impossible de vérifier le mot de passe, on refuse
        # (supprimer le dossier reste possible manuellement, en connaissance de cause).
        raise VaultCorruptedError(
            "Ce coffre est illisible : sa suppression ne peut pas être vérifiée."
        )
    unwrap_data_key(master_password, meta)  # WrongMasterPasswordError si faux
    shutil.rmtree(directory)
    get_logger().info("Vault deleted: %s", vault_id)
