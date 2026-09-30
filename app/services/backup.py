"""Sauvegardes chiffrées du coffre.

Format d'un fichier `.mcfbak` (corps chiffré, en-tête technique lisible, autonome) :

    MAGIC (8 o) | longueur de l'en-tête (4 o, big-endian) | en-tête JSON
    | nonce (12 o) | AES-256-GCM( zlib( base SQLite complète ) )

* L'en-tête JSON est LISIBLE sans mot de passe (non secret, mais pas caché) :
  identifiant et nom du coffre, type et date de la sauvegarde, version de
  l'application, versions du schéma et du format, et ce qu'il faut pour le
  déverrouillage — paramètres Argon2id, sel, DEK enveloppée, vérificateur,
  exactement comme `vault_meta`. La sauvegarde s'ouvre donc avec le mot de
  passe maître **en vigueur au moment de la sauvegarde**, même si le coffre
  d'origine a disparu.
* Clé de chiffrement du corps : HKDF-SHA256(DEK, "mon-coffre-fort:backup:v1") —
  séparée de la clé des données.
* Donnée associée AES-GCM = MAGIC + en-tête : toute modification de
  l'en-tête est détectée.
* Le corps (la base complète : entrées, métadonnées, historique, catégories)
  n'est lisible qu'avec le mot de passe maître ; une sauvegarde peut être
  copiée sur un support externe, en sachant que son en-tête révèle les
  informations ci-dessus. Une sauvegarde d'un coffre v1 à v3 contient la base
  dans son ancien format (métadonnées en clair À L'INTÉRIEUR du corps chiffré).

Restaurer une sauvegarde crée toujours un **nouveau** coffre : rien n'est
écrasé.
"""

from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import struct
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app import __version__
from app.core import crypto
from app.core.exceptions import VaultCorruptedError, VaultError
from app.core.vault import (
    MAX_VAULT_NAME_LENGTH,
    Vault,
    VaultInfo,
    check_supported_versions,
    generate_vault_id,
    unwrap_data_key,
    validate_vault_name,
)
from app.database import database
from app.database.models import VaultMeta
from app.database.repositories import VaultMetaRepository
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger
from app.utils.paths import default_backup_dir, vault_path

MAGIC = b"MCFBAK\x00\x01"
BACKUP_SUFFIX = ".mcfbak"
_BACKUP_KEY_INFO = b"mon-coffre-fort:backup:v1"
_MAX_HEADER_SIZE = 64 * 1024
# Temporaires d'écriture (« .tmp-XXXX.mcfbak ») : ignorés au listage.
_TEMP_PREFIX = ".tmp-"
DEFAULT_AUTO_BACKUPS_KEPT = 10

KIND_MANUAL = "manuelle"
KIND_AUTO = "auto"
KIND_MIGRATION = "migration"  # faite juste avant une migration de schéma ; jamais tournée


class BackupError(VaultError):
    """Fichier de sauvegarde invalide, illisible ou restauration impossible."""


@dataclass(frozen=True, slots=True)
class BackupInfo:
    """Informations lisibles sans mot de passe (en-tête)."""

    path: Path
    vault_id: str
    vault_name: str
    created_at: str
    kind: str
    size: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Valeur base64 attendue.")
    return base64.b64decode(value.encode("ascii"), validate=True)


def _header_for(vault: Vault, kind: str) -> dict:
    meta = VaultMetaRepository(vault.connection).get()
    if meta is None:
        raise VaultCorruptedError("Métadonnées du coffre absentes.")
    return {
        "format": "mon-coffre-fort-backup",
        "version": 1,
        "app_version": __version__,
        "vault_id": vault.vault_id,
        "vault_name": meta.vault_name,
        "kind": kind,
        "created_at": datetime.now(UTC).isoformat(),
        "schema_version": meta.schema_version,
        "format_version": meta.format_version,
        "kdf_name": meta.kdf_name,
        "kdf_params": meta.kdf_params.to_dict(),
        "kdf_salt": _b64(meta.kdf_salt),
        "wrapped_key_blob": _b64(meta.wrapped_key_blob),
        "verifier_blob": _b64(meta.verifier_blob),
    }


def _meta_from_header(header: dict) -> VaultMeta:
    try:
        return VaultMeta(
            # Entiers stricts : validés par VaultMeta (pas de conversion « 3.7 » -> 3).
            schema_version=header["schema_version"],
            format_version=header["format_version"],
            kdf_name=str(header["kdf_name"]),
            kdf_params=crypto.Argon2Params.from_dict(header["kdf_params"]),
            kdf_salt=_unb64(header["kdf_salt"]),
            wrapped_key_blob=_unb64(header["wrapped_key_blob"]),
            verifier_blob=_unb64(header["verifier_blob"]),
            vault_name=str(header["vault_name"]),
            created_at=str(header["created_at"]),
            updated_at=str(header["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError("En-tête de sauvegarde invalide.") from exc


def _read(path: Path) -> tuple[bytes, dict, bytes]:
    """Retourne (octets de l'en-tête, en-tête décodé, reste du fichier)."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BackupError(f"Impossible de lire {path.name}.") from exc
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise BackupError(f"{path.name} n'est pas une sauvegarde Mon Coffre-Fort.")
    (length,) = struct.unpack(">I", data[len(MAGIC):len(MAGIC) + 4])
    start = len(MAGIC) + 4
    if length > _MAX_HEADER_SIZE or start + length > len(data):
        raise BackupError("Sauvegarde tronquée ou invalide.")
    header_bytes = data[start:start + length]
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError as exc:
        raise BackupError("En-tête de sauvegarde illisible.") from exc
    if not isinstance(header, dict) or header.get("format") != "mon-coffre-fort-backup":
        raise BackupError("Format de sauvegarde inconnu.")
    version = header.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise BackupError("Version de sauvegarde invalide.")
    if version > 1:
        raise BackupError("Sauvegarde créée par une version plus récente de l'application.")
    return header_bytes, header, data[start + length:]


# --- API ----------------------------------------------------------------------------


def create_backup(vault: Vault, directory: Path | None = None, kind: str = KIND_MANUAL,
                  destination: Path | None = None) -> Path:
    """Crée une sauvegarde chiffrée du coffre (déverrouillé) et retourne son chemin."""
    dek = vault._require_unlocked_key()
    header = _header_for(vault, kind)
    header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    database_bytes = vault.connection.serialize()  # instantané cohérent (WAL inclus)
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    nonce, ciphertext = crypto.aes_gcm_encrypt(
        key, zlib.compress(database_bytes, 9), MAGIC + header_bytes
    )
    if destination is None:
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")  # heure locale
        directory = directory or default_backup_dir()
        destination = directory / f"{vault.vault_id}_{stamp}_{kind}{BACKUP_SUFFIX}"
        # Deux sauvegardes dans la même seconde : jamais d'écrasement silencieux.
        counter = 2
        while destination.exists():
            destination = directory / f"{vault.vault_id}_{stamp}-{counter}_{kind}{BACKUP_SUFFIX}"
            counter += 1
    payload = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + nonce + ciphertext
    write_private_atomic(destination, payload, temp_prefix=_TEMP_PREFIX,
                         temp_suffix=BACKUP_SUFFIX)
    get_logger().info("Backup created (%s): %s", kind, destination.name)
    return destination


def read_backup_info(path: Path) -> BackupInfo:
    _header_bytes, header, _rest = _read(path)
    return BackupInfo(
        path=path,
        vault_id=str(header.get("vault_id", "")),
        vault_name=str(header.get("vault_name", "")),
        created_at=str(header.get("created_at", "")),
        kind=str(header.get("kind", "")),
        size=path.stat().st_size,
    )


def list_backups(directory: Path | None = None, vault_id: str | None = None) -> list[BackupInfo]:
    """Sauvegardes présentes dans un dossier, les plus récentes d'abord."""
    directory = directory or default_backup_dir()
    infos = []
    for path in directory.glob(f"*{BACKUP_SUFFIX}"):
        if path.name.startswith(_TEMP_PREFIX):  # écriture en cours ou interrompue
            continue
        try:
            info = read_backup_info(path)
        except (BackupError, OSError):  # fichier invalide, ou supprimé entre-temps
            continue
        if vault_id is None or info.vault_id == vault_id:
            infos.append(info)
    infos.sort(key=lambda i: i.created_at, reverse=True)
    return infos


def rotate_auto_backups(vault_id: str, directory: Path | None = None,
                        keep: int = DEFAULT_AUTO_BACKUPS_KEPT) -> int:
    """Ne conserve que les `keep` sauvegardes automatiques les plus récentes du coffre."""
    autos = [i for i in list_backups(directory, vault_id) if i.kind == KIND_AUTO]
    removed = 0
    for info in autos[keep:]:
        try:
            info.path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def delete_backup(path: Path, vault_id: str) -> None:
    """Supprime UNE sauvegarde du coffre `vault_id`.

    L'en-tête est relu d'abord : un fichier qui n'est pas une sauvegarde valide
    de CE coffre n'est jamais supprimé (BackupError).
    """
    path = Path(path)
    if path.suffix != BACKUP_SUFFIX or not path.is_file():
        raise BackupError("Ce fichier n'est pas une sauvegarde.")
    if read_backup_info(path).vault_id != vault_id:
        raise BackupError("Cette sauvegarde appartient à un autre coffre.")
    path.unlink()


def delete_backups(vault_id: str, directory: Path | None = None,
                   kind: str | None = None) -> int:
    """Supprime les sauvegardes du coffre (toutes, ou d'un seul type) ; retourne leur nombre."""
    removed = 0
    for info in list_backups(directory, vault_id):
        if kind is not None and info.kind != kind:
            continue
        try:
            delete_backup(info.path, vault_id)
            removed += 1
        except (BackupError, OSError):
            pass
    return removed


def verify_backup(path: Path, dek: bytes) -> None:
    """Vérifie qu'une sauvegarde est COMPLÈTEMENT restaurable avec la clé de données `dek`.

    Relit le fichier, authentifie et déchiffre le corps, décompresse la base et
    contrôle son intégrité SQLite, en mémoire uniquement (aucun fichier écrit).
    Lève BackupError sinon. Utilisé avant une migration : on ne migre jamais sans
    sauvegarde vérifiée.
    """
    header_bytes, header, rest = _read(path)
    meta = _meta_from_header(header)
    if len(rest) < crypto.NONCE_SIZE + crypto.TAG_SIZE:
        raise BackupError("Sauvegarde tronquée.")
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    try:
        image = bytearray(zlib.decompress(crypto.aes_gcm_decrypt(
            key, rest[:crypto.NONCE_SIZE], rest[crypto.NONCE_SIZE:], MAGIC + header_bytes)))
    except (crypto.AuthenticationFailed, zlib.error) as exc:
        raise BackupError("La sauvegarde ne se déchiffre pas avec la clé de ce coffre.") from exc
    if len(image) < 100 or not image.startswith(b"SQLite format 3\x00"):
        raise BackupError("Le contenu de la sauvegarde n'est pas une base valide.")
    image[18] = image[19] = 1  # mode journal classique (comme à la restauration)
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(bytes(image))
        if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
            raise BackupError("La base contenue dans la sauvegarde est incohérente.")
        stored = conn.execute("SELECT schema_version FROM vault_meta WHERE id = 1;").fetchone()
        if stored is None or stored[0] != meta.schema_version:
            raise BackupError("En-tête et contenu de la sauvegarde ne correspondent pas.")
    except sqlite3.DatabaseError as exc:
        raise BackupError("La base contenue dans la sauvegarde est illisible.") from exc
    finally:
        conn.close()


def restore_backup(path: Path, master_password: str) -> VaultInfo:
    """Restaure une sauvegarde sous forme d'un **nouveau** coffre.

    Lève WrongMasterPasswordError (mauvais mot de passe), BackupError ou
    VaultCorruptedError (fichier invalide ou altéré).
    """
    header_bytes, header, rest = _read(path)
    meta = _meta_from_header(header)
    check_supported_versions(meta)
    dek = unwrap_data_key(master_password, meta)  # WrongMasterPasswordError si faux

    if len(rest) < crypto.NONCE_SIZE + 16:
        raise BackupError("Sauvegarde tronquée.")
    nonce, ciphertext = rest[:crypto.NONCE_SIZE], rest[crypto.NONCE_SIZE:]
    key = crypto.derive_subkey(dek, _BACKUP_KEY_INFO)
    try:
        compressed = crypto.aes_gcm_decrypt(key, nonce, ciphertext, MAGIC + header_bytes)
        database_bytes = zlib.decompress(compressed)
    except (crypto.AuthenticationFailed, zlib.error) as exc:
        raise VaultCorruptedError("La sauvegarde a été altérée ou est corrompue.") from exc

    suffix = f" (restauré le {datetime.now().astimezone():%d/%m/%Y %H:%M})"
    # Le nom vient de l'en-tête (non authentifié à ce stade) : borné et nettoyé.
    base = " ".join(meta.vault_name.split())[:MAX_VAULT_NAME_LENGTH - len(suffix)] or "Coffre"
    restored_name = validate_vault_name(base + suffix)
    new_id = generate_vault_id(meta.vault_name)
    directory = vault_path(new_id)
    db_path = directory / "vault.db"
    try:
        image = bytearray(database_bytes)
        if len(image) < 100 or not image.startswith(b"SQLite format 3\x00"):
            raise BackupError("Le contenu de la sauvegarde n'est pas une base valide.")
        # Octets 18-19 de l'en-tête SQLite = 2 en mode WAL : on repasse en mode
        # journal classique pour que le fichier soit lisible seul (sans -wal) ;
        # database.connect() réactive ensuite le WAL.
        image[18] = image[19] = 1
        write_private_atomic(db_path, bytes(image), temp_prefix=_TEMP_PREFIX,
                             temp_suffix=BACKUP_SUFFIX)
        conn = database.connect(db_path)
        try:
            if conn.execute("PRAGMA integrity_check;").fetchone()[0] != "ok":
                raise BackupError("La base contenue dans la sauvegarde est incohérente.")
            with conn:
                VaultMetaRepository(conn).rename_vault(
                    restored_name, datetime.now(UTC).isoformat()
                )
        finally:
            conn.close()
        # Vérification complète : le coffre restauré doit se déverrouiller.
        if meta.schema_version < database.SCHEMA_VERSION:
            # Ancienne sauvegarde (v1 à v3) : coffre restauré tel quel, vérifié SANS être
            # modifié ; sa mise à niveau sera PROPOSÉE à sa première ouverture (préflight,
            # confirmation explicite, sauvegarde, migration, vérification : vault_upgrade).
            Vault.open_for_migration(new_id, master_password).close()
        else:
            Vault.unlock(new_id, master_password).close()
    except Exception as exc:
        shutil.rmtree(directory, ignore_errors=True)
        if isinstance(exc, VaultError):
            raise
        raise BackupError("La restauration a échoué ; aucun coffre n'a été créé.") from exc

    get_logger().info("Backup restored as new vault: %s", new_id)
    return VaultInfo(new_id, restored_name, meta.format_version, meta.created_at, meta.created_at)
