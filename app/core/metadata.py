"""Chiffrement des métadonnées d'entrée et des noms de catégories (schéma v4).

Tout ce qui décrit le contenu ou l'organisation du coffre (nom, URL,
identifiant, type, catégorie, favori, tags, dates) est regroupé dans un JSON
chiffré et authentifié par entrée ; le nom d'une catégorie personnelle l'est
de même. Ce module ne fait qu'assembler des primitives existantes de
app.core.crypto (derive_subkey, encrypt_field, decrypt_field) :

    sous-clé métadonnées = HKDF-SHA256(DEK, "mon-coffre-fort:entry-metadata:v1")
    sous-clé catégories  = HKDF-SHA256(DEK, "mon-coffre-fort:category:v1")
    AAD entrée    = "mon-coffre-fort:entry-metadata:<vault_uuid hex>:<entry_id>"
    AAD catégorie = "mon-coffre-fort:category:<vault_uuid hex>:<category_id>"

Un blob ne peut donc être ni modifié, ni déplacé vers une autre entrée ou
catégorie, ni vers un autre coffre, ni pris pour l'autre usage (sous-clé ET
AAD différentes). Les secrets (mot de passe, notes…) restent chiffrés comme
avant, directement sous la DEK : ce module ne les touche pas.

JSON versionné ("v": 1), validé strictement à la lecture : clés exactes,
types, dates ISO 8601 avec fuseau, tags canoniques. Toute anomalie lève une
erreur de corruption — jamais de valeur par défaut silencieuse.

Remplissage (« pad ») : le texte chiffré a une longueur multiple de 64 octets.
Cela RÉDUIT la fuite de la longueur (un nom court et un nom moyen donnent la
même taille) sans la supprimer : un contenu très long reste plus gros, et le
nombre d'entrées, de catégories et de versions reste visible dans SQLite.
"""

from __future__ import annotations

import json
import secrets
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.core import crypto
from app.core.exceptions import (
    CategoryDecryptionError,
    CategoryError,
    EntryDecryptionError,
    EntryValidationError,
)

ENTRY_METADATA_INFO = b"mon-coffre-fort:entry-metadata:v1"
CATEGORY_INFO = b"mon-coffre-fort:category:v1"
METADATA_VERSION = 1
PAD_BLOCK = 64
VAULT_UUID_SIZE = 16

MAX_TAGS = 20
MAX_TAG_LENGTH = 32
# Doit rester identique aux clés de app.core.entries.ENTRY_TYPES (vérifié par un test ;
# pas d'import direct : entries dépendra de ce module).
ENTRY_TYPE_KEYS = frozenset({"login", "secure_note", "card", "identity", "wifi", "server"})

_ENTRY_KEYS = frozenset({
    "v", "name", "url", "username", "entry_type", "category_id", "is_favorite", "tags",
    "created_at", "updated_at", "password_changed_at", "deleted_at", "pad",
})
_CATEGORY_KEYS = frozenset({"v", "name", "created_at", "pad"})


# --- Objets déchiffrés ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntryMetadata:
    """Métadonnées d'une entrée, déchiffrées (n'existent qu'en mémoire)."""

    name: str
    url: str
    username: str
    entry_type: str
    category_id: int | None
    is_favorite: bool
    tags: tuple[str, ...]
    created_at: str
    updated_at: str
    password_changed_at: str
    deleted_at: str | None = None  # non nul = dans la corbeille

    def __repr__(self) -> str:  # jamais de contenu dans un repr (journaux, traces)
        return (f"EntryMetadata(entry_type={self.entry_type!r}, tags={len(self.tags)}, "
                f"in_trash={self.deleted_at is not None})")


@dataclass(frozen=True, slots=True)
class CategoryMetadata:
    """Nom d'une catégorie personnelle, déchiffré."""

    name: str
    created_at: str

    def __repr__(self) -> str:
        return "CategoryMetadata(…)"


# --- Tags --------------------------------------------------------------------------------


def tag_key(tag: str) -> str:
    """Clé de comparaison : « Linux », « linux » et « LINUX » sont le même tag, « Écoles »
    et « ecoles » aussi (casse et accents ignorés). La forme affichée est conservée."""
    decomposed = unicodedata.normalize("NFKD", tag)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()


def normalize_tags(raw: Iterable[str]) -> tuple[str, ...]:
    """Tags saisis -> forme canonique (ordre conservé). Lève EntryValidationError.

    Forme canonique : Unicode NFC, espaces superflus retirés, « # » initial retiré,
    casse d'origine conservée. Refusés : tag vide, plus de MAX_TAG_LENGTH caractères,
    caractère de contrôle ou virgule, doublon logique, plus de MAX_TAGS tags.
    """
    result: list[str] = []
    seen: set[str] = set()
    for value in raw:
        if not isinstance(value, str):
            raise EntryValidationError("Un tag doit être du texte.")
        tag = " ".join(unicodedata.normalize("NFC", value).split()).lstrip("#").strip()
        if not tag:
            raise EntryValidationError("Un tag ne peut pas être vide.")
        if len(tag) > MAX_TAG_LENGTH:
            raise EntryValidationError(
                f"Un tag ne doit pas dépasser {MAX_TAG_LENGTH} caractères.")
        if "," in tag or any(unicodedata.category(c).startswith("C") for c in tag):
            raise EntryValidationError("Un tag ne peut contenir ni virgule ni caractère spécial.")
        key = tag_key(tag)
        if key in seen:
            raise EntryValidationError(f"Tag en double : « {tag} ».")
        seen.add(key)
        result.append(tag)
    if len(result) > MAX_TAGS:
        raise EntryValidationError(f"Une entrée ne peut pas avoir plus de {MAX_TAGS} tags.")
    return tuple(result)


# --- Validation commune (écriture : erreur de saisie ; lecture : corruption) --------------


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_timestamp(value: object, error: type[Exception], what: str) -> str:
    if not isinstance(value, str):
        raise error(f"Date invalide : {what}.")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise error(f"Date invalide : {what}.") from exc
    if moment.tzinfo is None:
        raise error(f"Date sans fuseau horaire : {what}.")
    return value


def _check_entry(meta: EntryMetadata, error: type[Exception]) -> None:
    if not isinstance(meta.name, str) or not meta.name.strip():
        raise error("Nom d'entrée absent ou invalide.")
    for what, value in (("URL", meta.url), ("identifiant", meta.username)):
        if not isinstance(value, str):
            raise error(f"Champ invalide : {what}.")
    if meta.entry_type not in ENTRY_TYPE_KEYS:
        raise error("Type d'entrée inconnu.")
    if meta.category_id is not None and not (_is_int(meta.category_id) and meta.category_id > 0):
        raise error("Référence de catégorie invalide.")
    if not isinstance(meta.is_favorite, bool):
        raise error("Indicateur « favori » invalide.")
    if not isinstance(meta.tags, tuple):
        raise error("Liste de tags invalide.")
    try:
        canonical = normalize_tags(meta.tags)
    except EntryValidationError as exc:
        raise error("Liste de tags invalide.") from exc
    if canonical != meta.tags:
        raise error("Liste de tags non canonique.")
    for what in ("created_at", "updated_at", "password_changed_at"):
        _check_timestamp(getattr(meta, what), error, what)
    if meta.deleted_at is not None:
        _check_timestamp(meta.deleted_at, error, "deleted_at")


def _check_category(meta: CategoryMetadata, error: type[Exception]) -> None:
    if not isinstance(meta.name, str) or not meta.name.strip():
        raise error("Nom de catégorie absent ou invalide.")
    _check_timestamp(meta.created_at, error, "created_at")


# --- Sérialisation (JSON versionné + remplissage) ----------------------------------------


def _serialize(payload: dict) -> str:
    """JSON compact dont l'encodage UTF-8 a une longueur multiple de PAD_BLOCK."""
    payload = {**payload, "v": METADATA_VERSION, "pad": ""}
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    payload["pad"] = " " * (-len(text.encode("utf-8")) % PAD_BLOCK)
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("clé JSON en double")
        result[key] = value
    return result


def _parse(text: str, keys: frozenset[str], error: type[Exception]) -> dict:
    """JSON lu après déchiffrement : longueur, structure, version, remplissage."""
    if len(text.encode("utf-8")) % PAD_BLOCK:
        raise error("Longueur des métadonnées incohérente.")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:  # JSONDecodeError en hérite
        raise error("Métadonnées illisibles.") from exc
    if not isinstance(data, dict) or set(data) != keys:
        raise error("Structure des métadonnées invalide.")
    if not _is_int(data["v"]):
        raise error("Version des métadonnées invalide.")
    if data["v"] != METADATA_VERSION:
        raise error("Version des métadonnées non prise en charge.")
    pad = data["pad"]
    if not isinstance(pad, str) or pad.strip(" "):
        raise error("Remplissage des métadonnées invalide.")
    return data


# --- Chiffrement ------------------------------------------------------------------------


def new_vault_uuid() -> bytes:
    """Identité aléatoire et immuable d'un coffre (entre dans les AAD)."""
    return secrets.token_bytes(VAULT_UUID_SIZE)


def _check_id(value: object, what: str) -> int:
    if not (_is_int(value) and value > 0):
        raise ValueError(f"Identifiant de {what} invalide.")
    return value


class MetadataCipher:
    """Chiffre et déchiffre les métadonnées d'UN coffre (sous-clés dérivées une fois)."""

    __slots__ = ("_category_key", "_entry_key", "_uuid_hex")

    def __init__(self, dek: bytes, vault_uuid: bytes) -> None:
        if not isinstance(vault_uuid, bytes) or len(vault_uuid) != VAULT_UUID_SIZE:
            raise ValueError("Identité de coffre (vault_uuid) invalide.")
        self._uuid_hex = vault_uuid.hex()
        self._entry_key = crypto.derive_subkey(dek, ENTRY_METADATA_INFO)
        self._category_key = crypto.derive_subkey(dek, CATEGORY_INFO)

    def __repr__(self) -> str:
        return "MetadataCipher(…)"

    def entry_aad(self, entry_id: int) -> bytes:
        entry_id = _check_id(entry_id, "l'entrée")
        return f"mon-coffre-fort:entry-metadata:{self._uuid_hex}:{entry_id}".encode("ascii")

    def category_aad(self, category_id: int) -> bytes:
        category_id = _check_id(category_id, "la catégorie")
        return f"mon-coffre-fort:category:{self._uuid_hex}:{category_id}".encode("ascii")

    # --- Entrées -------------------------------------------------------------------

    def encrypt_entry(self, entry_id: int, meta: EntryMetadata) -> bytes:
        """Lève EntryValidationError si `meta` ne pourrait pas être relu tel quel."""
        _check_entry(meta, EntryValidationError)
        text = _serialize({
            "name": meta.name, "url": meta.url, "username": meta.username,
            "entry_type": meta.entry_type, "category_id": meta.category_id,
            "is_favorite": meta.is_favorite, "tags": list(meta.tags),
            "created_at": meta.created_at, "updated_at": meta.updated_at,
            "password_changed_at": meta.password_changed_at, "deleted_at": meta.deleted_at,
        })
        return crypto.encrypt_field(self._entry_key, text, self.entry_aad(entry_id))

    def decrypt_entry(self, entry_id: int, blob: object) -> EntryMetadata:
        """Lève EntryDecryptionError en cas d'altération, de substitution ou d'incohérence."""
        aad = self.entry_aad(entry_id)
        error = EntryDecryptionError
        try:
            if not isinstance(blob, bytes):
                raise ValueError("métadonnées absentes")
            text = crypto.decrypt_field(self._entry_key, blob, aad)
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise error(
                f"Les métadonnées chiffrées de l'entrée {entry_id} sont corrompues "
                "ou ont été altérées.") from exc
        data = _parse(text, _ENTRY_KEYS, error)
        tags = data["tags"]
        if not isinstance(tags, list):
            raise error("Liste de tags invalide.")
        meta = EntryMetadata(
            name=data["name"], url=data["url"], username=data["username"],
            entry_type=data["entry_type"], category_id=data["category_id"],
            is_favorite=data["is_favorite"], tags=tuple(tags),
            created_at=data["created_at"], updated_at=data["updated_at"],
            password_changed_at=data["password_changed_at"], deleted_at=data["deleted_at"],
        )
        _check_entry(meta, error)
        return meta

    # --- Catégories ----------------------------------------------------------------

    def encrypt_category(self, category_id: int, meta: CategoryMetadata) -> bytes:
        _check_category(meta, CategoryError)
        text = _serialize({"name": meta.name, "created_at": meta.created_at})
        return crypto.encrypt_field(self._category_key, text, self.category_aad(category_id))

    def decrypt_category(self, category_id: int, blob: object) -> CategoryMetadata:
        """Lève CategoryDecryptionError en cas d'altération, de substitution ou d'incohérence."""
        aad = self.category_aad(category_id)
        error = CategoryDecryptionError
        try:
            if not isinstance(blob, bytes):
                raise ValueError("nom absent")
            text = crypto.decrypt_field(self._category_key, blob, aad)
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise error(
                f"Le nom chiffré de la catégorie {category_id} est corrompu "
                "ou a été altéré.") from exc
        data = _parse(text, _CATEGORY_KEYS, error)
        meta = CategoryMetadata(name=data["name"], created_at=data["created_at"])
        _check_category(meta, error)
        return meta
