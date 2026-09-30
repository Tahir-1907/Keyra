"""Entrées du coffre : types, chiffrement des champs, CRUD, recherche, favoris.

Cette couche est la seule à manipuler à la fois la clé de données (DEK) du
coffre et les entrées en clair. L'UI ne fait qu'appeler `EntryService` ;
la base (`app.database`) ne voit que des BLOB chiffrés.

Chiffrement des champs sensibles
--------------------------------
Chaque champ sensible (email, mot de passe, notes, champs spécifiques au
type) est chiffré individuellement en AES-256-GCM avec la DEK et une
**donnée associée** (AAD) qui lie le chiffré à *son* entrée et à *son*
champ :

    AAD = "mon-coffre-fort:entry:<id>:<champ>"

Déplacer un BLOB chiffré d'une entrée à une autre, ou d'une colonne à une
autre (ex. copier le `password_enc` d'un compte bancaire dans les notes
d'une autre entrée), fait donc échouer l'authentification au lieu de
révéler silencieusement la valeur ailleurs. Les champs vides sont eux aussi
chiffrés, pour ne pas révéler sur disque quelles entrées ont un mot de
passe, des notes, etc.

Métadonnées (schéma v4)
-----------------------
Nom, URL, identifiant, type, catégorie, favori, tags et dates ne sont plus en
clair : ils forment un JSON chiffré par entrée (app.core.metadata), déchiffré
une fois par session dans le cache du coffre (`Vault.metadata`). Liste,
recherche, filtres et tri se font en mémoire sur ce cache. Les secrets restent
chiffrés champ par champ, directement sous la DEK, comme avant (décision D2).

Historique et corbeille
-----------------------
* Avant chaque modification du contenu d'une entrée, la version précédente
  complète est conservée dans `entry_history`, sous forme d'un JSON chiffré
  (AAD = "mon-coffre-fort:history:<entrée>:<version>"). Au plus
  `MAX_HISTORY_VERSIONS` versions par entrée ; les plus anciennes sont
  supprimées.
* Supprimer une entrée la place dans la corbeille ; elle peut être
  restaurée ou supprimée définitivement (avec son historique).
"""

from __future__ import annotations

import dataclasses
import json
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.core import crypto
from app.core.exceptions import (
    EntryDecryptionError,
    EntryNotFoundError,
    EntryValidationError,
)
from app.core.metadata import EntryMetadata, normalize_tags, tag_key
from app.core.snapshots import SnapshotContent, build_snapshot, parse_snapshot
from app.core.vault import Vault, _utc_now_iso
from app.database.repositories import EntryRepository, HistoryRepository
from app.utils.logging import get_logger

MAX_SERVICE_NAME_LENGTH = 200
MAX_SHORT_FIELD_LENGTH = 2048
MAX_HISTORY_VERSIONS = 20
DEFAULT_TRASH_RETENTION_DAYS = 30

# --- Types d'entrées -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Champ spécifique à un type d'entrée (stocké chiffré dans extra_fields_enc)."""

    key: str
    label: str
    secret: bool = False  # masqué par défaut dans l'interface


@dataclass(frozen=True, slots=True)
class EntryTypeSpec:
    key: str
    label: str
    uses_url: bool = True
    uses_username: bool = True
    uses_email: bool = True
    uses_password: bool = True
    password_label: str = "Mot de passe"  # noqa: S105 - libellé affiché
    extra_fields: tuple[FieldSpec, ...] = ()


ENTRY_TYPES: dict[str, EntryTypeSpec] = {
    spec.key: spec
    for spec in (
        EntryTypeSpec("login", "Identifiant"),
        EntryTypeSpec(
            "secure_note", "Note sécurisée",
            uses_url=False, uses_username=False, uses_email=False, uses_password=False,
        ),
        EntryTypeSpec(
            "card", "Carte bancaire",
            uses_url=False, uses_username=False, uses_email=False, uses_password=False,
            extra_fields=(
                FieldSpec("cardholder", "Titulaire"),
                FieldSpec("card_number", "Numéro de carte", secret=True),
                FieldSpec("expiry", "Expiration (MM/AA)"),
                FieldSpec("cvv", "Cryptogramme (CVV)", secret=True),
                FieldSpec("pin", "Code PIN", secret=True),
            ),
        ),
        EntryTypeSpec(
            "identity", "Identité",
            uses_url=False, uses_username=False, uses_password=False,
            extra_fields=(
                FieldSpec("full_name", "Nom complet"),
                FieldSpec("birth_date", "Date de naissance"),
                FieldSpec("phone", "Téléphone"),
                FieldSpec("address", "Adresse"),
                FieldSpec("id_number", "N° de pièce d'identité", secret=True),
            ),
        ),
        EntryTypeSpec(
            "wifi", "Réseau Wi-Fi",
            uses_url=False, uses_username=False, uses_email=False,
            password_label="Clé Wi-Fi",  # noqa: S106 - libellé affiché
            extra_fields=(
                FieldSpec("ssid", "SSID"),
                FieldSpec("security", "Sécurité (WPA2, WPA3...)"),
            ),
        ),
        EntryTypeSpec(
            "server", "Serveur",
            uses_email=False,
            extra_fields=(
                FieldSpec("hostname", "Hôte / adresse IP"),
                FieldSpec("port", "Port"),
                FieldSpec("protocol", "Protocole (SSH, RDP...)"),
            ),
        ),
    )
}

DEFAULT_ENTRY_TYPE = "login"

# --- Objets manipulés par l'application ----------------------------------------------


@dataclass(slots=True)
class Entry:
    """Entrée complète, déchiffrée. N'existe qu'en mémoire, coffre déverrouillé."""

    service_name: str
    entry_type: str = DEFAULT_ENTRY_TYPE
    url: str = ""
    username: str = ""
    email: str = ""
    password: str = ""
    notes: str = ""
    extra: dict[str, str] = field(default_factory=dict)
    category_id: int | None = None
    is_favorite: bool = False
    id: int | None = None
    created_at: str = ""
    updated_at: str = ""
    password_changed_at: str = ""
    deleted_at: str = ""
    tags: tuple[str, ...] = ()

    def __repr__(self) -> str:  # jamais de secret dans un repr (logs, tracebacks)
        return (
            f"Entry(id={self.id!r}, entry_type={self.entry_type!r}, "
            f"service_name={self.service_name!r})"
        )


@dataclass(frozen=True, slots=True)
class EntrySummary:
    """Vue d'une entrée pour les listes : uniquement des métadonnées, aucun secret.

    Ces métadonnées (nom, URL, identifiant, catégorie, tags…) ne sont pas des secrets
    au sens fonctionnel (elles sont affichées), mais elles sont chiffrées au repos (v4) ;
    un résumé n'existe qu'en mémoire, coffre déverrouillé.
    """

    id: int
    entry_type: str
    service_name: str
    username: str
    url: str
    category_id: int | None
    category_name: str
    is_favorite: bool
    updated_at: str
    deleted_at: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HistoryVersion:
    """Version précédente d'une entrée, déchiffrée (coffre déverrouillé)."""

    id: int
    replaced_at: str            # date à laquelle cette version a été remplacée
    entry: Entry                # contenu complet de la version
    changed: tuple[str, ...]    # libellés des champs modifiés par la version suivante


# Valeur spéciale de filtre : entrées sans catégorie.
UNCATEGORIZED = -1


@dataclass(frozen=True, slots=True)
class EntryFilter:
    """Critères de liste. `category_id=UNCATEGORIZED` => entrées sans catégorie."""

    text: str = ""
    category_id: int | None = None
    favorites_only: bool = False
    in_trash: bool = False


def normalize_for_search(value: str) -> str:
    """Minuscules + suppression des accents : « Éléphant » == « elephant »."""
    decomposed = unicodedata.normalize("NFKD", value)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return stripped.casefold()


# `#tag` (sans espace) ou `#"tag avec espaces"` en début de mot. Le guillemet fermant
# doit être suivi d'un espace ou de la fin du texte : un tag peut contenir « " ».
_TAG_TERM = re.compile(r'(?:^|(?<=\s))#(?:"(.*?)"(?=\s|$)|(\S*))')


def parse_search(text: str) -> tuple[list[str], set[str]]:
    """Texte de recherche -> (termes libres normalisés, clés `tag_key` des `#tag`).

    `#tag` : correspondance EXACTE avec un tag de l'entrée, casse et accents ignorés
    (règles de app.core.metadata.tag_key). Un « # » seul est ignoré ; un « # » au
    milieu d'un mot (« C# ») est du texte ordinaire.
    """
    tags: set[str] = set()

    def take(match: re.Match) -> str:
        value = match.group(1) if match.group(1) is not None else match.group(2)
        value = " ".join(value.split())
        if value:
            tags.add(tag_key(value))
        return " "

    rest = _TAG_TERM.sub(take, text)
    return normalize_for_search(rest).split(), tags


def tag_search_query(tag: str) -> str:
    """Recherche qui sélectionne exactement les entrées portant `tag` (clic sur un badge)."""
    quoted = tag.startswith('"') or any(c.isspace() for c in tag)
    return f'#"{tag}"' if quoted else f"#{tag}"


def summary_matches(summary: EntrySummary, flt: EntryFilter) -> bool:
    if flt.favorites_only and not summary.is_favorite:
        return False
    if flt.category_id is not None:
        if flt.category_id == UNCATEGORIZED:
            if summary.category_id is not None:
                return False
        elif summary.category_id != flt.category_id:
            return False
    terms, wanted_tags = parse_search(flt.text)
    if wanted_tags and not wanted_tags <= {tag_key(t) for t in summary.tags}:
        return False
    if not terms:
        return True
    haystack = normalize_for_search(
        " ".join(
            (summary.service_name, summary.username, summary.url, summary.category_name,
             *summary.tags)
        )
    )
    return all(term in haystack for term in terms)


# --- Service --------------------------------------------------------------------------


_SECRET_COLUMNS = ("email", "password", "notes", "extra")


def _aad(entry_id: int, column: str) -> bytes:
    return f"mon-coffre-fort:entry:{entry_id}:{column}".encode("ascii")


def _history_aad(entry_id: int, history_id: int) -> bytes:
    return f"mon-coffre-fort:history:{entry_id}:{history_id}".encode("ascii")


def _content(entry: Entry) -> tuple:
    """Contenu comparé pour l'historique (le statut favori n'en fait pas partie)."""
    return (entry.entry_type, entry.service_name, entry.url, entry.username, entry.email,
            entry.password, entry.notes, tuple(sorted(entry.extra.items())), entry.category_id,
            tuple(entry.tags))


def changed_field_labels(old: Entry, new: Entry) -> tuple[str, ...]:
    spec = ENTRY_TYPES.get(new.entry_type) or ENTRY_TYPES[DEFAULT_ENTRY_TYPE]
    labels = []
    for label, a, b in (
        ("Nom", old.service_name, new.service_name),
        ("URL", old.url, new.url),
        ("Nom d'utilisateur", old.username, new.username),
        ("Email", old.email, new.email),
        (spec.password_label, old.password, new.password),
        ("Notes", old.notes, new.notes),
        ("Catégorie", old.category_id, new.category_id),
        ("Tags", tuple(old.tags), tuple(new.tags)),
    ):
        if a != b:
            labels.append(label)
    for field_spec in spec.extra_fields:
        if old.extra.get(field_spec.key, "") != new.extra.get(field_spec.key, ""):
            labels.append(field_spec.label)
    return tuple(labels)


class EntryService:
    """CRUD des entrées d'un coffre v4 déverrouillé (métadonnées via `Vault.metadata`)."""

    def __init__(self, vault: Vault) -> None:
        self._vault = vault
        self._conn = vault.connection
        self._entries = EntryRepository(self._conn)
        self._history = HistoryRepository(self._conn)
        self._logger = get_logger()

    @property
    def _store(self):
        return self._vault.metadata  # VaultLockedError si le coffre est verrouillé

    # --- Lecture ---------------------------------------------------------------

    def list_entries(self, flt: EntryFilter | None = None) -> list[EntrySummary]:
        """Liste triée (ordre alphabétique insensible à la casse/aux accents).

        Calculée en mémoire à partir des métadonnées déchiffrées (cache de session) :
        aucun secret n'est déchiffré. Les entrées illisibles sont signalées à part
        (`unreadable_entries`).
        """
        flt = flt or EntryFilter()
        store = self._store
        result = []
        for entry_id, meta in store.entries().items():
            if (meta.deleted_at is not None) != flt.in_trash:
                continue
            summary = EntrySummary(
                id=entry_id, entry_type=meta.entry_type, service_name=meta.name,
                username=meta.username, url=meta.url, category_id=meta.category_id,
                category_name=store.category_name(meta.category_id),
                is_favorite=meta.is_favorite, updated_at=meta.updated_at,
                deleted_at=meta.deleted_at or "", tags=meta.tags,
            )
            if summary_matches(summary, flt):
                result.append(summary)
        if flt.in_trash:  # corbeille : dernières suppressions en premier
            result.sort(key=lambda s: (s.deleted_at, s.id), reverse=True)
        else:
            result.sort(key=lambda s: (normalize_for_search(s.service_name), s.id))
        return result

    def all_tags(self) -> tuple[str, ...]:
        """Tags des entrées actives et lisibles (complétion), un par `tag_key`.

        Forme affichée : la plus fréquente (à égalité, la première par ordre de code).
        Recalculé à chaque appel depuis le cache de session : rien n'est conservé ici.
        """
        forms: dict[str, Counter[str]] = {}
        for meta in self._store.entries().values():
            if meta.deleted_at is None:
                for tag in meta.tags:
                    forms.setdefault(tag_key(tag), Counter())[tag] += 1
        return tuple(
            min(counter, key=lambda form: (-counter[form], form))
            for _key, counter in sorted(forms.items()))

    def unreadable_entries(self) -> list[int]:
        """Entrées dont les métadonnées chiffrées sont altérées (actives ou corbeille)."""
        return sorted(self._store.unreadable())

    def get_entry(self, entry_id: int, include_deleted: bool = False) -> Entry:
        """Retourne l'entrée complète, champs sensibles déchiffrés."""
        key = self._vault._require_unlocked_key()
        meta = self._store.entry(entry_id)  # EntryNotFoundError / EntryDecryptionError
        if meta.deleted_at is not None and not include_deleted:
            raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")
        blobs = self._entries.get_secret_blobs(entry_id)
        if blobs is None:
            raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")
        email, password, notes, extra_json = (
            self._decrypt(key, entry_id, column, blob)
            for column, blob in zip(_SECRET_COLUMNS, blobs, strict=True))
        try:
            extra = json.loads(extra_json) if extra_json else {}
        except json.JSONDecodeError as exc:
            raise EntryDecryptionError("Champs additionnels illisibles.") from exc
        if not isinstance(extra, dict):
            raise EntryDecryptionError("Champs additionnels invalides.")
        return Entry(
            id=entry_id, entry_type=meta.entry_type, service_name=meta.name, url=meta.url,
            username=meta.username, email=email, password=password, notes=notes,
            extra={str(k): str(v) for k, v in extra.items()}, category_id=meta.category_id,
            is_favorite=meta.is_favorite, created_at=meta.created_at,
            updated_at=meta.updated_at, password_changed_at=meta.password_changed_at,
            deleted_at=meta.deleted_at or "", tags=meta.tags,
        )

    # --- Écriture --------------------------------------------------------------

    def validate_entry(self, entry: Entry) -> None:
        """Lève EntryValidationError si l'entrée ne peut pas être enregistrée."""
        self._validate(entry)

    def create_entry(self, entry: Entry) -> int:
        key = self._vault._require_unlocked_key()
        self._validate(entry)
        with self._conn:  # transaction atomique : identifiant + blobs chiffrés
            entry_id = self._insert(entry, key, _utc_now_iso())
        self._logger.info("Entry created: id=%d", entry_id)
        return entry_id

    def import_entries(self, entries: list[Entry]) -> list[int]:
        """Crée plusieurs entrées en **une seule** transaction (tout ou rien)."""
        key = self._vault._require_unlocked_key()
        for entry in entries:
            self._validate(entry)
        now = _utc_now_iso()
        with self._conn:
            ids = [self._insert(entry, key, now) for entry in entries]
        self._logger.info("Entries imported: %d", len(ids))
        return ids

    def update_entry(self, entry: Entry) -> None:
        """Enregistre une modification ; la version précédente va dans l'historique."""
        key = self._vault._require_unlocked_key()
        if entry.id is None:
            raise EntryValidationError("Impossible de modifier une entrée sans identifiant.")
        previous = self.get_entry(entry.id)  # entrée active uniquement
        self._validate(entry)
        new = self._normalized(entry)
        new.id = entry.id
        if _content(new) == _content(previous):
            if new.is_favorite != previous.is_favorite:
                self.set_favorite(entry.id, new.is_favorite)
            return
        now = _utc_now_iso()
        meta = EntryMetadata(
            name=new.service_name, url=new.url, username=new.username,
            entry_type=new.entry_type, category_id=new.category_id,
            is_favorite=new.is_favorite, tags=new.tags, created_at=previous.created_at,
            updated_at=now,
            password_changed_at=(now if new.password != previous.password
                                 else previous.password_changed_at),
        )
        with self._conn:  # historique + mise à jour : tout ou rien
            self._save_history(previous, key, replaced_at=now)
            self._write_secrets(entry.id, new, key)
            self._store.write_entry(entry.id, meta)
        self._logger.info("Entry updated: id=%d", entry.id)

    def set_favorite(self, entry_id: int, is_favorite: bool) -> None:
        """Le favori ne crée pas de version d'historique (D7)."""
        meta = self._active_meta(entry_id)
        with self._conn:
            self._store.write_entry(entry_id, dataclasses.replace(meta, is_favorite=is_favorite))

    def duplicate_entry(self, entry_id: int) -> int:
        """Copie d'une entrée (« Nom (copie) »), sans son historique ni le statut favori."""
        source = self.get_entry(entry_id)
        suffix = " (copie)"
        source.service_name = source.service_name[:MAX_SERVICE_NAME_LENGTH - len(suffix)] + suffix
        source.id = None
        source.is_favorite = False
        return self.create_entry(source)

    # --- Corbeille -------------------------------------------------------------

    def delete_entry(self, entry_id: int) -> None:
        """Place l'entrée dans la corbeille (restaurable)."""
        meta = self._active_meta(entry_id)
        with self._conn:
            self._store.write_entry(entry_id, dataclasses.replace(meta, deleted_at=_utc_now_iso()))
        self._logger.info("Entry moved to trash: id=%d", entry_id)

    def restore_entry(self, entry_id: int) -> None:
        self._vault._require_unlocked_key()
        try:
            meta = self._store.entry(entry_id)
        except EntryNotFoundError:
            meta = None
        if meta is None or meta.deleted_at is None:
            raise EntryNotFoundError(f"Entrée {entry_id} absente de la corbeille.")
        # Une catégorie supprimée entre-temps a déjà été retirée des métadonnées.
        with self._conn:
            self._store.write_entry(entry_id, dataclasses.replace(meta, deleted_at=None))
        self._logger.info("Entry restored from trash: id=%d", entry_id)

    def delete_permanently(self, entry_id: int) -> None:
        """Suppression définitive, historique compris (pages effacées : secure_delete)."""
        self._vault._require_unlocked_key()
        with self._conn:
            found = self._entries.delete_permanently(entry_id)  # historique : ON DELETE CASCADE
            self._store.invalidate_entry(entry_id)
        if not found:
            raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")
        self._logger.info("Entry permanently deleted: id=%d", entry_id)

    def trash_count(self) -> int:
        return sum(1 for m in self._store.entries().values() if m.deleted_at is not None)

    def empty_trash(self) -> int:
        ids = [i for i, m in self._store.entries().items() if m.deleted_at is not None]
        with self._conn:
            for entry_id in ids:
                self._entries.delete_permanently(entry_id)
                self._store.invalidate_entry(entry_id)
        self._logger.info("Trash emptied: %d entries", len(ids))
        return len(ids)

    def purge_trash(self, retention_days: int = DEFAULT_TRASH_RETENTION_DAYS) -> int:
        """Supprime définitivement les entrées en corbeille depuis plus de N jours.

        La date de suppression est lue dans les métadonnées CHIFFRÉES : elle ne peut
        plus être falsifiée sur disque pour provoquer une purge.
        """
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        ids = [i for i, m in self._store.entries().items()
               if m.deleted_at is not None and datetime.fromisoformat(m.deleted_at) < cutoff]
        if ids:
            with self._conn:
                for entry_id in ids:
                    self._entries.delete_permanently(entry_id)
                    self._store.invalidate_entry(entry_id)
            self._logger.info("Trash purged: %d entries older than %d days", len(ids),
                              retention_days)
        return len(ids)

    # --- Historique -----------------------------------------------------------

    def history_count(self, entry_id: int) -> int:
        self._vault._require_unlocked_key()
        return self._history.count_for_entry(entry_id)

    def list_history(self, entry_id: int) -> list[HistoryVersion]:
        """Versions précédentes, de la plus récente à la plus ancienne."""
        key = self._vault._require_unlocked_key()
        current = self.get_entry(entry_id, include_deleted=True)
        versions: list[HistoryVersion] = []
        newer = current
        for record in self._history.list_for_entry(entry_id):
            snapshot = self._decrypt_snapshot(key, record.entry_id, record.id,
                                              record.snapshot_enc, newer)
            versions.append(HistoryVersion(
                id=record.id,
                replaced_at=record.created_at,
                entry=snapshot,
                changed=changed_field_labels(snapshot, newer),
            ))
            newer = snapshot
        return versions

    def restore_version(self, history_id: int) -> None:
        """Rétablit une version ; la version actuelle part elle-même dans l'historique.

        Favori : celui d'aujourd'hui est conservé (il ne fait pas partie des versions).
        Tags : ceux de la version (format v2) ; une version v1 n'en connaissait pas,
        les tags actuels sont alors conservés.
        """
        key = self._vault._require_unlocked_key()
        record = self._history.get(history_id)
        if record is None:
            raise EntryNotFoundError("Version introuvable.")
        current = self.get_entry(record.entry_id)
        snapshot = self._decrypt_snapshot(key, record.entry_id, record.id,
                                          record.snapshot_enc, current)
        snapshot.id = current.id
        snapshot.is_favorite = current.is_favorite
        if (snapshot.category_id is not None
                and snapshot.category_id not in self._store.categories()):
            snapshot.category_id = None
        self.update_entry(snapshot)
        self._logger.info("Entry version restored: id=%d", record.entry_id)

    def clear_history(self, entry_id: int) -> int:
        self._vault._require_unlocked_key()
        with self._conn:
            count = self._history.delete_for_entry(entry_id)
        self._logger.info("Entry history cleared: id=%d (%d versions)", entry_id, count)
        return count

    # --- Interne ---------------------------------------------------------------

    def _active_meta(self, entry_id: int) -> EntryMetadata:
        self._vault._require_unlocked_key()
        meta = self._store.entry(entry_id)
        if meta.deleted_at is not None:
            raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")
        return meta

    def _validate(self, entry: Entry) -> None:
        spec = ENTRY_TYPES.get(entry.entry_type)
        if spec is None:
            raise EntryValidationError(f"Type d'entrée inconnu : {entry.entry_type!r}.")
        name = entry.service_name.strip()
        if not name:
            raise EntryValidationError("Le nom de l'entrée est obligatoire.")
        if len(name) > MAX_SERVICE_NAME_LENGTH:
            raise EntryValidationError(
                f"Le nom de l'entrée ne doit pas dépasser {MAX_SERVICE_NAME_LENGTH} caractères."
            )
        for label, value in (("L'URL", entry.url), ("Le nom d'utilisateur", entry.username)):
            if len(value) > MAX_SHORT_FIELD_LENGTH:
                raise EntryValidationError(f"{label} est trop long.")
        if entry.category_id is not None and entry.category_id not in self._store.categories():
            raise EntryValidationError("La catégorie sélectionnée n'existe plus.")
        allowed = {f.key for f in spec.extra_fields}
        unknown = set(entry.extra) - allowed
        if unknown:
            raise EntryValidationError(
                f"Champs non prévus pour ce type d'entrée : {', '.join(sorted(unknown))}."
            )
        normalize_tags(entry.tags)  # EntryValidationError si invalides

    @staticmethod
    def _normalized(entry: Entry) -> Entry:
        """Forme stockée d'une entrée (espaces retirés, champs inutilisés vidés)."""
        spec = ENTRY_TYPES[entry.entry_type]
        extra = {f.key: entry.extra.get(f.key, "") for f in spec.extra_fields}
        return Entry(
            service_name=entry.service_name.strip(),
            entry_type=entry.entry_type,
            url=entry.url.strip() if spec.uses_url else "",
            username=entry.username.strip() if spec.uses_username else "",
            email=entry.email.strip() if spec.uses_email else "",
            password=entry.password if spec.uses_password else "",
            notes=entry.notes,
            extra={k: v for k, v in extra.items() if v},
            category_id=entry.category_id,
            is_favorite=entry.is_favorite,
            id=entry.id,
            tags=normalize_tags(entry.tags),
        )

    def _insert(self, entry: Entry, key: bytes, now: str) -> int:
        """Insertion sans commit (l'appelant délimite la transaction)."""
        normalized = self._normalized(entry)
        entry_id = self._entries.insert_v4_placeholder()
        self._write_secrets(entry_id, normalized, key)
        self._store.write_entry(entry_id, EntryMetadata(
            name=normalized.service_name, url=normalized.url, username=normalized.username,
            entry_type=normalized.entry_type, category_id=normalized.category_id,
            is_favorite=normalized.is_favorite, tags=normalized.tags, created_at=now,
            updated_at=now, password_changed_at=now,
        ))
        return entry_id

    def _write_secrets(self, entry_id: int, entry: Entry, key: bytes) -> None:
        spec = ENTRY_TYPES[entry.entry_type]
        extra = {f.key: entry.extra.get(f.key, "") for f in spec.extra_fields}
        extra = {k: v for k, v in extra.items() if v}
        values = {
            "email": entry.email.strip() if spec.uses_email else "",
            "password": entry.password if spec.uses_password else "",
            "notes": entry.notes,
            "extra": json.dumps(extra, ensure_ascii=False) if extra else "",
        }
        blobs = [crypto.encrypt_field(key, values[column], _aad(entry_id, column))
                 for column in _SECRET_COLUMNS]
        if not self._entries.set_secret_blobs(entry_id, *blobs):
            raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")

    def _save_history(self, previous: Entry, key: bytes, replaced_at: str) -> None:
        if previous.id is None:
            raise EntryValidationError("Version sans identifiant d'entrée.")
        payload = build_snapshot(SnapshotContent(
            version=2, entry_type=previous.entry_type, service_name=previous.service_name,
            url=previous.url, username=previous.username, email=previous.email,
            password=previous.password, notes=previous.notes, extra=previous.extra,
            category_id=previous.category_id, updated_at=previous.updated_at,
            password_changed_at=previous.password_changed_at, tags=tuple(previous.tags),
            is_favorite=previous.is_favorite,
        ))
        history_id = self._history.insert_placeholder(previous.id, replaced_at)
        self._history.set_snapshot(history_id, crypto.encrypt_field(
            key, json.dumps(payload, ensure_ascii=False), _history_aad(previous.id, history_id)))
        older = self._history.list_for_entry(previous.id)[MAX_HISTORY_VERSIONS:]
        if older:
            self._history.delete_ids([r.id for r in older])

    @staticmethod
    def _decrypt_snapshot(key: bytes, entry_id: int, history_id: int, blob: bytes | None,
                          newer: Entry) -> Entry:
        """Version d'historique -> Entry. Format v1 (sans tags ni favori) : ceux de la
        version plus récente sont repris, pour ne pas afficher de faux changement."""
        try:
            if not blob:
                raise ValueError("version vide")
            content = parse_snapshot(json.loads(crypto.decrypt_field(
                key, blob, _history_aad(entry_id, history_id))))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise EntryDecryptionError(
                f"Une version de l'historique de l'entrée {entry_id} est corrompue."
            ) from exc
        return Entry(
            id=entry_id, entry_type=content.entry_type, service_name=content.service_name,
            url=content.url, username=content.username, email=content.email,
            password=content.password, notes=content.notes, extra=content.extra,
            category_id=content.category_id, updated_at=content.updated_at,
            password_changed_at=content.password_changed_at,
            tags=content.tags if content.version >= 2 else tuple(newer.tags),
            is_favorite=(content.is_favorite if content.is_favorite is not None
                         else newer.is_favorite),
        )

    @staticmethod
    def _decrypt(key: bytes, entry_id: int, column: str, blob: bytes | None) -> str:
        """NULL ou blob altéré : corruption (jamais une valeur vide silencieuse)."""
        try:
            if not blob:
                raise ValueError("champ chiffré absent")
            return crypto.decrypt_field(key, blob, _aad(entry_id, column))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise EntryDecryptionError(
                f"Le champ chiffré « {column} » de l'entrée {entry_id} est "
                "corrompu ou a été altéré."
            ) from exc
