"""Vault entries: types, field encryption, CRUD, search, favorites.

This layer is the only one that handles both the vault data key (DEK) and
plaintext entries. The UI only calls `EntryService`; the database
(`app.database`) only sees encrypted BLOBs.

Encryption of sensitive fields
------------------------------
Each sensitive field (email, password, notes, type-specific fields) is
encrypted individually with AES-256-GCM, using the DEK and **associated
data** (AAD) that binds the ciphertext to *its* entry and *its* field:

    AAD = "mon-coffre-fort:entry:<id>:<field>"

Moving an encrypted BLOB from one entry to another, or from one column to
another (e.g. copying the `password_enc` of a bank account into the notes of
another entry), therefore makes authentication fail instead of silently
revealing the value elsewhere. Empty fields are encrypted too, so that the
disk does not reveal which entries have a password, notes, etc.

Metadata (schema v4)
--------------------
Name, URL, username, type, category, favorite, tags and dates are no longer
in plaintext: they form one encrypted JSON document per entry
(app.core.metadata), decrypted once per session into the vault cache
(`Vault.metadata`). Listing, search, filters and sorting are done in memory
on this cache. Secrets stay encrypted field by field, directly under the
DEK, as before (decision D2).

History and Trash
-----------------
* Before every change to the content of an entry, the complete previous
  version is kept in `entry_history`, as encrypted JSON
  (AAD = "mon-coffre-fort:history:<entry>:<version>"). At most
  `MAX_HISTORY_VERSIONS` versions per entry; the oldest are deleted.
* Deleting an entry moves it to the Trash; it can be restored or deleted
  permanently (together with its history).
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
from app.i18n import tr
from app.utils.logging import get_logger

MAX_SERVICE_NAME_LENGTH = 200
MAX_SHORT_FIELD_LENGTH = 2048
MAX_HISTORY_VERSIONS = 20
DEFAULT_TRASH_RETENTION_DAYS = 30

# --- Entry types -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Type-specific field of an entry (stored encrypted in extra_fields_enc)."""

    key: str
    label_key: str  # translation key of the label (app/i18n)
    secret: bool = False  # hidden by default in the interface

    @property
    def label(self) -> str:
        return tr(self.label_key)


@dataclass(frozen=True, slots=True)
class EntryTypeSpec:
    key: str
    label_key: str  # translation keys (app/i18n): labels follow the interface language
    uses_url: bool = True
    uses_username: bool = True
    uses_email: bool = True
    uses_password: bool = True
    password_label_key: str = "field.password"  # noqa: S105 - translation key
    extra_fields: tuple[FieldSpec, ...] = ()

    @property
    def label(self) -> str:
        return tr(self.label_key)

    @property
    def password_label(self) -> str:
        return tr(self.password_label_key)


ENTRY_TYPES: dict[str, EntryTypeSpec] = {
    spec.key: spec
    for spec in (
        EntryTypeSpec("login", "entry_type.login"),
        EntryTypeSpec(
            "secure_note", "entry_type.secure_note",
            uses_url=False, uses_username=False, uses_email=False, uses_password=False,
        ),
        EntryTypeSpec(
            "card", "entry_type.card",
            uses_url=False, uses_username=False, uses_email=False, uses_password=False,
            extra_fields=(
                FieldSpec("cardholder", "field.cardholder"),
                FieldSpec("card_number", "field.card_number", secret=True),
                FieldSpec("expiry", "field.expiry"),
                FieldSpec("cvv", "field.cvv", secret=True),
                FieldSpec("pin", "field.pin", secret=True),
            ),
        ),
        EntryTypeSpec(
            "identity", "entry_type.identity",
            uses_url=False, uses_username=False, uses_password=False,
            extra_fields=(
                FieldSpec("full_name", "field.full_name"),
                FieldSpec("birth_date", "field.birth_date"),
                FieldSpec("phone", "field.phone"),
                FieldSpec("address", "field.address"),
                FieldSpec("id_number", "field.id_number", secret=True),
            ),
        ),
        EntryTypeSpec(
            "wifi", "entry_type.wifi",
            uses_url=False, uses_username=False, uses_email=False,
            password_label_key="field.wifi_key",  # noqa: S106 - translation key
            extra_fields=(
                FieldSpec("ssid", "field.ssid"),
                FieldSpec("security", "field.wifi_security"),
            ),
        ),
        EntryTypeSpec(
            "server", "entry_type.server",
            uses_email=False,
            extra_fields=(
                FieldSpec("hostname", "field.hostname"),
                FieldSpec("port", "field.port"),
                FieldSpec("protocol", "field.protocol"),
            ),
        ),
    )
}

DEFAULT_ENTRY_TYPE = "login"

# --- Objects handled by the application ----------------------------------------------


@dataclass(slots=True)
class Entry:
    """Complete, decrypted entry. Exists only in memory, while the vault is unlocked."""

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

    def __repr__(self) -> str:  # never a secret in a repr (logs, tracebacks)
        return (
            f"Entry(id={self.id!r}, entry_type={self.entry_type!r}, "
            f"service_name={self.service_name!r})"
        )


@dataclass(frozen=True, slots=True)
class EntrySummary:
    """View of an entry for lists: metadata only, no secret.

    This metadata (name, URL, username, category, tags…) is not secret in the
    functional sense (it is displayed), but it is encrypted at rest (v4); a
    summary exists only in memory, while the vault is unlocked.
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
    """Previous version of an entry, decrypted (unlocked vault)."""

    id: int
    replaced_at: str            # date on which this version was replaced
    entry: Entry                # complete content of the version
    changed: tuple[str, ...]    # labels of the fields changed by the next version


# Special filter value: uncategorized entries.
UNCATEGORIZED = -1


@dataclass(frozen=True, slots=True)
class EntryFilter:
    """List criteria. `category_id=UNCATEGORIZED` => uncategorized entries."""

    text: str = ""
    category_id: int | None = None
    favorites_only: bool = False
    in_trash: bool = False


def normalize_for_search(value: str) -> str:
    """Lowercase + accents removed: "Éléphant" == "elephant"."""
    decomposed = unicodedata.normalize("NFKD", value)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return stripped.casefold()


# `#tag` (no space) or `#"tag with spaces"` at the start of a word. The closing quote
# must be followed by a space or the end of the text: a tag may contain '"'.
_TAG_TERM = re.compile(r'(?:^|(?<=\s))#(?:"(.*?)"(?=\s|$)|(\S*))')


def parse_search(text: str) -> tuple[list[str], set[str]]:
    """Search text -> (normalized free terms, `tag_key` keys of the `#tag` terms).

    `#tag`: EXACT match with a tag of the entry, ignoring case and accents
    (rules of app.core.metadata.tag_key). A lone "#" is ignored; a "#" in the
    middle of a word ("C#") is ordinary text.
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
    """Search that selects exactly the entries carrying `tag` (click on a badge)."""
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
    """Content compared for the history (the favorite status is not part of it)."""
    return (entry.entry_type, entry.service_name, entry.url, entry.username, entry.email,
            entry.password, entry.notes, tuple(sorted(entry.extra.items())), entry.category_id,
            tuple(entry.tags))


def changed_field_labels(old: Entry, new: Entry) -> tuple[str, ...]:
    spec = ENTRY_TYPES.get(new.entry_type) or ENTRY_TYPES[DEFAULT_ENTRY_TYPE]
    labels = []
    for label, a, b in (
        (tr("field.name"), old.service_name, new.service_name),
        (tr("field.url"), old.url, new.url),
        (tr("field.username"), old.username, new.username),
        (tr("field.email"), old.email, new.email),
        (spec.password_label, old.password, new.password),
        (tr("field.notes"), old.notes, new.notes),
        (tr("field.category"), old.category_id, new.category_id),
        (tr("field.tags"), tuple(old.tags), tuple(new.tags)),
    ):
        if a != b:
            labels.append(label)
    for field_spec in spec.extra_fields:
        if old.extra.get(field_spec.key, "") != new.extra.get(field_spec.key, ""):
            labels.append(field_spec.label)
    return tuple(labels)


class EntryService:
    """CRUD of the entries of an unlocked v4 vault (metadata through `Vault.metadata`)."""

    def __init__(self, vault: Vault) -> None:
        self._vault = vault
        self._conn = vault.connection
        self._entries = EntryRepository(self._conn)
        self._history = HistoryRepository(self._conn)
        self._logger = get_logger()

    @property
    def _store(self):
        return self._vault.metadata  # VaultLockedError if the vault is locked

    # --- Reading ---------------------------------------------------------------

    def list_entries(self, flt: EntryFilter | None = None) -> list[EntrySummary]:
        """Sorted list (alphabetical, case- and accent-insensitive).

        Computed in memory from the decrypted metadata (session cache): no
        secret is decrypted. Unreadable entries are reported separately
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
        if flt.in_trash:  # Trash: most recently deleted first
            result.sort(key=lambda s: (s.deleted_at, s.id), reverse=True)
        else:
            result.sort(key=lambda s: (normalize_for_search(s.service_name), s.id))
        return result

    def all_tags(self) -> tuple[str, ...]:
        """Tags of the active, readable entries (completion), one per `tag_key`.

        Displayed form: the most frequent one (on a tie, the first in code-point
        order). Recomputed on every call from the session cache: nothing is kept here.
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
        """Entries whose encrypted metadata has been tampered with (active or in the Trash)."""
        return sorted(self._store.unreadable())

    def get_entry(self, entry_id: int, include_deleted: bool = False) -> Entry:
        """Returns the complete entry, with its sensitive fields decrypted."""
        key = self._vault._require_unlocked_key()
        meta = self._store.entry(entry_id)  # EntryNotFoundError / EntryDecryptionError
        if meta.deleted_at is not None and not include_deleted:
            raise EntryNotFoundError(tr("entries.error.not_found", id=entry_id))
        blobs = self._entries.get_secret_blobs(entry_id)
        if blobs is None:
            raise EntryNotFoundError(tr("entries.error.not_found", id=entry_id))
        email, password, notes, extra_json = (
            self._decrypt(key, entry_id, column, blob)
            for column, blob in zip(_SECRET_COLUMNS, blobs, strict=True))
        try:
            extra = json.loads(extra_json) if extra_json else {}
        except json.JSONDecodeError as exc:
            raise EntryDecryptionError(tr("entries.error.extra_unreadable")) from exc
        if not isinstance(extra, dict):
            raise EntryDecryptionError(tr("entries.error.extra_invalid"))
        return Entry(
            id=entry_id, entry_type=meta.entry_type, service_name=meta.name, url=meta.url,
            username=meta.username, email=email, password=password, notes=notes,
            extra={str(k): str(v) for k, v in extra.items()}, category_id=meta.category_id,
            is_favorite=meta.is_favorite, created_at=meta.created_at,
            updated_at=meta.updated_at, password_changed_at=meta.password_changed_at,
            deleted_at=meta.deleted_at or "", tags=meta.tags,
        )

    # --- Writing --------------------------------------------------------------

    def validate_entry(self, entry: Entry) -> None:
        """Raises EntryValidationError if the entry cannot be saved."""
        self._validate(entry)

    def create_entry(self, entry: Entry) -> int:
        key = self._vault._require_unlocked_key()
        self._validate(entry)
        with self._conn:  # atomic transaction: identifier + encrypted blobs
            entry_id = self._insert(entry, key, _utc_now_iso())
        self._logger.info("Entry created: id=%d", entry_id)
        return entry_id

    def import_entries(self, entries: list[Entry]) -> list[int]:
        """Creates several entries in **a single** transaction (all or nothing)."""
        key = self._vault._require_unlocked_key()
        for entry in entries:
            self._validate(entry)
        now = _utc_now_iso()
        with self._conn:
            ids = [self._insert(entry, key, now) for entry in entries]
        self._logger.info("Entries imported: %d", len(ids))
        return ids

    def update_entry(self, entry: Entry) -> None:
        """Saves a modification; the previous version goes into the history."""
        key = self._vault._require_unlocked_key()
        if entry.id is None:
            raise EntryValidationError(tr("entries.error.no_identifier"))
        previous = self.get_entry(entry.id)  # active entry only
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
        with self._conn:  # history + update: all or nothing
            self._save_history(previous, key, replaced_at=now)
            self._write_secrets(entry.id, new, key)
            self._store.write_entry(entry.id, meta)
        self._logger.info("Entry updated: id=%d", entry.id)

    def set_favorite(self, entry_id: int, is_favorite: bool) -> None:
        """The favorite does not create a history version (D7)."""
        meta = self._active_meta(entry_id)
        with self._conn:
            self._store.write_entry(entry_id, dataclasses.replace(meta, is_favorite=is_favorite))

    def duplicate_entry(self, entry_id: int) -> int:
        """Copy of an entry ("Name (copy)"), without its history or favorite status."""
        source = self.get_entry(entry_id)
        suffix = tr("entries.copy_suffix")
        source.service_name = source.service_name[:MAX_SERVICE_NAME_LENGTH - len(suffix)] + suffix
        source.id = None
        source.is_favorite = False
        return self.create_entry(source)

    # --- Trash -------------------------------------------------------------

    def delete_entry(self, entry_id: int) -> None:
        """Moves the entry to the Trash (restorable)."""
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
            raise EntryNotFoundError(tr("entries.error.not_in_trash", id=entry_id))
        # A category deleted in the meantime has already been removed from the metadata.
        with self._conn:
            self._store.write_entry(entry_id, dataclasses.replace(meta, deleted_at=None))
        self._logger.info("Entry restored from trash: id=%d", entry_id)

    def delete_permanently(self, entry_id: int) -> None:
        """Permanent deletion, history included (pages erased: secure_delete)."""
        self._vault._require_unlocked_key()
        with self._conn:
            found = self._entries.delete_permanently(entry_id)  # history: ON DELETE CASCADE
            self._store.invalidate_entry(entry_id)
        if not found:
            raise EntryNotFoundError(tr("entries.error.not_found", id=entry_id))
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
        """Permanently deletes the entries that have been in the Trash for more than N days.

        The deletion date is read from the ENCRYPTED metadata: it can no longer
        be forged on disk to trigger a purge.
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

    # --- History -----------------------------------------------------------

    def history_count(self, entry_id: int) -> int:
        self._vault._require_unlocked_key()
        return self._history.count_for_entry(entry_id)

    def list_history(self, entry_id: int) -> list[HistoryVersion]:
        """Previous versions, most recent first."""
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
        """Restores a version; the current version itself goes into the history.

        Favorite: the current one is kept (it is not part of the versions).
        Tags: those of the version (format v2); a v1 version had none, so the
        current tags are kept.
        """
        key = self._vault._require_unlocked_key()
        record = self._history.get(history_id)
        if record is None:
            raise EntryNotFoundError(tr("entries.error.version_not_found"))
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

    # --- Internal ---------------------------------------------------------------

    def _active_meta(self, entry_id: int) -> EntryMetadata:
        self._vault._require_unlocked_key()
        meta = self._store.entry(entry_id)
        if meta.deleted_at is not None:
            raise EntryNotFoundError(tr("entries.error.not_found", id=entry_id))
        return meta

    def _validate(self, entry: Entry) -> None:
        spec = ENTRY_TYPES.get(entry.entry_type)
        if spec is None:
            raise EntryValidationError(
                tr("entries.error.unknown_type", type=repr(entry.entry_type)))
        name = entry.service_name.strip()
        if not name:
            raise EntryValidationError(tr("entries.error.name_required"))
        if len(name) > MAX_SERVICE_NAME_LENGTH:
            raise EntryValidationError(
                tr("entries.error.name_too_long", max=MAX_SERVICE_NAME_LENGTH))
        for message, value in (("entries.error.url_too_long", entry.url),
                               ("entries.error.username_too_long", entry.username)):
            if len(value) > MAX_SHORT_FIELD_LENGTH:
                raise EntryValidationError(tr(message))
        if entry.category_id is not None and entry.category_id not in self._store.categories():
            raise EntryValidationError(tr("entries.error.category_gone"))
        allowed = {f.key for f in spec.extra_fields}
        unknown = set(entry.extra) - allowed
        if unknown:
            raise EntryValidationError(
                tr("entries.error.unsupported_fields", fields=", ".join(sorted(unknown))))
        normalize_tags(entry.tags)  # EntryValidationError if invalid

    @staticmethod
    def _normalized(entry: Entry) -> Entry:
        """Stored form of an entry (whitespace trimmed, unused fields emptied)."""
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
        """Insert without commit (the caller delimits the transaction)."""
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
            raise EntryNotFoundError(tr("entries.error.not_found", id=entry_id))

    def _save_history(self, previous: Entry, key: bytes, replaced_at: str) -> None:
        if previous.id is None:
            raise EntryValidationError(tr("entries.error.version_no_identifier"))
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
        """History version -> Entry. Format v1 (no tags, no favorite): those of the
        more recent version are reused, so that no false change is displayed."""
        try:
            if not blob:
                raise ValueError("empty version")
            content = parse_snapshot(json.loads(crypto.decrypt_field(
                key, blob, _history_aad(entry_id, history_id))))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise EntryDecryptionError(
                tr("entries.error.version_corrupted", id=entry_id)) from exc
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
        """NULL or tampered blob: corruption (never a silent empty value)."""
        try:
            if not blob:
                raise ValueError("missing encrypted field")
            return crypto.decrypt_field(key, blob, _aad(entry_id, column))
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise EntryDecryptionError(
                tr("entries.error.field_corrupted", field=column, id=entry_id)) from exc
