"""Import and export of entries.

Import (preview then confirmation, in a single transaction):
* CSV files exported by Bitwarden, KeePassXC, Chrome / Chromium / Edge /
  Brave, Firefox, a generic CSV, or this application's own CSV;
* this application's encrypted export (`.mcfexport`).

Export (the master password is **asked again**: a session left open is not
enough to export everything):
* encrypted `.mcfexport` — **recommended**: JSON encrypted with AES-256-GCM
  using an Argon2id key derived from an export password chosen by the user
  (independent from the vault, to transfer to another vault or machine);
* **unencrypted** CSV — to move to other software; the file contains every
  password in plaintext (explicit warning in the interface) and is created
  as 0600.

Entries in the Trash are never exported, and neither is the history.
KeePass `.kdbx` files are not read directly (that would require an extra
dependency): export them to CSV from KeePassXC first.

Compatibility: the format keys ("moncoffre"…), the "mon-coffre-fort-export"
container name and a few French input values written by versions 1.x
("oui", "racine", "catégorie", built-in category names) are still accepted
on import.
"""

from __future__ import annotations

import base64
import csv
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from app.core import crypto
from app.core.builtin_categories import builtin_key_for_name, every_builtin_name
from app.core.categories import CategoryService
from app.core.entries import ENTRY_TYPES, Entry, EntryService, normalize_for_search
from app.core.exceptions import (
    EntryValidationError,
    InvalidMasterPasswordPolicyError,
    VaultError,
    WrongMasterPasswordError,
)
from app.core.metadata import MAX_TAGS, normalize_tags, tag_key
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault
from app.i18n import tr
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger

MAX_IMPORT_FILE_SIZE = 20 * 1024 * 1024
EXPORT_SUFFIX = ".mcfexport"
_EXPORT_AAD = b"mon-coffre-fort:export:v1"
EXPORT_TEMP_PREFIX = ".tmp-export-"  # export temporaries (CSV, encrypted, PDF)

# Format key (technical, never translated) -> translation key of its label.
FORMAT_LABELS = {
    "moncoffre": "format.keyra_csv",
    "moncoffre_encrypted": "format.keyra_encrypted",
    "bitwarden": "format.bitwarden",
    "keepassxc": "format.keepassxc",
    "chrome": "format.chrome",
    "firefox": "format.firefox",
    "generic": "format.generic",
}

# Required columns to recognize this application's CSV (v1.0 to v1.6);
# "tags" (v1.7) is optional on import: older exports are still recognized.
_CSV_BASE_COLUMNS = ("type", "name", "url", "username", "email", "password", "notes",
                     "category", "favorite", "extra")
CSV_COLUMNS = (*_CSV_BASE_COLUMNS, "tags")


class ImportExportError(VaultError):
    """Unreadable file, unrecognized format, invalid options…"""


@dataclass(slots=True)
class ImportItem:
    entry: Entry
    category_name: str = ""
    dropped_tags: int = 0  # invalid tags dropped (the entry itself is imported)


@dataclass(slots=True)
class ImportPreview:
    format_key: str
    items: list[ImportItem]
    skipped_rows: int = 0

    @property
    def dropped_tags(self) -> int:
        return sum(item.dropped_tags for item in self.items)

    @property
    def format_label(self) -> str:
        return tr(FORMAT_LABELS[self.format_key])


@dataclass(slots=True)
class ImportResult:
    imported: int = 0
    duplicates: int = 0
    invalid: int = 0
    categories_created: list[str] = field(default_factory=list)


# --- CSV reading -------------------------------------------------------------------


def _hostname(url: str) -> str:
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("www.")


def _notes_with(*parts: tuple[str, str]) -> str:
    """Builds notes from non-empty (label, value) pairs."""
    lines = []
    for label, value in parts:
        value = (value or "").strip()
        if value:
            lines.append(value if not label else f"{label}: {value}")
    return "\n".join(lines)


def _detect_format(headers: list[str]) -> str:
    h = {c.strip().lower() for c in headers}
    if set(_CSV_BASE_COLUMNS) <= h:
        return "moncoffre"
    if {"login_password", "login_username", "name"} <= h:
        return "bitwarden"
    if {"title", "username", "password", "url"} <= h and "group" in h:
        return "keepassxc"
    if {"url", "username", "password"} <= h and ("guid" in h or "formactionorigin" in h):
        return "firefox"
    if {"name", "url", "username", "password"} <= h:
        return "chrome"
    if "password" in h and h & {"name", "title", "url", "username", "login"}:
        return "generic"
    raise ImportExportError(tr("import.error.unknown_format"))


def _row_to_item(fmt: str, row: dict[str, str]) -> ImportItem | None:
    r = {k.strip().lower(): (v or "") for k, v in row.items() if k}

    def get(*keys: str) -> str:
        """First non-empty value among the `keys` columns."""
        return next((r[k].strip() for k in keys if r.get(k, "").strip()), "")

    category = ""
    favorite = False
    entry_type = "login"
    extra: dict[str, str] = {}
    email = ""
    tags: list[str] = []
    if fmt == "moncoffre":
        entry_type = get("type") or "login"
        name, url, username = get("name"), get("url"), get("username")
        email, password, notes = get("email"), r.get("password", ""), r.get("notes", "")
        category = get("category")
        favorite = get("favorite").lower() in ("1", "true", "oui", "yes")
        if get("extra"):
            try:
                loaded = json.loads(r["extra"])
                if isinstance(loaded, dict):
                    extra = {str(k): str(v) for k, v in loaded.items()}
                else:
                    extra = {}
            except json.JSONDecodeError:
                extra = {}
        # Comma-separated tags (commas are not allowed in a tag); validated on import.
        tags = [t.strip() for t in r.get("tags", "").split(",") if t.strip()]
    elif fmt == "bitwarden":
        entry_type = "secure_note" if get("type") == "note" else "login"
        name, username = get("name"), get("login_username")
        url = get("login_uri").split(",")[0].strip()
        password = r.get("login_password", "")
        notes = _notes_with(("", r.get("notes", "")),
                            (tr("import.notes.fields"), r.get("fields", "")),
                            ("TOTP", r.get("login_totp", "")))
        category = get("folder")
        favorite = get("favorite") == "1"
    elif fmt == "keepassxc":
        name, username, url = get("title"), get("username"), get("url")
        password = r.get("password", "")
        notes = _notes_with(("", r.get("notes", "")), ("TOTP", r.get("totp", "")))
        group = get("group").replace("\\", "/").strip("/")
        category = "" if group.lower() in ("", "root", "racine") else group.split("/")[-1]
    elif fmt == "chrome":
        name, url, username = get("name"), get("url"), get("username")
        password = r.get("password", "")
        notes = r.get("note", "") or r.get("notes", "")
    elif fmt == "firefox":
        url, username = get("url"), get("username")
        name = _hostname(url)
        password = r.get("password", "")
        notes = ""
    else:  # generic
        name = get("name", "title", "service", "site")
        url = get("url", "uri", "website", "login_uri")
        username = get("username", "login", "user", "login_username")
        email = get("email", "e-mail", "mail")
        password = r.get("password", "")
        notes = get("notes", "note", "comment", "comments")
        category = get("category", "folder", "group", "catégorie")

    if not any((name, url, username, password, notes, extra)):
        return None
    if entry_type not in ENTRY_TYPES:
        entry_type = "login"
    name = name or _hostname(url) or username or tr("import.untitled")
    kept = _importable_tags(tags)
    return ImportItem(
        Entry(service_name=name, entry_type=entry_type, url=url, username=username,
              email=email, password=password, notes=notes, extra=extra,
              is_favorite=favorite, tags=kept),
        category_name=category,
        dropped_tags=len(tags) - len(kept),
    )


def _importable_tags(raw: list[str]) -> tuple[str, ...]:
    """Imported tags: the valid ones, without logical duplicates, 20 at most.

    An invalid tag is dropped rather than rejecting the whole entry.
    """
    kept: list[str] = []
    for value in raw:
        try:
            (tag,) = normalize_tags([value])
        except EntryValidationError:
            continue
        if tag_key(tag) not in {tag_key(t) for t in kept} and len(kept) < MAX_TAGS:
            kept.append(tag)
    return tuple(kept)


def parse_csv(path: Path) -> ImportPreview:
    try:
        if path.stat().st_size > MAX_IMPORT_FILE_SIZE:
            raise ImportExportError(tr("import.error.too_large"))
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportExportError(tr("import.error.not_utf8")) from exc
    except OSError as exc:
        raise ImportExportError(tr("import.error.cannot_read", name=path.name)) from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise ImportExportError(tr("import.error.empty_csv"))
    fmt = _detect_format(reader.fieldnames)
    items, skipped = [], 0
    try:
        for row in reader:
            item = _row_to_item(fmt, row)
            if item is None:
                skipped += 1
            else:
                items.append(item)
    except csv.Error as exc:
        raise ImportExportError(tr("import.error.invalid_csv", line=reader.line_num)) from exc
    return ImportPreview(fmt, items, skipped)


# --- Encrypted export / import -------------------------------------------------------------


def _entries_payload(service: EntryService, vault: Vault) -> list[dict]:
    names = {c.id: c.name for c in CategoryService(vault).list_categories()}
    payload = []
    for summary in service.list_entries():
        e = service.get_entry(summary.id)
        payload.append({
            "type": e.entry_type, "name": e.service_name, "url": e.url,
            "username": e.username, "email": e.email, "password": e.password,
            "notes": e.notes, "extra": e.extra, "favorite": e.is_favorite,
            "category": names.get(e.category_id, "") if e.category_id else "",
            "tags": list(e.tags),
        })
    return payload


def _require_master_password(vault: Vault, master_password: str) -> None:
    if not vault.verify_master_password(master_password):
        raise WrongMasterPasswordError(tr("vault.error.wrong_password"))


def export_encrypted(service: EntryService, vault: Vault, master_password: str,
                     export_password: str, destination: Path) -> int:
    _require_master_password(vault, master_password)
    if len(export_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            tr("export.error.password_too_short", min=MIN_MASTER_PASSWORD_LENGTH))
    entries = _entries_payload(service, vault)
    plaintext = json.dumps(
        {"exported_at": datetime.now(UTC).isoformat(), "entries": entries},
        ensure_ascii=False,
    ).encode("utf-8")
    params = crypto.Argon2Params()
    salt = crypto.generate_salt()
    key = crypto.derive_key(export_password, salt, params)
    nonce, ciphertext = crypto.aes_gcm_encrypt(key, plaintext, _EXPORT_AAD)
    container = {
        "format": "mon-coffre-fort-export", "version": 1, "kdf": "argon2id",
        "kdf_params": params.to_dict(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    write_private_atomic(destination, json.dumps(container).encode("utf-8"),
                         temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().info("Encrypted export written: %d entries", len(entries))
    return len(entries)


def export_csv(service: EntryService, vault: Vault, master_password: str,
               destination: Path) -> int:
    """**Unencrypted** export (plaintext passwords) — file created as 0600."""
    _require_master_password(vault, master_password)
    entries = _entries_payload(service, vault)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for e in entries:
        writer.writerow({
            **{k: e[k] for k in ("type", "name", "url", "username", "email",
                                 "password", "notes", "category")},
            "favorite": "1" if e["favorite"] else "0",
            "extra": json.dumps(e["extra"], ensure_ascii=False) if e["extra"] else "",
            "tags": ", ".join(e["tags"]),
        })
    write_private_atomic(destination, buffer.getvalue().encode("utf-8"),
                         temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().warning("Unencrypted CSV export written: %d entries", len(entries))
    return len(entries)


def is_encrypted_export(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            start = f.read(64)
    except OSError:
        return False
    return b'"mon-coffre-fort-export"' in start or start.lstrip().startswith(b'{"format"')


def parse_encrypted_export(path: Path, export_password: str) -> ImportPreview:
    try:
        if path.stat().st_size > MAX_IMPORT_FILE_SIZE:
            raise ImportExportError(tr("import.error.too_large"))
        container = json.loads(path.read_text(encoding="utf-8"))
        if container.get("format") != "mon-coffre-fort-export" or container.get("version") != 1:
            raise ImportExportError(tr("import.error.not_export"))
        params = crypto.Argon2Params.from_dict(container["kdf_params"])
        salt = crypto.check_salt(base64.b64decode(container["salt"], validate=True))
        nonce = base64.b64decode(container["nonce"], validate=True)
        if len(nonce) != crypto.NONCE_SIZE:
            raise ValueError("Invalid nonce.")
        ciphertext = base64.b64decode(container["ciphertext"], validate=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ImportExportError(tr("import.error.export_unreadable")) from exc
    key = crypto.derive_key(export_password, salt, params)
    try:
        data = json.loads(crypto.aes_gcm_decrypt(key, nonce, ciphertext, _EXPORT_AAD))
    except crypto.AuthenticationFailed as exc:
        raise WrongMasterPasswordError(tr("import.error.wrong_export_password")) from exc
    items = []
    for raw in data.get("entries", []):
        row = {k: raw.get(k, "") for k in ("type", "name", "url", "username", "email",
                                            "password", "notes", "category")}
        row["favorite"] = "1" if raw.get("favorite") else "0"
        raw_tags = raw.get("tags") or []  # non-text value: ignored, never converted
        row["tags"] = (", ".join(t for t in raw_tags if isinstance(t, str))
                       if isinstance(raw_tags, list) else "")
        row["extra"] = json.dumps(raw.get("extra") or {}, ensure_ascii=False)
        item = _row_to_item("moncoffre", row)
        if item is not None:
            items.append(item)
    return ImportPreview("moncoffre_encrypted", items)


# --- Applying the import --------------------------------------------------------------


def _dedup_key(e: Entry) -> tuple:
    return (normalize_for_search(e.service_name.strip()), e.username.strip(),
            e.url.strip(), e.password)


def apply_import(entries: EntryService, categories: CategoryService, preview: ImportPreview,
                 create_categories: bool = True, skip_duplicates: bool = True) -> ImportResult:
    result = ImportResult()
    existing_categories = {normalize_for_search(c.name): c.id
                           for c in categories.list_categories()}
    # A built-in category may be named in another interface language (export made
    # in German, import in French…) or in 1.x French (files of versions 1.x).
    for c in categories.list_categories():
        key = builtin_key_for_name(c.name) if c.is_builtin else None
        for alias in every_builtin_name(key) if key else ():
            existing_categories.setdefault(normalize_for_search(alias), c.id)
    known = set()
    if skip_duplicates:
        for summary in entries.list_entries():
            known.add(_dedup_key(entries.get_entry(summary.id)))

    to_create: list[Entry] = []
    for item in preview.items:
        entry = item.entry
        if skip_duplicates:
            key = _dedup_key(entry)
            if key in known:
                result.duplicates += 1
                continue
            known.add(key)
        entry.category_id = None
        if item.category_name:
            wanted = normalize_for_search(" ".join(item.category_name.split()))
            if wanted in existing_categories:
                entry.category_id = existing_categories[wanted]
            elif create_categories:
                try:
                    new_id = categories.create_category(item.category_name)
                except VaultError:
                    new_id = None
                if new_id is not None:
                    existing_categories[wanted] = new_id
                    result.categories_created.append(" ".join(item.category_name.split()))
                    entry.category_id = new_id
        try:
            entries.validate_entry(entry)
        except EntryValidationError:
            result.invalid += 1
            continue
        to_create.append(entry)

    result.imported = len(entries.import_entries(to_create)) if to_create else 0
    get_logger().info(
        "Import applied (%s): %d imported, %d duplicates, %d invalid",
        preview.format_key, result.imported, result.duplicates, result.invalid,
    )
    return result
