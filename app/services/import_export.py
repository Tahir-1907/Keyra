"""Import et export d'entrées.

Import (aperçu puis confirmation, en une seule transaction) :
* CSV exportés par Bitwarden, KeePassXC, Chrome / Chromium / Edge / Brave,
  Firefox, un CSV générique, ou le CSV de cette application ;
* export chiffré de cette application (`.mcfexport`).

Export (le mot de passe maître est **redemandé** : une session laissée
ouverte ne suffit pas pour tout exporter) :
* `.mcfexport` chiffré — **recommandé** : JSON chiffré en AES-256-GCM avec
  une clé Argon2id dérivée d'un mot de passe d'export choisi par
  l'utilisateur (indépendant du coffre, pour transférer vers un autre coffre
  ou une autre machine) ;
* CSV **non chiffré** — pour migrer vers un autre logiciel ; le fichier
  contient tous les mots de passe en clair (avertissement explicite dans
  l'interface), il est créé en 0600.

Les entrées de la corbeille ne sont jamais exportées. L'historique non plus.
Les fichiers KeePass `.kdbx` ne sont pas lus directement (cela nécessiterait
une dépendance supplémentaire) : exporter d'abord en CSV depuis KeePassXC.
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
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger

MAX_IMPORT_FILE_SIZE = 20 * 1024 * 1024
EXPORT_SUFFIX = ".mcfexport"
_EXPORT_AAD = b"mon-coffre-fort:export:v1"
EXPORT_TEMP_PREFIX = ".tmp-export-"  # temporaires des exports (CSV, chiffré, PDF)

FORMAT_LABELS = {
    "moncoffre": "Mon Coffre-Fort (CSV)",
    "moncoffre_encrypted": "Mon Coffre-Fort (export chiffré)",
    "bitwarden": "Bitwarden (CSV)",
    "keepassxc": "KeePassXC (CSV)",
    "chrome": "Chrome / Chromium / Edge / Brave (CSV)",
    "firefox": "Firefox (CSV)",
    "generic": "CSV générique",
}

# Colonnes obligatoires pour reconnaître un CSV Mon Coffre-Fort (v1.0 à v1.6) ;
# « tags » (v1.7) est facultative à l'import : les anciens exports restent reconnus.
_CSV_BASE_COLUMNS = ("type", "name", "url", "username", "email", "password", "notes",
                     "category", "favorite", "extra")
CSV_COLUMNS = (*_CSV_BASE_COLUMNS, "tags")


class ImportExportError(VaultError):
    """Fichier illisible, format non reconnu, options invalides…"""


@dataclass(slots=True)
class ImportItem:
    entry: Entry
    category_name: str = ""
    dropped_tags: int = 0  # tags invalides écartés (l'entrée, elle, est importée)


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
        return FORMAT_LABELS[self.format_key]


@dataclass(slots=True)
class ImportResult:
    imported: int = 0
    duplicates: int = 0
    invalid: int = 0
    categories_created: list[str] = field(default_factory=list)


# --- Lecture des CSV -------------------------------------------------------------------


def _hostname(url: str) -> str:
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("www.")


def _notes_with(*parts: tuple[str, str]) -> str:
    """Assemble des notes à partir de (libellé, valeur) non vides."""
    lines = []
    for label, value in parts:
        value = (value or "").strip()
        if value:
            lines.append(value if not label else f"{label} : {value}")
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
    raise ImportExportError(
        "Format CSV non reconnu. Formats acceptés : Bitwarden, KeePassXC, Chrome, "
        "Firefox, Mon Coffre-Fort, ou un CSV contenant au moins une colonne "
        "« password » et une colonne « name », « title », « url » ou « username »."
    )


def _row_to_item(fmt: str, row: dict[str, str]) -> ImportItem | None:
    r = {k.strip().lower(): (v or "") for k, v in row.items() if k}

    def get(*keys: str) -> str:
        """Première valeur non vide parmi les colonnes `keys`."""
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
        # Tags séparés par des virgules (interdites dans un tag) ; validés à l'import.
        tags = [t.strip() for t in r.get("tags", "").split(",") if t.strip()]
    elif fmt == "bitwarden":
        entry_type = "secure_note" if get("type") == "note" else "login"
        name, username = get("name"), get("login_username")
        url = get("login_uri").split(",")[0].strip()
        password = r.get("login_password", "")
        notes = _notes_with(("", r.get("notes", "")), ("Champs", r.get("fields", "")),
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
    else:  # générique
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
    name = name or _hostname(url) or username or "Sans nom"
    kept = _importable_tags(tags)
    return ImportItem(
        Entry(service_name=name, entry_type=entry_type, url=url, username=username,
              email=email, password=password, notes=notes, extra=extra,
              is_favorite=favorite, tags=kept),
        category_name=category,
        dropped_tags=len(tags) - len(kept),
    )


def _importable_tags(raw: list[str]) -> tuple[str, ...]:
    """Tags importés : les valides, sans doublon logique, 20 au plus.

    Un tag invalide est écarté plutôt que de faire refuser toute l'entrée.
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
            raise ImportExportError("Fichier trop volumineux (20 Mo maximum).")
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportExportError("Le fichier doit être encodé en UTF-8.") from exc
    except OSError as exc:
        raise ImportExportError(f"Impossible de lire {path.name}.") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise ImportExportError("Fichier CSV vide.")
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
        raise ImportExportError(f"CSV invalide (ligne {reader.line_num}).") from exc
    return ImportPreview(fmt, items, skipped)


# --- Export / import chiffré -------------------------------------------------------------


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
        raise WrongMasterPasswordError("Mot de passe maître incorrect.")


def export_encrypted(service: EntryService, vault: Vault, master_password: str,
                     export_password: str, destination: Path) -> int:
    _require_master_password(vault, master_password)
    if len(export_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            f"Le mot de passe d'export doit contenir au moins {MIN_MASTER_PASSWORD_LENGTH} "
            "caractères."
        )
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
    """Export **non chiffré** (mots de passe en clair) — fichier créé en 0600."""
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
            raise ImportExportError("Fichier trop volumineux (20 Mo maximum).")
        container = json.loads(path.read_text(encoding="utf-8"))
        if container.get("format") != "mon-coffre-fort-export" or container.get("version") != 1:
            raise ImportExportError("Ce fichier n'est pas un export Mon Coffre-Fort compatible.")
        params = crypto.Argon2Params.from_dict(container["kdf_params"])
        salt = crypto.check_salt(base64.b64decode(container["salt"], validate=True))
        nonce = base64.b64decode(container["nonce"], validate=True)
        if len(nonce) != crypto.NONCE_SIZE:
            raise ValueError("Nonce invalide.")
        ciphertext = base64.b64decode(container["ciphertext"], validate=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ImportExportError("Export chiffré illisible ou invalide.") from exc
    key = crypto.derive_key(export_password, salt, params)
    try:
        data = json.loads(crypto.aes_gcm_decrypt(key, nonce, ciphertext, _EXPORT_AAD))
    except crypto.AuthenticationFailed as exc:
        raise WrongMasterPasswordError(
            "Mot de passe d'export incorrect (ou fichier altéré)."
        ) from exc
    items = []
    for raw in data.get("entries", []):
        row = {k: raw.get(k, "") for k in ("type", "name", "url", "username", "email",
                                            "password", "notes", "category")}
        row["favorite"] = "1" if raw.get("favorite") else "0"
        raw_tags = raw.get("tags") or []  # valeur non textuelle : ignorée, jamais convertie
        row["tags"] = (", ".join(t for t in raw_tags if isinstance(t, str))
                       if isinstance(raw_tags, list) else "")
        row["extra"] = json.dumps(raw.get("extra") or {}, ensure_ascii=False)
        item = _row_to_item("moncoffre", row)
        if item is not None:
            items.append(item)
    return ImportPreview("moncoffre_encrypted", items)


# --- Application de l'import --------------------------------------------------------------


def _dedup_key(e: Entry) -> tuple:
    return (normalize_for_search(e.service_name.strip()), e.username.strip(),
            e.url.strip(), e.password)


def apply_import(entries: EntryService, categories: CategoryService, preview: ImportPreview,
                 create_categories: bool = True, skip_duplicates: bool = True) -> ImportResult:
    result = ImportResult()
    existing_categories = {normalize_for_search(c.name): c.id
                           for c in categories.list_categories()}
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
