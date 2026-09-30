"""Format of history versions (`entry_history.snapshot_enc`, encrypted JSON).

Encryption is unchanged: DEK and AAD "mon-coffre-fort:history:<entry>:<version>"
(app.core.entries). This module only describes and validates the JSON:

* **v1** (versions 1.0 to 1.6): no "v" key, exactly these 11 fields:
  entry_type, service_name, url, username, email, password, notes, extra,
  category_id, updated_at, password_changed_at. Always read, never rewritten:
  existing histories stay intact.
* **v2** (from schema v4 on): "v" = 2, the same fields, plus `tags` and
  `is_favorite`, to faithfully rebuild the historical state (D7). A v1 version
  is read with `tags = ()` and `is_favorite = None` (unknown: a restore then
  keeps the current favorite, as before).

The replacement date stays in plaintext in `entry_history.created_at` (D3).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.exceptions import EntryValidationError
from app.core.metadata import ENTRY_TYPE_KEYS, normalize_tags

SNAPSHOT_VERSION = 2
_V1_KEYS = frozenset({"entry_type", "service_name", "url", "username", "email", "password",
                      "notes", "extra", "category_id", "updated_at", "password_changed_at"})
_V2_KEYS = _V1_KEYS | {"v", "tags", "is_favorite"}


@dataclass(frozen=True, slots=True)
class SnapshotContent:
    """Decrypted content of a history version (exists only in memory)."""

    version: int
    entry_type: str
    service_name: str
    url: str
    username: str
    email: str
    password: str
    notes: str
    extra: dict[str, str]
    category_id: int | None
    updated_at: str
    password_changed_at: str
    tags: tuple[str, ...] = ()
    is_favorite: bool | None = None  # None: unknown (v1 version)

    def __repr__(self) -> str:  # never a secret in a repr
        return f"SnapshotContent(version={self.version}, entry_type={self.entry_type!r})"


def build_snapshot(content: SnapshotContent) -> dict:
    """v2 JSON of a version (tags and favorite included). ValueError if inconsistent."""
    if not isinstance(content.is_favorite, bool):
        raise ValueError("A v2 version always records the favorite.")
    data = {
        "v": SNAPSHOT_VERSION, "entry_type": content.entry_type,
        "service_name": content.service_name, "url": content.url,
        "username": content.username, "email": content.email,
        "password": content.password, "notes": content.notes, "extra": dict(content.extra),
        "category_id": content.category_id, "updated_at": content.updated_at,
        "password_changed_at": content.password_changed_at, "tags": list(content.tags),
        "is_favorite": content.is_favorite,
    }
    parse_snapshot(data)  # never write what could not be read back
    return data


def parse_snapshot(data: object) -> SnapshotContent:
    """Validates the JSON (v1 or v2) of a history version. ValueError if malformed."""
    if not isinstance(data, dict):
        raise ValueError("Invalid history version.")
    if "v" in data:
        version = data["v"]
        if not isinstance(version, int) or isinstance(version, bool) or version != 2:
            raise ValueError("Unsupported history version format.")
        expected = _V2_KEYS
    else:
        version, expected = 1, _V1_KEYS
    if set(data) != expected:
        raise ValueError("Invalid history version fields.")
    for key in ("service_name", "url", "username", "email", "password", "notes",
                "updated_at", "password_changed_at"):
        if not isinstance(data[key], str):
            raise ValueError("Invalid text field in a history version.")
    if data["entry_type"] not in ENTRY_TYPE_KEYS or not data["service_name"].strip():
        raise ValueError("Inconsistent history version.")
    extra = data["extra"]
    if not isinstance(extra, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in extra.items()):
        raise ValueError("Invalid additional fields in a history version.")
    category_id = data["category_id"]
    if category_id is not None and (
            not isinstance(category_id, int) or isinstance(category_id, bool) or category_id < 1):
        raise ValueError("Invalid category reference in a history version.")
    tags: tuple[str, ...] = ()
    is_favorite = None
    if version == 2:
        if not isinstance(data["tags"], list) or not isinstance(data["is_favorite"], bool):
            raise ValueError("Invalid tags or favorite in a history version.")
        try:
            tags = normalize_tags(data["tags"])
        except EntryValidationError as exc:
            raise ValueError("Invalid tags in a history version.") from exc
        if list(tags) != data["tags"]:
            raise ValueError("Non-canonical tags in a history version.")
        is_favorite = data["is_favorite"]
    return SnapshotContent(
        version=version, entry_type=data["entry_type"], service_name=data["service_name"],
        url=data["url"], username=data["username"], email=data["email"],
        password=data["password"], notes=data["notes"], extra=dict(extra),
        category_id=category_id, updated_at=data["updated_at"],
        password_changed_at=data["password_changed_at"], tags=tags, is_favorite=is_favorite,
    )
