"""Vault activity log (the "History" view), read-only.

Rebuilt from what the vault actually records — no data is invented or added:
* entry created     ← encrypted metadata (created_at)
* entry modified    ← entry_history.created_at (one version per modification)
* moved to Trash    ← encrypted metadata (deleted_at)
Backups (.mcfbak files) are added by the services layer.
Locks, copies, etc. are deliberately not recorded anywhere, so they do not
appear.

Only metadata (already decrypted in the vault cache) is read: no secret is
decrypted.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.vault import Vault
from app.database.repositories import HistoryRepository

KIND_CREATED = "created"
KIND_MODIFIED = "modified"
KIND_TRASHED = "trashed"
KIND_BACKUP = "backup"


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    timestamp: str          # ISO 8601 (UTC)
    kind: str
    title: str
    entry_id: int | None = None
    detail: str = ""


def vault_activity(vault: Vault, limit: int = 200) -> list[ActivityEvent]:
    """Vault events, most recent first."""
    metas = vault.metadata.entries()  # VaultLockedError if locked
    events: list[ActivityEvent] = []
    for entry_id, meta in metas.items():
        events.append(ActivityEvent(meta.created_at, KIND_CREATED, meta.name, entry_id))
        if meta.deleted_at is not None:
            events.append(ActivityEvent(meta.deleted_at, KIND_TRASHED, meta.name, entry_id))
    for version in HistoryRepository(vault.connection).list_recent_meta(limit):
        meta = metas.get(version.entry_id)
        if meta is not None:
            events.append(ActivityEvent(version.created_at, KIND_MODIFIED, meta.name,
                                        version.entry_id))
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]


def last_activity(vault: Vault) -> str | None:
    """Date of the last change in the vault (creation, modification, deletion)."""
    events = vault_activity(vault, limit=1)
    latest = max((m.updated_at for m in vault.metadata.entries().values()
                  if m.deleted_at is None), default=None)
    candidates = [c for c in (latest, events[0].timestamp if events else None) if c]
    return max(candidates) if candidates else None
