"""Journal d'activité du coffre (vue « Historique »), en lecture seule.

Reconstruit à partir de ce que le coffre enregistre réellement — aucune
donnée n'est inventée ni ajoutée :
* création d'une entrée          ← métadonnées chiffrées (created_at)
* modification d'une entrée      ← entry_history.created_at (une version par modification)
* mise à la corbeille            ← métadonnées chiffrées (deleted_at)
Les sauvegardes (fichiers .mcfbak) sont ajoutées par la couche services.
Les verrouillages, copies, etc. ne sont volontairement enregistrés nulle
part : ils n'apparaissent donc pas.

Seules les métadonnées (déjà déchiffrées dans le cache du coffre) sont lues :
aucun secret n'est déchiffré.
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
    """Événements du coffre, du plus récent au plus ancien."""
    metas = vault.metadata.entries()  # VaultLockedError si verrouillé
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
    """Date du dernier changement dans le coffre (création, modification, suppression)."""
    events = vault_activity(vault, limit=1)
    latest = max((m.updated_at for m in vault.metadata.entries().values()
                  if m.deleted_at is None), default=None)
    candidates = [c for c in (latest, events[0].timestamp if events else None) if c]
    return max(candidates) if candidates else None
