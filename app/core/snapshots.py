"""Format des versions d'historique (`entry_history.snapshot_enc`, JSON chiffré).

Le chiffrement ne change pas : DEK et AAD « mon-coffre-fort:history:<entrée>:<version> »
(app.core.entries). Ce module ne fait que décrire et valider le JSON :

* **v1** (versions 1.0 à 1.6) : pas de clé « v », exactement ces 11 champs :
  entry_type, service_name, url, username, email, password, notes, extra,
  category_id, updated_at, password_changed_at. Toujours lu, jamais réécrit :
  les historiques existants restent intacts.
* **v2** (à partir du schéma v4) : « v » = 2, les mêmes champs, plus `tags` et
  `is_favorite`, pour reconstruire fidèlement l'état historique (D7). Une version
  v1 est lue avec `tags = ()` et `is_favorite = None` (inconnu : une restauration
  conserve alors le favori actuel, comme aujourd'hui).

La date de remplacement reste en clair dans `entry_history.created_at` (D3).
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
    """Contenu d'une version d'historique, déchiffré (n'existe qu'en mémoire)."""

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
    is_favorite: bool | None = None  # None : inconnu (version v1)

    def __repr__(self) -> str:  # jamais de secret dans un repr
        return f"SnapshotContent(version={self.version}, entry_type={self.entry_type!r})"


def build_snapshot(content: SnapshotContent) -> dict:
    """JSON v2 d'une version (tags et favori inclus). ValueError si incohérent."""
    if not isinstance(content.is_favorite, bool):
        raise ValueError("Une version v2 enregistre toujours le favori.")
    data = {
        "v": SNAPSHOT_VERSION, "entry_type": content.entry_type,
        "service_name": content.service_name, "url": content.url,
        "username": content.username, "email": content.email,
        "password": content.password, "notes": content.notes, "extra": dict(content.extra),
        "category_id": content.category_id, "updated_at": content.updated_at,
        "password_changed_at": content.password_changed_at, "tags": list(content.tags),
        "is_favorite": content.is_favorite,
    }
    parse_snapshot(data)  # on n'écrit jamais ce qu'on ne saurait pas relire
    return data


def parse_snapshot(data: object) -> SnapshotContent:
    """Valide le JSON (v1 ou v2) d'une version d'historique. ValueError si malformé."""
    if not isinstance(data, dict):
        raise ValueError("Version d'historique invalide.")
    if "v" in data:
        version = data["v"]
        if not isinstance(version, int) or isinstance(version, bool) or version != 2:
            raise ValueError("Format de version d'historique non pris en charge.")
        expected = _V2_KEYS
    else:
        version, expected = 1, _V1_KEYS
    if set(data) != expected:
        raise ValueError("Champs de la version d'historique invalides.")
    for key in ("service_name", "url", "username", "email", "password", "notes",
                "updated_at", "password_changed_at"):
        if not isinstance(data[key], str):
            raise ValueError("Champ texte invalide dans une version d'historique.")
    if data["entry_type"] not in ENTRY_TYPE_KEYS or not data["service_name"].strip():
        raise ValueError("Version d'historique incohérente.")
    extra = data["extra"]
    if not isinstance(extra, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in extra.items()):
        raise ValueError("Champs additionnels invalides dans une version d'historique.")
    category_id = data["category_id"]
    if category_id is not None and (
            not isinstance(category_id, int) or isinstance(category_id, bool) or category_id < 1):
        raise ValueError("Référence de catégorie invalide dans une version d'historique.")
    tags: tuple[str, ...] = ()
    is_favorite = None
    if version == 2:
        if not isinstance(data["tags"], list) or not isinstance(data["is_favorite"], bool):
            raise ValueError("Tags ou favori invalides dans une version d'historique.")
        try:
            tags = normalize_tags(data["tags"])
        except EntryValidationError as exc:
            raise ValueError("Tags invalides dans une version d'historique.") from exc
        if list(tags) != data["tags"]:
            raise ValueError("Tags non canoniques dans une version d'historique.")
        is_favorite = data["is_favorite"]
    return SnapshotContent(
        version=version, entry_type=data["entry_type"], service_name=data["service_name"],
        url=data["url"], username=data["username"], email=data["email"],
        password=data["password"], notes=data["notes"], extra=dict(extra),
        category_id=category_id, updated_at=data["updated_at"],
        password_changed_at=data["password_changed_at"], tags=tags, is_favorite=is_favorite,
    )
