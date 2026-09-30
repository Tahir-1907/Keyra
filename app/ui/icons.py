"""Icône de l'application (logo, app/resources/icons/) : fenêtres et lanceur du bureau."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from PySide6.QtGui import QIcon

ICONS_DIR = Path(__file__).resolve().parent.parent / "resources" / "icons"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    """Icône multi-résolution : Qt choisit la taille adaptée au contexte."""
    icon = QIcon()
    for size in ICON_SIZES:
        path = ICONS_DIR / f"logo-{size}.png"
        if path.is_file():
            icon.addFile(str(path))
    return icon
