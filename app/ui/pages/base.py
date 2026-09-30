"""Socle commun des vues et contexte partagé (services, presse-papiers, navigation)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.core.categories import CategoryService
from app.core.entries import EntryService
from app.core.session import SessionManager
from app.services.settings import Settings
from app.ui.secure_clipboard import SecureClipboard


@dataclass
class AppContext:
    """Ce dont une vue a besoin, sans connaître la fenêtre principale."""

    session: SessionManager
    entries: EntryService
    categories: CategoryService
    clipboard: SecureClipboard
    settings: Callable[[], Settings]
    notify: Callable[..., None]  # notify(titre, message="", kind="success", icon=None)
    navigate: Callable[..., None]               # navigate("vault", entry_id=…)
    changed: Callable[[], None]                 # données modifiées : rafraîchir compteurs/vues
    vault_action: Callable[[str], None]         # "new", "switch", "password", "delete", "lock"
    update_settings: Callable[[Settings], None]  # enregistre et applique de nouveaux paramètres

    @property
    def vault(self):
        return self.session.vault


class Page(QWidget):
    """Une vue : titre + sous-titre (affichés dans l'en-tête), `refresh()`, `on_show()`."""

    key = ""
    title = ""
    subtitle = ""
    icon = ""

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.ctx = ctx

    def on_show(self, **kwargs) -> None:
        """Appelé à chaque affichage de la vue (kwargs : paramètres de navigation)."""
        self.refresh()

    def refresh(self) -> None:
        pass

    def wipe(self) -> None:
        """Retire toute donnée affichée (verrouillage)."""


def scrolling(page: QWidget, margins=(32, 28, 32, 32), spacing: int = 20) -> QVBoxLayout:
    """Contenu défilant de la vue ; retourne la mise en page du contenu."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    content = QWidget()
    layout = QVBoxLayout(content)
    layout.setContentsMargins(*margins)
    layout.setSpacing(spacing)
    scroll.setWidget(content)
    outer = QVBoxLayout(page)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.addWidget(scroll)
    return layout
