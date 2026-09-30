"""Shared base of the views and shared context (services, clipboard, navigation)."""

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
    """What a view needs, without knowing the main window."""

    session: SessionManager
    entries: EntryService
    categories: CategoryService
    clipboard: SecureClipboard
    settings: Callable[[], Settings]
    notify: Callable[..., None]  # notify(title, message="", kind="success", icon=None)
    navigate: Callable[..., None]               # navigate("vault", entry_id=…)
    changed: Callable[[], None]                 # data changed: refresh counters/views
    vault_action: Callable[[str], None]         # "new", "switch", "password", "delete", "lock"
    update_settings: Callable[[Settings], None]  # saves and applies new settings

    @property
    def vault(self):
        return self.session.vault


class Page(QWidget):
    """A view: title + subtitle (shown in the header), `refresh()`, `on_show()`."""

    key = ""
    title = ""
    subtitle = ""
    icon = ""

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.ctx = ctx

    def on_show(self, **kwargs) -> None:
        """Called every time the view is shown (kwargs: navigation parameters)."""
        self.refresh()

    def refresh(self) -> None:
        pass

    def wipe(self) -> None:
        """Removes every displayed value (locking)."""


def scrolling(page: QWidget, margins=(32, 28, 32, 32), spacing: int = 20) -> QVBoxLayout:
    """Scrolling content of the view; returns the content layout."""
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
