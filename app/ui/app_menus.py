"""Registry of the application actions (keyboard shortcuts + Ctrl+K palette).

Every action is declared here, with a Lucide icon and a shortcut. Visible
navigation is provided by the sidebar and the header; this registry makes
each action reachable from the keyboard and from the command palette.
Actions that need an open vault are disabled while it is locked (their
shortcuts are then inactive).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import QMainWindow

from app.i18n import tr
from app.ui import lucide, theme


@dataclass(frozen=True)
class ActionSpec:
    key: str
    text_key: str                     # translation key of the label (app/i18n)
    icon: str | None = None
    shortcut: str | None = None       # real shortcut (window level)
    shortcut_hint: str | None = None  # display only (shortcut handled by a widget)
    needs_vault: bool = True
    checkable: bool = False
    keywords: str = ""                # English search terms (the label is searched too)
    group_key: str = "action_group.actions"

    @property
    def text(self) -> str:
        return tr(self.text_key)

    @property
    def group(self) -> str:
        return tr(self.group_key)


_GO, _VAULT, _APP = "action_group.go_to", "action_group.vault", "action_group.application"

ACTIONS: tuple[ActionSpec, ...] = (
    # Navigation
    ActionSpec("go_dashboard", "action.go_dashboard", "layout-dashboard", "Alt+1", group_key=_GO),
    ActionSpec("go_vault", "action.go_vault", "key-round", "Alt+2", group_key=_GO),
    ActionSpec("go_security", "action.go_security", "shield-check", "Alt+3",
               keywords="audit score weak reused", group_key=_GO),
    ActionSpec("go_history", "action.go_history", "history", "Alt+4", keywords="activity timeline",
               group_key=_GO),
    ActionSpec("go_trash", "action.go_trash", "trash-2", "Alt+5", group_key=_GO),
    ActionSpec("go_backups", "action.go_backups", "database-backup", "Alt+6",
               keywords="backup restore import export", group_key=_GO),
    ActionSpec("settings", "action.settings", "settings", "Ctrl+,", needs_vault=False,
               keywords="preferences options configuration", group_key=_GO),
    # Entries
    ActionSpec("new_entry", "action.new_entry", "plus", "Ctrl+N", keywords="add create entry"),
    ActionSpec("edit_entry", "action.edit_entry", "square-pen", "Ctrl+E"),
    ActionSpec("duplicate_entry", "action.duplicate_entry", "copy-plus", "Ctrl+D", keywords="copy"),
    ActionSpec("delete_entry", "action.delete_entry", "trash-2", shortcut_hint="Del",
               keywords="delete remove"),
    ActionSpec("copy_password", "action.copy_password", "copy", shortcut_hint="Ctrl+C"),
    ActionSpec("copy_username", "action.copy_username", "copy", shortcut_hint="Ctrl+B",
               keywords="user name login"),
    ActionSpec("search", "action.search", "search", "Ctrl+F", keywords="filter find"),
    ActionSpec("palette", "action.palette", "command", "Ctrl+K", keywords="command action"),
    # Tools
    ActionSpec("generator", "action.generator", "wand-sparkles", "Ctrl+G",
               keywords="random passphrase"),
    ActionSpec("import", "action.import", "file-down",
               keywords="csv bitwarden keepass chrome firefox"),
    ActionSpec("export", "action.export", "file-up", keywords="csv encrypted mcfexport"),
    ActionSpec("backup_now", "action.backup_now", "database-backup", keywords="backup copy"),
    ActionSpec("restore_backup", "action.restore_backup", "rotate-ccw", needs_vault=False,
               keywords="backup mcfbak"),
    ActionSpec("open_backups", "action.open_backups", "folder-open",
               needs_vault=False),
    # Vault
    ActionSpec("new_vault", "action.new_vault", "lock-keyhole", needs_vault=False,
               keywords="create",
               group_key=_VAULT),
    ActionSpec("switch_vault", "action.switch_vault", "log-out", keywords="open switch",
               group_key=_VAULT),
    ActionSpec("rename_vault", "action.rename_vault", "square-pen", group_key=_VAULT),
    ActionSpec("change_password", "action.change_password", "key-round",
               keywords="master security", group_key=_VAULT),
    ActionSpec("recovery_key", "action.recovery_key", "key-round",
               keywords="forgot password rescue recover", group_key=_VAULT),
    ActionSpec("delete_vault", "action.delete_vault", "trash-2", group_key=_VAULT),
    ActionSpec("lock", "action.lock", "lock", "Ctrl+L", keywords="close security",
               group_key=_VAULT),
    # Application
    ActionSpec("animations", "action.animations", "sparkles", needs_vault=False, checkable=True,
               keywords="effects motion", group_key=_APP),
    ActionSpec("fullscreen", "action.fullscreen", "maximize-2", "F11", needs_vault=False,
               group_key=_APP),
    ActionSpec("shortcuts", "action.shortcuts", "keyboard", "F1", needs_vault=False,
               group_key=_APP),
    ActionSpec("about", "action.about", "info", needs_vault=False,
               group_key=_APP),
    ActionSpec("quit", "action.quit", "power", "Ctrl+Q", needs_vault=False, group_key=_APP),
)


class AppMenus:
    """Creates the actions (shortcuts active across the whole window) and keeps their registry."""

    def __init__(self, window: QMainWindow, handlers: dict[str, Callable[[], None]]) -> None:
        self.actions: dict[str, QAction] = {}
        self.specs: dict[str, ActionSpec] = {}
        for spec in ACTIONS:
            icon = lucide.icon(spec.icon, theme.TEXT_2) if spec.icon else QIcon()
            action = QAction(icon, spec.text, window)
            if spec.shortcut:
                action.setShortcut(QKeySequence(spec.shortcut))
                action.setShortcutContext(Qt.WindowShortcut)
            action.setCheckable(spec.checkable)
            handler = handlers[spec.key]
            if spec.checkable:
                action.toggled.connect(lambda checked, h=handler: h(checked))
            else:
                action.triggered.connect(lambda _checked=False, h=handler: h())
            window.addAction(action)
            self.actions[spec.key] = action
            self.specs[spec.key] = spec

    def retranslate(self) -> None:
        """Labels in the current interface language (after a language change)."""
        for key, action in self.actions.items():
            action.setText(self.specs[key].text)

    def set_vault_open(self, is_open: bool) -> None:
        for key, action in self.actions.items():
            if self.specs[key].needs_vault:
                action.setEnabled(is_open)
