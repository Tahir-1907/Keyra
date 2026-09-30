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

from app.ui import lucide, theme


@dataclass(frozen=True)
class ActionSpec:
    key: str
    text: str
    icon: str | None = None
    shortcut: str | None = None       # real shortcut (window level)
    shortcut_hint: str | None = None  # display only (shortcut handled by a widget)
    needs_vault: bool = True
    checkable: bool = False
    keywords: str = ""
    group: str = "Actions"


ACTIONS: tuple[ActionSpec, ...] = (
    # Navigation
    ActionSpec("go_dashboard", "Overview", "layout-dashboard", "Alt+1", group="Go to"),
    ActionSpec("go_vault", "Vault", "key-round", "Alt+2", group="Go to"),
    ActionSpec("go_security", "Security", "shield-check", "Alt+3",
               keywords="audit score weak reused", group="Go to"),
    ActionSpec("go_history", "History", "history", "Alt+4", keywords="activity timeline",
               group="Go to"),
    ActionSpec("go_trash", "Trash", "trash-2", "Alt+5", group="Go to"),
    ActionSpec("go_backups", "Backups", "database-backup", "Alt+6",
               keywords="backup restore import export", group="Go to"),
    ActionSpec("settings", "Settings", "settings", "Ctrl+,", needs_vault=False,
               keywords="preferences options configuration", group="Go to"),
    # Entries
    ActionSpec("new_entry", "New entry", "plus", "Ctrl+N", keywords="add create entry"),
    ActionSpec("edit_entry", "Edit entry", "square-pen", "Ctrl+E"),
    ActionSpec("duplicate_entry", "Duplicate entry", "copy-plus", "Ctrl+D", keywords="copy"),
    ActionSpec("delete_entry", "Move to Trash", "trash-2", shortcut_hint="Del",
               keywords="delete remove"),
    ActionSpec("copy_password", "Copy password", "copy", shortcut_hint="Ctrl+C"),
    ActionSpec("copy_username", "Copy username", "copy", shortcut_hint="Ctrl+B",
               keywords="user name login"),
    ActionSpec("search", "Search", "search", "Ctrl+F", keywords="filter find"),
    ActionSpec("palette", "Command palette", "command", "Ctrl+K", keywords="command action"),
    # Tools
    ActionSpec("generator", "Password generator", "wand-sparkles", "Ctrl+G",
               keywords="random passphrase"),
    ActionSpec("import", "Import…", "file-down", keywords="csv bitwarden keepass chrome firefox"),
    ActionSpec("export", "Export…", "file-up", keywords="csv encrypted mcfexport"),
    ActionSpec("backup_now", "Create a backup", "database-backup", keywords="backup copy"),
    ActionSpec("restore_backup", "Restore a backup…", "rotate-ccw", needs_vault=False,
               keywords="backup mcfbak"),
    ActionSpec("open_backups", "Open the backup folder", "folder-open",
               needs_vault=False),
    # Vault
    ActionSpec("new_vault", "New vault…", "lock-keyhole", needs_vault=False, keywords="create",
               group="Vault"),
    ActionSpec("switch_vault", "Switch vault", "log-out", keywords="open switch",
               group="Vault"),
    ActionSpec("rename_vault", "Rename vault…", "square-pen", group="Vault"),
    ActionSpec("change_password", "Change master password…", "key-round",
               keywords="master security", group="Vault"),
    ActionSpec("recovery_key", "Recovery key…", "key-round",
               keywords="forgot password rescue recover", group="Vault"),
    ActionSpec("delete_vault", "Delete this vault…", "trash-2", group="Vault"),
    ActionSpec("lock", "Lock", "lock", "Ctrl+L", keywords="close security", group="Vault"),
    # Application
    ActionSpec("animations", "Animations", "sparkles", needs_vault=False, checkable=True,
               keywords="effects motion", group="Application"),
    ActionSpec("fullscreen", "Full screen", "maximize-2", "F11", needs_vault=False,
               group="Application"),
    ActionSpec("shortcuts", "Keyboard shortcuts", "keyboard", "F1", needs_vault=False,
               group="Application"),
    ActionSpec("about", "About Keyra", "info", needs_vault=False,
               group="Application"),
    ActionSpec("quit", "Quit", "power", "Ctrl+Q", needs_vault=False, group="Application"),
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

    def set_vault_open(self, is_open: bool) -> None:
        for key, action in self.actions.items():
            if self.specs[key].needs_vault:
                action.setEnabled(is_open)
