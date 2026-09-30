"""Registre des actions de l'application (raccourcis clavier + palette Ctrl+K).

Toutes les actions sont déclarées ici, avec icône Lucide et raccourci. La
navigation visible est portée par la barre latérale et l'en-tête ; ce
registre rend chaque action accessible au clavier et depuis la palette de
commandes. Les actions qui exigent un coffre ouvert sont désactivées quand
il est verrouillé (leurs raccourcis sont alors inactifs).
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
    shortcut: str | None = None       # raccourci réel (niveau fenêtre)
    shortcut_hint: str | None = None  # affiché seulement (raccourci géré par un widget)
    needs_vault: bool = True
    checkable: bool = False
    keywords: str = ""
    group: str = "Actions"


ACTIONS: tuple[ActionSpec, ...] = (
    # Navigation
    ActionSpec("go_dashboard", "Vue générale", "layout-dashboard", "Alt+1", group="Aller à"),
    ActionSpec("go_vault", "Coffre", "key-round", "Alt+2", group="Aller à"),
    ActionSpec("go_security", "Sécurité", "shield-check", "Alt+3",
               keywords="audit score faibles réutilisés", group="Aller à"),
    ActionSpec("go_history", "Historique", "history", "Alt+4", keywords="activité timeline",
               group="Aller à"),
    ActionSpec("go_trash", "Corbeille", "trash-2", "Alt+5", group="Aller à"),
    ActionSpec("go_backups", "Sauvegardes", "database-backup", "Alt+6",
               keywords="backup restaurer import export", group="Aller à"),
    ActionSpec("settings", "Paramètres", "settings", "Ctrl+,", needs_vault=False,
               keywords="préférences options réglages", group="Aller à"),
    # Comptes
    ActionSpec("new_entry", "Nouveau compte", "plus", "Ctrl+N", keywords="ajouter créer entrée"),
    ActionSpec("edit_entry", "Modifier le compte", "square-pen", "Ctrl+E"),
    ActionSpec("duplicate_entry", "Dupliquer le compte", "copy-plus", "Ctrl+D", keywords="copie"),
    ActionSpec("delete_entry", "Déplacer vers la corbeille", "trash-2", shortcut_hint="Suppr",
               keywords="supprimer effacer"),
    ActionSpec("copy_password", "Copier le mot de passe", "copy", shortcut_hint="Ctrl+C"),
    ActionSpec("copy_username", "Copier l'identifiant", "copy", shortcut_hint="Ctrl+B",
               keywords="nom utilisateur login"),
    ActionSpec("search", "Rechercher", "search", "Ctrl+F", keywords="filtrer trouver"),
    ActionSpec("palette", "Palette de commandes", "command", "Ctrl+K", keywords="commande action"),
    # Outils
    ActionSpec("generator", "Générateur de mots de passe", "wand-sparkles", "Ctrl+G",
               keywords="aléatoire phrase de passe"),
    ActionSpec("import", "Importer…", "file-down", keywords="csv bitwarden keepass chrome firefox"),
    ActionSpec("export", "Exporter…", "file-up", keywords="csv chiffré mcfexport"),
    ActionSpec("backup_now", "Créer une sauvegarde", "database-backup", keywords="backup copie"),
    ActionSpec("restore_backup", "Restaurer une sauvegarde…", "rotate-ccw", needs_vault=False,
               keywords="backup mcfbak"),
    ActionSpec("open_backups", "Ouvrir le dossier des sauvegardes", "folder-open",
               needs_vault=False),
    # Coffre
    ActionSpec("new_vault", "Nouveau coffre…", "lock-keyhole", needs_vault=False, keywords="créer",
               group="Coffre"),
    ActionSpec("switch_vault", "Changer de coffre", "log-out", keywords="ouvrir basculer",
               group="Coffre"),
    ActionSpec("rename_vault", "Renommer le coffre…", "square-pen", group="Coffre"),
    ActionSpec("change_password", "Changer le mot de passe maître…", "key-round",
               keywords="master sécurité", group="Coffre"),
    ActionSpec("recovery_key", "Clé de récupération…", "key-round",
               keywords="mot de passe oublié secours récupérer", group="Coffre"),
    ActionSpec("delete_vault", "Supprimer ce coffre…", "trash-2", group="Coffre"),
    ActionSpec("lock", "Verrouiller", "lock", "Ctrl+L", keywords="fermer sécurité", group="Coffre"),
    # Application
    ActionSpec("animations", "Animations", "sparkles", needs_vault=False, checkable=True,
               keywords="effets mouvement", group="Application"),
    ActionSpec("fullscreen", "Plein écran", "maximize-2", "F11", needs_vault=False,
               group="Application"),
    ActionSpec("shortcuts", "Raccourcis clavier", "keyboard", "F1", needs_vault=False,
               group="Application"),
    ActionSpec("about", "À propos de Mon Coffre-Fort", "info", needs_vault=False,
               group="Application"),
    ActionSpec("quit", "Quitter", "power", "Ctrl+Q", needs_vault=False, group="Application"),
)


class AppMenus:
    """Crée les actions (raccourcis actifs sur toute la fenêtre) et tient leur registre."""

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
