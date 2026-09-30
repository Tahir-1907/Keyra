"""Panneau de détail d'un compte (coffre, corbeille, versions de l'historique).

Entre depuis la droite à chaque sélection. Les secrets sont masqués par
défaut ; « afficher » les révèle par un simple fondu (150 ms) — jamais
d'animation qui exposerait le secret plus longtemps que nécessaire. La copie
passe par le signal `copy_requested` (presse-papiers sécurisé géré par
l'appelant) et l'icône du bouton devient ✓.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.core.entries import ENTRY_TYPES, Entry, tag_search_query
from app.core.strength import estimate_strength
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.entry_list import domain_of
from app.ui.tag_editor import FlowLayout, tag_chip

_MASK = "•" * 14


def _format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y à %H:%M")
    except (TypeError, ValueError):
        return iso


class _FieldBox(QFrame):
    """Valeur dans une boîte arrondie, suivie de ses boutons d'action."""

    def __init__(self, value: str, secret: bool, mono: bool = False) -> None:
        super().__init__()
        self.setObjectName("FieldBox")
        self.setStyleSheet(
            f"QFrame#FieldBox {{ background: {theme.BG_2}; border: 1px solid {theme.BORDER};"
            f" border-radius: {theme.RADIUS_M}px; }}")
        self.real_value = value
        self.secret = secret
        self.revealed = False
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 4, 4, 4)
        row.setSpacing(2)
        # Valeur longue : passage à la ligne n'importe où, jamais d'élargissement du
        # panneau (les boutons Afficher / Copier restent toujours visibles). Pas de
        # sélection à la souris : elle copierait les points de coupure invisibles ;
        # la copie passe par le bouton, qui copie la valeur exacte.
        self.value = QLabel(_MASK if secret else ui.breakable(value))
        self.value.setMinimumHeight(30)
        self.value.setMinimumWidth(40)
        self.value.setWordWrap(True)
        self.value.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        if mono or secret:
            self.value.setFont(theme.mono_font(theme.SIZE_BODY))
        row.addWidget(self.value, 1)
        self.actions = row

    def add(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)

    def set_revealed(self, revealed: bool) -> None:
        self.revealed = revealed
        self.value.setText(ui.breakable(self.real_value) if revealed else _MASK)
        effects.fade_in(self.value, theme.DURATION_FAST)


class DetailPanel(QFrame):
    MODE_NORMAL, MODE_TRASH, MODE_READONLY = "normal", "trash", "readonly"

    edit_requested = Signal(int)
    delete_requested = Signal(int)
    history_requested = Signal(int)
    duplicate_requested = Signal(int)
    restore_requested = Signal(int)
    purge_requested = Signal(int)
    favorite_toggled = Signal(int, bool)
    copy_requested = Signal(str, str, bool)  # valeur, libellé, sensible
    tag_clicked = Signal(str)  # tag d'un badge (vue « Coffre » uniquement)

    def __init__(self, parent: QWidget | None = None, mode: str = MODE_NORMAL) -> None:
        super().__init__(parent)
        self.setObjectName("Surface")
        self._mode = mode
        self._entry: Entry | None = None
        self._secret_boxes: list[_FieldBox] = []
        self._tag_widgets: list[QWidget] = []

        self.placeholder = ui.EmptyState(
            "key-round", "Sélectionnez un compte",
            "Ses identifiants, sa robustesse et son historique s'afficheront ici.")
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(22, 22, 22, 22)
        self.content_layout.setSpacing(14)
        self.scroll.setWidget(self.content)

        self.footer = QHBoxLayout()
        self.footer.setContentsMargins(22, 0, 22, 18)
        self.footer.setSpacing(8)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.placeholder, 1)
        layout.addWidget(self.scroll, 1)
        layout.addLayout(self.footer)
        self.clear()

    # --- API --------------------------------------------------------------------------------

    def set_mode(self, mode: str) -> None:
        self._mode = mode

    def current_entry_id(self) -> int | None:
        return self._entry.id if self._entry else None

    def tag_widgets(self) -> list[QWidget]:
        """Badges des tags affichés (boutons en vue « Coffre », étiquettes ailleurs)."""
        return list(self._tag_widgets)

    def clear(self) -> None:
        """Efface toute donnée affichée (sélection vide, verrouillage)."""
        self._entry = None
        self._secret_boxes = []
        self._tag_widgets = []
        self._clear_layout(self.content_layout)
        self._clear_layout(self.footer)
        self.scroll.hide()
        self.placeholder.set_text("Sélectionnez un compte",
                                  "Ses identifiants, sa robustesse et son historique "
                                  "s'afficheront ici.")
        self.placeholder.show()

    def show_error(self, message: str) -> None:
        self.clear()
        self.placeholder.set_text("Entrée illisible", message)

    def set_favorite_state(self, is_favorite: bool) -> None:
        if self._entry is not None:
            self._entry.is_favorite = is_favorite
            self._favorite.setIcon(self._star_icon(is_favorite))

    def show_entry(self, entry: Entry, category_name: str, history_count: int = 0) -> None:
        self.clear()
        self._entry = entry
        spec = ENTRY_TYPES[entry.entry_type]
        layout = self.content_layout

        # En-tête : avatar, nom, domaine, favori, modifier.
        header = QHBoxLayout()
        header.setSpacing(14)
        header.addWidget(ui.Avatar(entry.service_name, 48), 0, Qt.AlignTop)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        name = ui.label(entry.service_name, "H2", wrap=True)
        name.setFont(theme.font(19, name.font().weight()))
        name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        titles.addWidget(name)
        subtitle = ui.label(ui.breakable(domain_of(entry.url) or spec.label), "Muted", wrap=True)
        subtitle.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)
        if self._mode == self.MODE_NORMAL:
            self._favorite = ui.icon_button(
                "star", "Retirer des favoris" if entry.is_favorite else "Ajouter aux favoris",
                on_click=lambda: self.favorite_toggled.emit(entry.id, not entry.is_favorite))
            self._favorite.setIcon(self._star_icon(entry.is_favorite))
            header.addWidget(self._favorite, 0, Qt.AlignTop)
            header.addWidget(ui.icon_button("square-pen", "Modifier", "Ctrl+E",
                                            lambda: self.edit_requested.emit(entry.id)),
                             0, Qt.AlignTop)
        layout.addLayout(header)

        badges = QHBoxLayout()
        badges.setSpacing(6)
        badges.addWidget(ui.label(spec.label, "Badge"))
        badges.addWidget(ui.label(category_name or "Sans catégorie", "Badge"))
        if entry.deleted_at:
            badges.addWidget(ui.label("Dans la corbeille", "BadgeDanger"))
        badges.addStretch(1)
        layout.addLayout(badges)
        if entry.tags:
            layout.addWidget(self._tags_row(entry.tags))
        layout.addWidget(ui.divider())

        if spec.uses_username:
            self._field("Identifiant", entry.username, copy_label="Nom d'utilisateur",
                        sensitive=False)
        if spec.uses_email:
            self._field("Email", entry.email, copy_label="Email")
        if spec.uses_password:
            box = self._field(spec.password_label, entry.password, secret=True,
                              copy_label=spec.password_label)
            if box is not None:
                self._strength(entry.password)
        for field_spec in spec.extra_fields:
            self._field(field_spec.label, entry.extra.get(field_spec.key, ""),
                        secret=field_spec.secret, copy_label=field_spec.label,
                        sensitive=field_spec.secret)
        if spec.uses_url and entry.url:
            box = self._field("URL", entry.url, copy_label="URL", sensitive=False)
            if box is not None:
                box.add(ui.icon_button(
                    "external-link", "Ouvrir dans le navigateur", size=16,
                    on_click=lambda: QDesktopServices.openUrl(QUrl(
                        entry.url if "://" in entry.url else f"https://{entry.url}"))))
        if entry.notes:
            layout.addWidget(ui.label("Notes", "FieldLabel"))
            notes = QPlainTextEdit(entry.notes)
            notes.setReadOnly(True)
            notes.setMinimumHeight(70)
            notes.setMaximumHeight(170)
            layout.addWidget(notes)

        meta = []
        if entry.created_at:
            meta.append(f"Créé le {_format_date(entry.created_at)}")
        if entry.updated_at:
            meta.append(f"modifié le {_format_date(entry.updated_at)}")
        if spec.uses_password and entry.password and entry.password_changed_at:
            meta.append(f"mot de passe changé le {_format_date(entry.password_changed_at)}")
        if entry.deleted_at:
            meta.append(f"supprimé le {_format_date(entry.deleted_at)}")
        layout.addWidget(ui.label(" · ".join(meta), "Faint", wrap=True))
        layout.addStretch(1)

        self._build_footer(entry, history_count)
        self.placeholder.hide()
        self.scroll.show()
        effects.slide_in(self.content, theme.SLIDE_DISTANCE, 0, theme.DURATION_BASE)

    def hide_secrets(self) -> None:
        for box in self._secret_boxes:
            if box.revealed:
                box.set_revealed(False)

    def secret_buttons(self, index: int = 0):
        """(bouton Afficher, bouton Copier) du n-ième champ secret (tests, accessibilité)."""
        box = self._secret_boxes[index]
        widgets = [box.actions.itemAt(i).widget() for i in range(box.actions.count())]
        buttons = [w for w in widgets if isinstance(w, QToolButton)]
        return buttons[0], buttons[1]

    # --- Construction -------------------------------------------------------------------------

    def _tags_row(self, tags: tuple[str, ...]) -> QWidget:
        host = QWidget()
        flow = FlowLayout(host)
        for tag in tags:
            if self._mode == self.MODE_NORMAL:  # clic : recherche de ce tag
                widget = tag_chip(tag, f"Rechercher {tag_search_query(tag)}")
                widget.clicked.connect(lambda _checked=False, t=tag: self.tag_clicked.emit(t))
            else:  # corbeille, historique : simple étiquette
                widget = ui.label(tag, "Badge")
            flow.addWidget(widget)
            self._tag_widgets.append(widget)
        return host

    def _field(self, title: str, value: str, secret: bool = False, copy_label: str = "",
               sensitive: bool = True) -> _FieldBox | None:
        if not value:
            return None
        self.content_layout.addWidget(ui.label(title, "FieldLabel"))
        box = _FieldBox(value, secret)
        if secret:
            # Champ secret : boutons libellés « Afficher » / « Copier », bien visibles.
            eye = ui.icon_button("eye", f"Afficher {title.lower()}", size=16)
            eye.setText("Afficher")
            eye.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

            def toggle(_checked=False, b=box, e=eye) -> None:
                b.set_revealed(not b.revealed)
                e.setIcon(ui.lucide.icon("eye-off" if b.revealed else "eye", theme.TEXT_2, 16))
                e.setText("Masquer" if b.revealed else "Afficher")

            eye.clicked.connect(toggle)
            box.add(eye)
            self._secret_boxes.append(box)
        copy = ui.CopyButton(f"Copier {copy_label.lower() or title.lower()}", labeled=secret)

        def do_copy(_checked=False, b=box, c=copy) -> None:
            self.copy_requested.emit(b.real_value, copy_label or title, sensitive)
            c.confirm()

        copy.clicked.connect(do_copy)
        box.add(copy)
        self.content_layout.addWidget(box)
        return box

    def _strength(self, password: str) -> None:
        result = estimate_strength(password)
        row = QHBoxLayout()
        row.addWidget(ui.label("Robustesse", "FieldLabel"))
        row.addStretch(1)
        row.addWidget(ui.label(f"{result.label} · ~{result.entropy_bits:.0f} bits", "Faint"))
        self.content_layout.addLayout(row)
        bar = ui.StrengthBar()
        self.content_layout.addWidget(bar)
        bar.set_score(result.score, result.entropy_bits)

    def _build_footer(self, entry: Entry, history_count: int) -> None:
        if self._mode == self.MODE_NORMAL:
            versions = f"{history_count} version{'s' if history_count > 1 else ''} précédente" \
                       f"{'s' if history_count > 1 else ''}"
            history = ui.icon_button("history", f"Historique — {versions}" if history_count
                                     else "Historique — aucune version précédente",
                                     on_click=lambda: self.history_requested.emit(entry.id))
            if history_count:
                history.setText(str(history_count))
                history.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            history.setEnabled(history_count > 0)
            self.footer.addWidget(history)
            self.footer.addWidget(ui.icon_button("copy-plus", "Dupliquer", "Ctrl+D",
                                                 lambda: self.duplicate_requested.emit(entry.id)))
            self.footer.addStretch(1)
            self.footer.addWidget(ui.button("Supprimer", "trash-2", "Danger", tooltip="Suppr",
                                            on_click=lambda: self.delete_requested.emit(entry.id)))
        elif self._mode == self.MODE_TRASH:
            self.footer.addWidget(ui.button("Restaurer", "archive-restore", "Primary",
                                            on_click=lambda: self.restore_requested.emit(entry.id)))
            self.footer.addStretch(1)
            self.footer.addWidget(ui.button("Supprimer définitivement", "trash-2", "Danger",
                                            on_click=lambda: self.purge_requested.emit(entry.id)))

    @staticmethod
    def _star_icon(active: bool):
        return ui.lucide.icon("star", theme.WARNING if active else theme.TEXT_2, 18)

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
            elif item.layout() is not None:
                DetailPanel._clear_layout(item.layout())
