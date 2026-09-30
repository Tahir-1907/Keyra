"""Liste des comptes en cartes compactes (coffre, corbeille, tableau de bord).

Peinte par un délégué (rapide même avec des centaines d'entrées) :
* carte : avatar monogramme, nom, identifiant, domaine, favori ;
* survol : fond plus clair + bordure plus visible ;
* sélection : fond actif, bordure accent, léger halo ;
* apparition décalée (30 ms entre cartes) à chaque nouvelle liste ;
* suppression : la carte sort vers la gauche (-30 px) en s'effaçant.

Ne manipule que des `EntrySummary` : aucun champ sensible.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlparse

from PySide6.QtCore import (
    QAbstractListModel,
    QEasingCurve,
    QItemSelectionModel,
    QModelIndex,
    QRectF,
    QSize,
    Qt,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QAbstractItemView, QListView, QStyle, QStyledItemDelegate

from app.core.entries import ENTRY_TYPES, EntrySummary
from app.ui import effects, lucide, theme
from app.ui.components import paint_avatar

CARD_HEIGHT = 68
CARD_SPACING = 8


def domain_of(url: str) -> str:
    if not url:
        return ""
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("www.")


def relative_date(iso: str) -> str:
    try:
        moment = datetime.fromisoformat(iso).astimezone()
    except (TypeError, ValueError):
        return ""
    delta = datetime.now().astimezone() - moment
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "à l'instant"
    if seconds < 3600:
        return f"il y a {seconds // 60} min"
    if seconds < 86400 and moment.date() == datetime.now().astimezone().date():
        return f"aujourd'hui à {moment:%H:%M}"
    if delta.days < 2:
        return f"hier à {moment:%H:%M}"
    return f"le {moment:%d/%m/%Y}"


class EntryListModel(QAbstractListModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[EntrySummary] = []

    def set_rows(self, rows: list[EntrySummary]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> list[EntrySummary]:
        return list(self._rows)

    def summary(self, row: int) -> EntrySummary | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def row_of(self, entry_id: int | None) -> int:
        return next((i for i, s in enumerate(self._rows) if s.id == entry_id), -1)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index, role=Qt.DisplayRole):
        summary = self.summary(index.row())
        if summary is None:
            return None
        if role in (Qt.DisplayRole, Qt.AccessibleTextRole):
            return f"{summary.service_name} {summary.username}".strip()
        if role == Qt.ToolTipRole:
            return summary.url or summary.service_name
        return None


class EntryCardDelegate(QStyledItemDelegate):
    def __init__(self, view: EntryListView) -> None:
        super().__init__(view)
        self._view = view

    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), CARD_HEIGHT + CARD_SPACING)

    def paint(self, painter: QPainter, option, index) -> None:
        summary = self._view.model().summary(index.row())
        if summary is None:
            return
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        progress = self._view.stagger.progress(index.row())
        removal = self._view.removal_progress(summary.id)
        painter.setOpacity(progress * (1 - removal))
        offset_y = (1 - progress) * 8
        offset_x = -30 * removal
        rect = QRectF(option.rect).adjusted(2 + offset_x, 2 + offset_y,
                                            -2 + offset_x, -CARD_SPACING + offset_y)
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        trash = self._view.trash_mode

        if selected:  # halo discret autour de la carte active
            glow = QColor(theme.ACCENT)
            for i, alpha in enumerate((26, 14, 6)):
                glow.setAlpha(alpha)
                painter.setPen(QPen(glow, 1))
                painter.setBrush(Qt.NoBrush)
                grow = 1 + i * 1.5
                painter.drawRoundedRect(rect.adjusted(-grow, -grow, grow, grow),
                                        theme.RADIUS_L + grow, theme.RADIUS_L + grow)
        background = QColor(theme.SURFACE_3 if (selected or hovered) else theme.SURFACE_2)
        border = QColor(theme.ACCENT if selected else
                        (theme.BORDER_ACTIVE if hovered else theme.BORDER))
        if selected:
            border.setAlpha(170)
        painter.setPen(QPen(border, 1))
        painter.setBrush(background)
        painter.drawRoundedRect(rect, theme.RADIUS_L, theme.RADIUS_L)
        if selected:  # liseré d'accent à gauche
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(theme.ACCENT))
            painter.drawRoundedRect(QRectF(rect.left() + 1, rect.top() + 16, 3,
                                           rect.height() - 32), 1.5, 1.5)

        avatar = QRectF(rect.left() + 14, rect.center().y() - 19, 38, 38)
        paint_avatar(painter, avatar, summary.service_name, 15)

        left = avatar.right() + 14
        right = rect.right() - 16
        painter.setPen(QColor(theme.TEXT))
        painter.setFont(theme.font(14, QFont.DemiBold))
        name_rect = QRectF(left, rect.top() + 13, right - left - 90, 20)
        name = painter.fontMetrics().elidedText(summary.service_name, Qt.ElideRight,
                                                int(name_rect.width()))
        painter.drawText(name_rect, Qt.AlignLeft | Qt.AlignVCenter, name)

        secondary = summary.username or (ENTRY_TYPES[summary.entry_type].label
                                         if summary.entry_type in ENTRY_TYPES else "")
        painter.setPen(QColor(theme.TEXT_2))
        painter.setFont(theme.font(theme.SIZE_SMALL))
        sub_rect = QRectF(left, rect.top() + 34, right - left - 90, 18)
        detail = domain_of(summary.url)
        text = " · ".join(p for p in (secondary, detail) if p)
        painter.drawText(sub_rect, Qt.AlignLeft | Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(text, Qt.ElideRight,
                                                          int(sub_rect.width())))

        # À droite : favori ou date de suppression (corbeille), catégorie.
        painter.setFont(theme.font(theme.SIZE_TINY, QFont.Medium))
        if trash:
            painter.setPen(QColor(theme.TEXT_3))
            painter.drawText(QRectF(right - 150, rect.top() + 13, 150, 20),
                             Qt.AlignRight | Qt.AlignVCenter,
                             f"supprimée {relative_date(summary.deleted_at)}")
        else:
            star = lucide.pixmap("star", theme.WARNING if summary.is_favorite else theme.TEXT_3,
                                 16, 1.8)
            if summary.is_favorite or hovered or selected:
                painter.drawPixmap(int(right - 16), int(rect.top() + 15), star)
        if summary.category_name:
            painter.setPen(QColor(theme.TEXT_3))
            painter.drawText(QRectF(right - 150, rect.top() + 34, 150, 18),
                             Qt.AlignRight | Qt.AlignVCenter, summary.category_name)
        painter.restore()


class EntryListView(QListView):
    """Liste de cartes ; signaux `entry_selected(id | None)` et `favorite_clicked(id)`."""

    entry_selected = Signal(object)
    favorite_clicked = Signal(int)
    activated_entry = Signal(int)

    def __init__(self, parent=None, trash_mode: bool = False) -> None:
        super().__init__(parent)
        self.trash_mode = trash_mode
        self.setModel(EntryListModel(self))
        self.stagger = effects.Stagger(self.viewport())
        self.setItemDelegate(EntryCardDelegate(self))
        self.setMouseTracking(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setUniformItemSizes(True)
        self.setSpacing(0)
        self.setFocusPolicy(Qt.StrongFocus)
        self._removals: dict[int, float] = {}
        self.selectionModel().selectionChanged.connect(self._on_selection)
        self.doubleClicked.connect(self._on_double_click)

    def model(self) -> EntryListModel:  # type: ignore[override]
        return super().model()

    # --- Données -------------------------------------------------------------------------

    def set_entries(self, rows: list[EntrySummary], animate: bool = True,
                    keep_id: int | None = None) -> None:
        self.model().set_rows(rows)
        if animate:
            self.stagger.start(len(rows))
        if keep_id is not None:
            self.select_entry(keep_id, emit=False)

    def select_entry(self, entry_id: int | None, emit: bool = True) -> None:
        row = self.model().row_of(entry_id)
        if row < 0:
            self.clearSelection()
            return
        index = self.model().index(row)
        if not emit:
            self.selectionModel().blockSignals(True)
        self.setCurrentIndex(index)
        self.selectionModel().select(index, QItemSelectionModel.ClearAndSelect)
        if not emit:
            self.selectionModel().blockSignals(False)
        self.scrollTo(index)

    def selected_id(self) -> int | None:
        rows = self.selectionModel().selectedRows()
        summary = self.model().summary(rows[0].row()) if rows else None
        return summary.id if summary else None

    def selected_summary(self) -> EntrySummary | None:
        return self.model().summary(self.model().row_of(self.selected_id()))

    # --- Suppression animée ------------------------------------------------------------------

    def removal_progress(self, entry_id: int) -> float:
        return self._removals.get(entry_id, 0.0)

    def animate_removal(self, entry_id: int, then: Callable[[], None]) -> None:
        """La carte sort vers la gauche, puis `then()` (suppression réelle) est appelé."""
        if not effects.animations_enabled() or self.model().row_of(entry_id) < 0:
            then()
            return
        animation = QVariantAnimation(self)
        animation.setDuration(theme.DURATION_BASE)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.InCubic)

        def step(value) -> None:
            self._removals[entry_id] = float(value)
            self.viewport().update()

        def done() -> None:
            self._removals.pop(entry_id, None)
            then()

        animation.valueChanged.connect(step)
        animation.finished.connect(done)
        animation.start(QVariantAnimation.DeleteWhenStopped)

    # --- Interaction -------------------------------------------------------------------------

    def _on_selection(self, *_args) -> None:
        self.entry_selected.emit(self.selected_id())

    def _on_double_click(self, index) -> None:
        summary = self.model().summary(index.row())
        if summary is not None:
            self.activated_entry.emit(summary.id)

    def mouseReleaseEvent(self, event) -> None:
        index = self.indexAt(event.position().toPoint())
        summary = self.model().summary(index.row()) if index.isValid() else None
        if summary is not None and not self.trash_mode and event.button() == Qt.LeftButton:
            rect = self.visualRect(index)
            star_zone = QRectF(rect.right() - 44, rect.top(), 44, 40)
            if star_zone.contains(event.position()):
                self.favorite_clicked.emit(summary.id)
                return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            entry_id = self.selected_id()
            if entry_id is not None:
                self.activated_entry.emit(entry_id)
                return
        super().keyPressEvent(event)
