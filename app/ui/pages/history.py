"""Vue « Historique » : timeline des événements réellement enregistrés.

Sources (voir app.core.activity) : création, modification (versions), mise à
la corbeille d'un compte, sauvegardes chiffrées. Rien n'est inventé.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from app.core.activity import (
    KIND_BACKUP,
    KIND_CREATED,
    KIND_MODIFIED,
    KIND_TRASHED,
    ActivityEvent,
    vault_activity,
)
from app.services import backup
from app.services.settings import backup_directory
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.pages.base import AppContext, Page, scrolling

EVENT_STYLE = {
    KIND_CREATED: ("plus", theme.ACCENT_2, "Compte créé"),
    KIND_MODIFIED: ("square-pen", theme.INFO, "Compte modifié"),
    KIND_TRASHED: ("trash-2", theme.DANGER, "Déplacé vers la corbeille"),
    KIND_BACKUP: ("database-backup", theme.TEXT_2, "Sauvegarde chiffrée"),
}


def _day_label(day) -> str:
    today = datetime.now().astimezone().date()
    if day == today:
        return "Aujourd'hui"
    if day == today - timedelta(days=1):
        return "Hier"
    months = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
              "septembre", "octobre", "novembre", "décembre")
    days = ("Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche")
    return f"{days[day.weekday()]} {day.day} {months[day.month - 1]} {day.year}"


class _Rail(QWidget):
    """Colonne de la timeline : trait vertical + point coloré."""

    def __init__(self, color: str, first: bool, last: bool) -> None:
        super().__init__()
        self.setFixedWidth(26)
        self._color, self._first, self._last = color, first, last

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        x = self.width() / 2
        mid = self.height() / 2
        painter.setPen(QPen(QColor(theme.BORDER_ACTIVE), 1.5))
        painter.drawLine(QPointF(x, 0 if not self._first else mid),
                         QPointF(x, self.height() if not self._last else mid))
        halo = QColor(self._color)
        halo.setAlpha(45)
        painter.setPen(Qt.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(QPointF(x, mid), 7, 7)
        painter.setBrush(QColor(self._color))
        painter.drawEllipse(QPointF(x, mid), 3.5, 3.5)


class _EventRow(QPushButton):
    def __init__(self, event: ActivityEvent, first: bool, last: bool, on_click) -> None:
        super().__init__()
        self.setObjectName("Ghost")
        self.setMinimumHeight(52)
        icon, color, caption = EVENT_STYLE[event.kind]
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 0, 12, 0)
        row.setSpacing(12)
        row.addWidget(_Rail(color, first, last))
        row.addWidget(ui.icon_label(icon, color, 16))
        texts = QVBoxLayout()
        texts.setSpacing(0)
        texts.addWidget(ui.label(event.title))
        texts.addWidget(ui.label(caption + (f" · {event.detail}" if event.detail else ""), "Faint"))
        row.addLayout(texts, 1)
        try:
            when = datetime.fromisoformat(event.timestamp).astimezone().strftime("%H:%M")
        except ValueError:
            when = ""
        row.addWidget(ui.label(when, "Faint"))
        clickable = event.entry_id is not None
        self.setCursor(Qt.PointingHandCursor if clickable else Qt.ArrowCursor)
        if clickable:
            self.clicked.connect(lambda _c=False: on_click(event))


class HistoryPage(Page):
    key = "history"
    title = "Historique"
    subtitle = "Activité enregistrée dans ce coffre"
    icon = "history"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self.layout_ = scrolling(self, spacing=6)

    def refresh(self) -> None:
        self._clear()
        if self.ctx.vault.is_locked:
            return
        events = vault_activity(self.ctx.vault, limit=300)
        try:
            for info in backup.list_backups(backup_directory(self.ctx.settings()),
                                            self.ctx.vault.vault_id):
                events.append(ActivityEvent(info.created_at, KIND_BACKUP,
                                            info.path.name, None, info.kind))
        except OSError:
            pass
        events.sort(key=lambda e: e.timestamp, reverse=True)
        if not events:
            self.layout_.addWidget(ui.EmptyState(
                "history", "Aucune activité",
                "Les créations, modifications, suppressions et sauvegardes de ce coffre "
                "apparaîtront ici."))
            return
        groups: dict = {}
        for event in events:
            try:
                day = datetime.fromisoformat(event.timestamp).astimezone().date()
            except ValueError:
                continue
            groups.setdefault(day, []).append(event)
        rows = []
        for day, day_events in groups.items():
            header = ui.label(_day_label(day).upper(), "Overline")
            header.setContentsMargins(6, 14, 0, 4)
            self.layout_.addWidget(header)
            for i, event in enumerate(day_events):
                row = _EventRow(event, i == 0, i == len(day_events) - 1, self._open)
                self.layout_.addWidget(row)
                rows.append(row)
        self.layout_.addStretch(1)
        effects.stagger(rows[:16])

    def _open(self, event: ActivityEvent) -> None:
        if event.kind == KIND_TRASHED:
            self.ctx.navigate("trash")
        else:
            self.ctx.navigate("vault", entry_id=event.entry_id)

    def _clear(self) -> None:
        while self.layout_.count():
            item = self.layout_.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def wipe(self) -> None:
        self._clear()
