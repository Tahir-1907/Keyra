"""The "Overview" view: vault state, statistics, recent entries, backups."""

from __future__ import annotations

import os
import pwd
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout

from app.core.activity import last_activity
from app.core.audit import KIND_OLD, run_audit
from app.services import backup
from app.services.settings import backup_directory
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.entry_list import relative_date
from app.ui.pages.base import AppContext, Page, scrolling


def _first_name() -> str:
    try:
        gecos = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip()
    except KeyError:
        gecos = ""
    return gecos.split()[0] if gecos else ""


class _RecentRow(QPushButton):
    """Clickable row: avatar, name, username, relative date."""

    def __init__(self, summary, on_click) -> None:
        super().__init__()
        self.setObjectName("Ghost")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(54)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 6, 12, 6)
        row.setSpacing(12)
        row.addWidget(ui.Avatar(summary.service_name, 34))
        texts = QVBoxLayout()
        texts.setSpacing(0)
        texts.addWidget(ui.label(summary.service_name))
        if summary.username:
            texts.addWidget(ui.label(summary.username, "Faint"))
        row.addLayout(texts, 1)
        row.addWidget(ui.label(relative_date(summary.updated_at), "Faint"))
        row.addWidget(ui.icon_label("chevron-right", theme.TEXT_3, 16))
        self.clicked.connect(lambda _checked=False: on_click(summary.id))


class DashboardPage(Page):
    key = "dashboard"
    title = "Overview"
    subtitle = "Your vault at a glance"
    icon = "layout-dashboard"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        layout = scrolling(self)

        # --- Welcome ----------------------------------------------------------------------
        self.greeting = ui.label("", "H1")
        self.status = ui.label("", "Muted")
        self.status.setFont(theme.font(15))
        self.activity = ui.label("", "Faint")
        hero = QVBoxLayout()
        hero.setSpacing(4)
        hero.addWidget(self.greeting)
        hero.addWidget(self.status)
        hero.addWidget(self.activity)
        layout.addLayout(hero)
        layout.addSpacing(4)

        # --- Statistics ----------------------------------------------------------------------
        self.cards = {
            "total": ui.StatCard("Entries", "key-round", theme.TEXT_2),
            "secure": ui.StatCard("Secure", "shield-check", theme.ACCENT_2),
            "review": ui.StatCard("To review", "shield-alert", theme.WARNING),
            "old": ui.StatCard("Old", "clock", theme.INFO),
        }
        self.cards["total"].clicked.connect(lambda: self.ctx.navigate("vault"))
        for key in ("secure", "review", "old"):
            self.cards[key].clicked.connect(lambda: self.ctx.navigate("security"))
        grid = QGridLayout()
        grid.setSpacing(14)
        for column, card in enumerate(self.cards.values()):
            grid.addWidget(card, 0, column)
        layout.addLayout(grid)
        self.skeleton = ui.Skeleton((0.35, 0.6, 0.5))
        layout.addWidget(self.skeleton)

        # --- Recent + side column ---------------------------------------------------------
        lower = QHBoxLayout()
        lower.setSpacing(14)
        self.recent_card = ui.card()
        recent_layout = QVBoxLayout(self.recent_card)
        recent_layout.setContentsMargins(18, 16, 18, 12)
        recent_layout.setSpacing(4)
        recent_layout.addWidget(ui.section("Recent entries", "Latest changes",
                                           ui.button("View all", "chevron-right", "Ghost",
                                                     on_click=lambda: self.ctx.navigate("vault"))))
        self.recent_rows = QVBoxLayout()
        self.recent_rows.setSpacing(2)
        recent_layout.addLayout(self.recent_rows)
        recent_layout.addStretch(1)
        lower.addWidget(self.recent_card, 3)

        side = QVBoxLayout()
        side.setSpacing(14)
        self.backup_card = ui.card()
        backup_layout = QVBoxLayout(self.backup_card)
        backup_layout.setContentsMargins(18, 16, 18, 16)
        backup_layout.setSpacing(8)
        top = QHBoxLayout()
        top.addWidget(ui.label("BACKUP", "Overline"))
        top.addStretch(1)
        top.addWidget(ui.icon_label("database-backup", theme.TEXT_2))
        backup_layout.addLayout(top)
        self.backup_value = ui.label("", "H2")
        self.backup_hint = ui.label("", "Faint", wrap=True)
        backup_layout.addWidget(self.backup_value)
        backup_layout.addWidget(self.backup_hint)
        backup_layout.addWidget(ui.button("Manage backups", "chevron-right",
                                          on_click=lambda: self.ctx.navigate("backups")))
        side.addWidget(self.backup_card)

        actions = ui.card()
        actions_layout = QVBoxLayout(actions)
        actions_layout.setContentsMargins(18, 16, 18, 16)
        actions_layout.setSpacing(8)
        actions_layout.addWidget(ui.label("QUICK ACTIONS", "Overline"))
        for text, icon, target in (("Add an entry", "plus", "new_entry"),
                                   ("Generate a password", "wand-sparkles", "generator"),
                                   ("Analyze security", "shield-check", "security")):
            button = ui.button(text, icon, on_click=lambda t=target: self.ctx.navigate(t))
            button.setStyleSheet("text-align: left;")
            actions_layout.addWidget(button)
        side.addWidget(actions)
        side.addStretch(1)
        lower.addLayout(side, 2)
        layout.addLayout(lower)
        layout.addStretch(1)

    def on_show(self, **kwargs) -> None:
        hour = datetime.now().astimezone().hour
        name = _first_name()
        salutation = "Good evening" if hour >= 18 or hour < 5 else "Hello"
        self.greeting.setText(f"{salutation}{', ' + name if name else ''}")
        self.status.setText("Analyzing the vault…")
        self.skeleton.show()
        # The audit decrypts the entries: let the view show first.
        QTimer.singleShot(0, self.refresh)

    def refresh(self) -> None:
        if self.ctx.vault.is_locked:
            return
        report = run_audit(self.ctx.entries)
        flagged = {f.entry_id for f in report.findings}
        old = {f.entry_id for f in report.by_kind(KIND_OLD)}
        review = {f.entry_id for f in report.findings if f.kind != KIND_OLD}
        total = report.checked_entries
        self.skeleton.hide()
        self.cards["total"].set_value(total, "in this vault")
        self.cards["secure"].set_value(total - len(flagged), "no issue found")
        self.cards["review"].set_value(len(review), "weak, reused, missing…")
        self.cards["old"].set_value(len(old), "password older than one year")
        if total == 0:
            self.status.setText("Your vault is ready. Add your first entry.")
            self.status.setStyleSheet(f"color: {theme.TEXT_2};")
        elif not review:
            self.status.setText("Your vault is secure.")
            self.status.setStyleSheet(f"color: {theme.ACCENT_2};")
        else:
            count = len(review)
            self.status.setText(f"{count} entr{'ies' if count > 1 else 'y'} "
                                f"need{'' if count > 1 else 's'} your attention.")
            self.status.setStyleSheet(f"color: {theme.WARNING};")
        latest = last_activity(self.ctx.vault)
        self.activity.setText(f"Last activity: {relative_date(latest)}" if latest
                              else "No activity yet.")
        self._fill_recent()
        self._fill_backup()
        effects.stagger(list(self.cards.values()))

    def _fill_recent(self) -> None:
        while self.recent_rows.count():
            item = self.recent_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        rows = sorted(self.ctx.entries.list_entries(), key=lambda s: s.updated_at, reverse=True)[:5]
        if not rows:
            empty = ui.EmptyState("key-round", "No entries",
                                  "Your recent entries will appear here.",
                                  "Add an entry", lambda: self.ctx.navigate("new_entry"))
            self.recent_rows.addWidget(empty)
            return
        widgets = [_RecentRow(s, lambda i: self.ctx.navigate("vault", entry_id=i)) for s in rows]
        for widget in widgets:
            self.recent_rows.addWidget(widget)
        effects.stagger(widgets)

    def _fill_backup(self) -> None:
        try:
            infos = backup.list_backups(backup_directory(self.ctx.settings()),
                                        self.ctx.vault.vault_id)
        except OSError:
            infos = []
        if infos:
            self.backup_value.setText(relative_date(infos[0].created_at).capitalize())
            self.backup_hint.setText(f"Encrypted backup ({backup.kind_label(infos[0].kind)}) · "
                                     f"{len(infos)} available")
        else:
            self.backup_value.setText("No backup")
            self.backup_hint.setText("An encrypted backup is created automatically on "
                                     "locking after a change.")

    def wipe(self) -> None:
        while self.recent_rows.count():
            item = self.recent_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

