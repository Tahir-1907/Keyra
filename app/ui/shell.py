"""Shell of the unlocked application: sidebar, header, views.

* Sidebar (236 px): brand, current vault (menu), navigation with counters,
  accent indicator that SLIDES to the active item, lock state (countdown) and
  Lock button.
* Minimal header: view title, search, Generate, New, lock.
* Compact mode (narrow window, e.g. snapped to half of the screen): sidebar
  reduced to icons (labels as tooltips), shorter search, "Generate" as an
  icon only.
* Directional view change: a "next" view comes in from the right, a
  "previous" one from the left (+/-20 px, fade, 220 ms).
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRect, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.categories import CategoryService
from app.core.entries import EntryService, tag_search_query
from app.core.session import SessionManager
from app.i18n import tr
from app.services.settings import Settings
from app.ui import components as ui
from app.ui import effects, lucide, theme
from app.ui.generator_dialog import GeneratorDialog
from app.ui.pages.backups import BackupsPage
from app.ui.pages.base import AppContext, Page
from app.ui.pages.dashboard import DashboardPage
from app.ui.pages.history import HistoryPage
from app.ui.pages.security import SecurityPage
from app.ui.pages.settings import SettingsPage
from app.ui.pages.trash import TrashPage
from app.ui.pages.vault import VaultPage
from app.ui.secure_clipboard import SecureClipboard
from app.ui.vault_dialogs import AboutDialog, ShortcutsDialog

NAV_ORDER = ("dashboard", "vault", "security", "history", "trash", "backups", "settings")


class NavButton(QPushButton):
    """Navigation item: icon, label, optional counter."""

    def __init__(self, icon: str, text: str, tooltip: str = "") -> None:
        super().__init__()
        self.setObjectName("Nav")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(tooltip or text)
        self.setAccessibleName(text)
        self.setMinimumHeight(38)
        self._icon = icon
        self._count: int | None = None
        self._compact = False
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 10, 0)
        row.setSpacing(11)
        self.icon_label = QLabel()
        self.icon_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        row.addWidget(self.icon_label)
        self.text_label = QLabel(text)
        self.text_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        row.addWidget(self.text_label, 1)
        self.badge = QLabel()
        self.badge.setObjectName("Badge")
        self.badge.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.badge.hide()
        row.addWidget(self.badge)
        self.toggled.connect(self._restyle)
        self._restyle(False)

    def _restyle(self, checked: bool) -> None:
        color = theme.ACCENT_2 if checked else theme.TEXT_2
        self.icon_label.setPixmap(lucide.pixmap(self._icon, color, 18))
        self.text_label.setStyleSheet(f"color: {theme.TEXT if checked else theme.TEXT_2};"
                                      f" font-weight: {600 if checked else 500};")

    def set_count(self, count: int | None) -> None:
        self._count = count
        self.badge.setVisible(bool(count) and not self._compact)
        self.badge.setText(str(count or ""))

    def set_compact(self, compact: bool) -> None:
        self._compact = compact
        self.text_label.setVisible(not compact)
        self.badge.setVisible(bool(self._count) and not compact)
        layout = self.layout()
        if compact:
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setAlignment(self.icon_label, Qt.AlignCenter)
        else:
            layout.setContentsMargins(12, 0, 10, 0)
            layout.setAlignment(self.icon_label, Qt.Alignment())


class _Indicator(QFrame):
    """Vertical accent bar that slides from one navigation item to another."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setStyleSheet(f"background: {theme.ACCENT}; border-radius: 1.5px;")
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._animation = QPropertyAnimation(self, b"geometry", self)
        self._animation.setDuration(theme.DURATION_BASE)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self.hide()

    def move_to(self, button: QWidget) -> None:
        top_left = button.mapTo(self.parentWidget(), button.rect().topLeft())
        target = QRect(top_left.x() - 7, top_left.y() + 10, 3, button.height() - 20)
        if not self.isVisible() or not effects.animations_enabled():
            self.setGeometry(target)
            self.show()
            self.raise_()
            return
        self._animation.stop()
        self._animation.setStartValue(self.geometry())
        self._animation.setEndValue(target)
        self._animation.start()
        self.raise_()


class AppShell(QWidget):
    lock_requested = Signal()

    def __init__(self, session: SessionManager, clipboard: SecureClipboard,
                 settings: Callable[[], Settings], notify: Callable[..., None],
                 vault_action: Callable[[str], None],
                 update_settings: Callable[[Settings], None]) -> None:
        super().__init__()
        self.setObjectName("Root")
        self.ctx = AppContext(
            session=session, entries=EntryService(session.vault),
            categories=CategoryService(session.vault), clipboard=clipboard, settings=settings,
            notify=notify, navigate=self.navigate, changed=self.data_changed,
            vault_action=vault_action, update_settings=update_settings,
        )
        self.pages: dict[str, Page] = {}
        self._current = ""

        # --- Sidebar -------------------------------------------------------------------
        sidebar = self.sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(theme.SIDEBAR_WIDTH)
        side = self._side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 20, 16, 16)
        side.setSpacing(4)
        brand = QHBoxLayout()
        brand.setSpacing(10)
        brand.addWidget(ui.brand_label(22))
        self.brand_text = ui.label("KEYRA", "Brand")
        brand.addWidget(self.brand_text, 1)
        side.addLayout(brand)
        side.addSpacing(14)
        self.vault_button = QPushButton()
        self.vault_button.setObjectName("Nav")
        self.vault_button.setCursor(Qt.PointingHandCursor)
        self.vault_button.setToolTip(tr("shell.vault_button.tooltip"))
        self.vault_button.setIcon(lucide.icon("lock-keyhole", theme.TEXT_2, 16))
        self.vault_button.setStyleSheet(
            f"QPushButton#Nav {{ background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; }}")
        vault_menu = QMenu(self.vault_button)
        vault_menu.addAction(lucide.icon("log-out"), tr("action.switch_vault"),
                             lambda: self.ctx.vault_action("switch"))
        vault_menu.addAction(lucide.icon("plus"), tr("action.new_vault"),
                             lambda: self.ctx.vault_action("new"))
        vault_menu.addSeparator()
        vault_menu.addAction(lucide.icon("settings"), tr("shell.vault_settings"),
                             lambda: self.navigate("settings"))
        self.vault_button.setMenu(vault_menu)
        side.addWidget(self.vault_button)
        side.addSpacing(10)
        side.addWidget(ui.divider())
        side.addSpacing(10)

        self.nav: dict[str, NavButton] = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        page_classes = (DashboardPage, VaultPage, SecurityPage, HistoryPage, TrashPage,
                        BackupsPage, SettingsPage)
        shortcuts = {"dashboard": "Alt+1", "vault": "Alt+2", "security": "Alt+3",
                     "history": "Alt+4", "trash": "Alt+5", "backups": "Alt+6",
                     "settings": "Ctrl+,"}
        self.stack = QStackedWidget()
        for cls in page_classes:
            page = cls(self.ctx)
            self.pages[cls.key] = page
            self.stack.addWidget(page)
            title = tr(cls.title_key)
            button = NavButton(cls.icon, title, f"{title}  ·  {shortcuts[cls.key]}")
            button.clicked.connect(lambda _c=False, k=cls.key: self.navigate(k))
            group.addButton(button)
            self.nav[cls.key] = button
            if cls.key == "settings":
                side.addStretch(1)
                side.addWidget(ui.divider())
                side.addSpacing(8)
            side.addWidget(button)
        self.indicator = _Indicator(sidebar)

        side.addSpacing(10)
        status = QFrame()
        status.setObjectName("Card")
        status_layout = self._status_layout = QVBoxLayout(status)
        status_layout.setContentsMargins(12, 10, 12, 10)
        status_layout.setSpacing(6)
        state = QHBoxLayout()
        state.setSpacing(8)
        self.state_icon = ui.icon_label("lock-open", theme.ACCENT_2, 16)
        state.addWidget(self.state_icon)
        self.state_text = ui.label(tr("shell.vault_unlocked"))
        state.addWidget(self.state_text, 1)
        status_layout.addLayout(state)
        self.countdown = ui.label("", "Faint")
        status_layout.addWidget(self.countdown)
        lock = self.side_lock = ui.button(tr("action.lock"), "lock",
                                          tooltip=tr("shell.lock.tooltip"),
                                          on_click=self.lock_requested.emit)
        status_layout.addWidget(lock)
        side.addWidget(status)

        # --- Header --------------------------------------------------------------------------
        header = QFrame()
        header.setObjectName("Header")
        header.setFixedHeight(theme.HEADER_HEIGHT)
        head = QHBoxLayout(header)
        head.setContentsMargins(28, 0, 20, 0)
        head.setSpacing(10)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addStretch(1)
        self.title = ui.label("", "ViewTitle")
        self.title.setFont(theme.font(19, self.title.font().weight()))
        self.subtitle = ui.label("", "Faint")
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        titles.addStretch(1)
        head.addLayout(titles, 1)
        self.search = QLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText(tr("shell.search.placeholder"))
        self.search.setToolTip(tr("shell.search.tooltip"))
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(theme.SEARCH_MIN_WIDTH)
        self.search.setMaximumWidth(theme.SEARCH_MAX_WIDTH)
        self.search.addAction(lucide.icon("search", theme.TEXT_3, 16), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self._on_search)
        # Enter: applies the search without waiting for the typing delay.
        self.search.returnPressed.connect(lambda: self.vault_page.apply_search_now())
        self.vault_page.detail.tag_clicked.connect(self.search_tag)
        head.addWidget(self.search)
        self.generate_button = ui.button(tr("shell.generate"), "wand-sparkles", "Ghost",
                                         tr("shell.generate.tooltip"),
                                         self.open_generator)
        head.addWidget(self.generate_button)
        new = ui.button(tr("shell.new"), "plus", "Primary", tr("shell.new.tooltip"),
                        lambda: self.navigate("new_entry"))
        head.addWidget(new)
        head.addWidget(ui.icon_button("lock", tr("action.lock"), "Ctrl+L",
                                      self.lock_requested.emit))

        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(0)
        content.addWidget(header)
        content.addWidget(self.stack, 1)
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(sidebar)
        root.addLayout(content, 1)

        self._compact = False
        self.update_vault_name()
        self.navigate("dashboard")

    # --- Navigation ---------------------------------------------------------------------------

    def navigate(self, key: str, **kwargs) -> None:
        if key == "new_entry":
            self.navigate("vault")
            self.vault_page.new_entry()
            return
        if key == "generator":
            self.open_generator()
            return
        if key == "shortcuts":
            ShortcutsDialog(self).exec()
            return
        if key == "about":
            AboutDialog(self).exec()
            return
        page = self.pages[key]
        previous = self._current
        self._current = key
        self.nav[key].setChecked(True)
        self.indicator.move_to(self.nav[key])
        self.title.setText(page.title)
        self.subtitle.setText(page.subtitle)
        if previous != key:
            direction = 1 if (not previous or
                              NAV_ORDER.index(key) >= NAV_ORDER.index(previous)) else -1
            effects.switch_page(self.stack, page, direction)
            effects.fade_in(self.title, theme.DURATION_FAST)
        if key == "vault" and "entry_id" in kwargs:
            self.vault_page.open_entry(kwargs["entry_id"])
        elif key == "vault":
            self.vault_page.refresh()
        else:
            page.on_show(**kwargs)
        self.update_badges()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._current:
            self.indicator.move_to(self.nav[self._current])

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.set_compact(event.size().width() < theme.COMPACT_BREAKPOINT)
        if self._current and self.indicator.isVisible():
            self.indicator.setGeometry(self.indicator.geometry())  # realigned on the next navigate
            self.indicator.move_to(self.nav[self._current])

    @property
    def is_compact(self) -> bool:
        return self._compact

    def set_compact(self, compact: bool) -> None:
        """Switches between the narrow (icons only) and the wide layout."""
        if compact == self._compact:
            return
        self._compact = compact
        self.sidebar.setFixedWidth(theme.SIDEBAR_COMPACT_WIDTH if compact else theme.SIDEBAR_WIDTH)
        self._side.setContentsMargins(*((12, 20, 12, 16) if compact else (16, 20, 16, 16)))
        self.brand_text.setVisible(not compact)
        self.state_text.setVisible(not compact)
        self.state_icon.setVisible(not compact)
        self.countdown.setVisible(not compact)
        self._status_layout.setContentsMargins(*((0, 0, 0, 0) if compact else (12, 10, 12, 10)))
        for button in self.nav.values():
            button.set_compact(compact)
        self.side_lock.setText("" if compact else tr("action.lock"))
        self.generate_button.setText("" if compact else tr("shell.generate"))
        self.subtitle.setVisible(not compact)
        self.update_vault_name()
        if self._current:
            self.indicator.move_to(self.nav[self._current])

    @property
    def current_key(self) -> str:
        return self._current

    @property
    def vault_page(self) -> VaultPage:
        return self.pages["vault"]  # type: ignore[return-value]

    # --- Search, generator ------------------------------------------------------------------

    def _on_search(self, text: str) -> None:
        if text and self._current != "vault":
            self.navigate("vault")
        self.vault_page.set_search(text)

    def search_tag(self, tag: str) -> None:
        """Click on a badge: exact search for this tag, applied immediately."""
        self.search.setText(tag_search_query(tag))
        self.vault_page.apply_search_now()

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def open_generator(self) -> None:
        GeneratorDialog(self.ctx.clipboard, parent=self, settings=self.ctx.settings()).exec()

    # --- State ------------------------------------------------------------------------------------

    def data_changed(self) -> None:
        self.update_badges()
        self.update_vault_name()

    def update_badges(self) -> None:
        if self.ctx.vault.is_locked:
            return
        overview = self.ctx.categories.overview()
        self.nav["vault"].set_count(overview.total)
        self.nav["trash"].set_count(overview.trash)

    def recovery_changed(self) -> None:
        """The recovery key was created, replaced or removed."""
        if not self.ctx.vault.is_locked:
            self.pages["settings"].refresh_recovery()
            self.pages["security"].refresh_recovery()

    def update_vault_name(self) -> None:
        if not self.ctx.vault.is_locked:
            name = self.ctx.vault.info.vault_name
            self.vault_button.setText("" if self._compact else "  " + name)
            self.vault_button.setToolTip(tr("shell.vault_button.tooltip_named", name=name))

    def set_countdown(self, text: str, warn: bool = False) -> None:
        self.countdown.setText(text)
        self.countdown.setStyleSheet(f"color: {theme.WARNING};" if warn else "")

    def wipe(self) -> None:
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        for page in self.pages.values():
            page.wipe()

