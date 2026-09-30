"""Locked vault screens: unlocking and creating a vault.

Layout: dark background with a very soft halo, the application logo in a
slowly "breathing" halo (the only continuous animation), application name,
state, master password field, primary action, secondary links, technical line
in the footer. Wrong password: slight shake. Success: an open padlock replaces
the logo, then the interface slides to the left (handled by the main window).

These screens touch neither the vault nor the cryptography: they emit a
request that the main window passes on to the core. The password fields are
cleared after each attempt.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QRadialGradient
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from app import __version__
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, VaultInfo
from app.i18n import tr
from app.ui import components as ui
from app.ui import dialogs, effects, theme
from app.ui.fields import PasswordField

COLUMN_WIDTH = 380


class _LockBackground(QWidget):
    """Background: very subtle emerald halo behind the column, darkened edges."""

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(theme.BG))
        center = QPointF(self.width() / 2, self.height() * 0.38)
        glow = QRadialGradient(center, max(self.width(), self.height()) * 0.55)
        glow.setColorAt(0.0, theme.rgba(theme.ACCENT, 20))
        glow.setColorAt(0.45, theme.rgba(theme.INFO, 6))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.fillRect(self.rect(), glow)


def _vault_label(info: VaultInfo, duplicate: bool) -> str:
    if not duplicate or not info.created_at:
        return info.vault_name
    try:
        created = datetime.fromisoformat(info.created_at).astimezone().strftime("%Y-%m-%d")
    except ValueError:
        return f"{info.vault_name} ({info.vault_id})"
    return tr("lock.vault_created_on", name=info.vault_name, date=created)


class _LockLayout(QWidget):
    """Shared skeleton: centered column + technical footer."""

    def __init__(self, icon: str, title: str, subtitle: str) -> None:
        super().__init__()
        background = _LockBackground(self)
        self._background = background
        self.card = QWidget()  # the column (target of the shake)
        self.card.setFixedWidth(COLUMN_WIDTH)
        self.column = QVBoxLayout(self.card)
        self.column.setContentsMargins(0, 0, 0, 0)
        self.column.setSpacing(12)
        self.halo = ui.HaloIcon(icon, 132)
        self.column.addWidget(self.halo, 0, Qt.AlignHCenter)
        self.title = ui.label(title, "H1")
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setFont(theme.font(27, self.title.font().weight(), display=True))
        self.column.addWidget(self.title)
        self.subtitle = ui.label(subtitle, "Muted", wrap=True)
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setFont(theme.font(15))
        self.column.addWidget(self.subtitle)
        self.column.addSpacing(10)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        footer.addStretch(1)
        footer.addWidget(ui.icon_label("shield-check", theme.TEXT_3, 14))
        footer.addWidget(ui.label(tr("lock.footer"), "Faint"))
        footer.addStretch(1)
        version = ui.label(f"v{__version__}", "Faint")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 20)
        outer.addStretch(3)
        outer.addWidget(self.card, 0, Qt.AlignHCenter)
        outer.addStretch(4)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addLayout(footer)
        bottom.addStretch(1)
        outer.addLayout(bottom)
        version.setParent(self)
        self._version = version

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._background.setGeometry(self.rect())
        self._background.lower()
        self._version.adjustSize()
        self._version.move(self.width() - self._version.width() - 20,
                           self.height() - self._version.height() - 20)

    def busy_row(self) -> tuple[QWidget, effects.Spinner, QWidget]:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addStretch(1)
        spinner = effects.Spinner(16)
        status = ui.label("", "Muted")
        layout.addWidget(spinner)
        layout.addWidget(status)
        layout.addStretch(1)
        row.hide()
        return row, spinner, status

    @staticmethod
    def link(text: str, icon: str) -> QWidget:
        button = ui.button(text, icon, "Ghost")
        return button


class UnlockScreen(_LockLayout):
    unlock_requested = Signal(str, str)  # vault_id, master password
    recovery_requested = Signal(str)     # vault_id: forgotten master password
    restore_requested = Signal()
    new_vault_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(ui.BRAND, "Keyra", tr("lock.subtitle"))
        if parent is not None:
            self.setParent(parent)
        self.info = ui.label("", "BadgeAccent", wrap=True)
        self.info.setAlignment(Qt.AlignCenter)
        self.info.hide()
        self.column.addWidget(self.info)

        self.vault_combo = QComboBox()
        self.vault_combo.setToolTip(tr("lock.vault_combo"))
        self.vault_label = ui.label("", "Badge")
        self.vault_label.setAlignment(Qt.AlignCenter)
        self.column.addWidget(self.vault_combo)
        self.column.addWidget(self.vault_label, 0, Qt.AlignHCenter)

        self.password = PasswordField(tr("common.master_password"), leading_icon="lock")
        self.password.setMinimumHeight(44)
        self.password.returnPressed.connect(self._submit)
        self.column.addWidget(self.password)
        self.error = ui.label("", "Error", wrap=True)
        self.error.setAlignment(Qt.AlignCenter)
        self.error.hide()
        self.column.addWidget(self.error)
        self.button = ui.button(tr("lock.unlock"), "lock-open", "Primary",
                                tr("lock.unlock.tooltip"), self._submit)
        self.button.setMinimumHeight(44)
        self.column.addWidget(self.button)
        self.busy_row, self.spinner, self.busy_status = super().busy_row()
        self.column.addWidget(self.busy_row)
        self.forgot = self.link(tr("lock.forgot_password"), "key-round")
        self.forgot.clicked.connect(self._forgot)
        self.column.addWidget(self.forgot, 0, Qt.AlignHCenter)
        links = QHBoxLayout()
        links.setSpacing(4)
        links.addStretch(1)
        new_vault = self.link(tr("lock.new_vault"), "plus")
        new_vault.clicked.connect(lambda: self.new_vault_requested.emit())
        restore = self.link(tr("lock.restore_backup"), "rotate-ccw")
        restore.clicked.connect(lambda: self.restore_requested.emit())
        links.addWidget(new_vault)
        links.addWidget(restore)
        links.addStretch(1)
        self.column.addLayout(links)

    def set_vaults(self, vaults: list[VaultInfo], selected_id: str | None = None) -> None:
        self.vault_combo.clear()
        names = [v.vault_name for v in vaults]
        for info in vaults:
            self.vault_combo.addItem(ui.lucide.icon("lock-keyhole", theme.TEXT_2, 16),
                                     _vault_label(info, names.count(info.vault_name) > 1),
                                     info.vault_id)
        if selected_id is not None:
            index = self.vault_combo.findData(selected_id)
            if index >= 0:
                self.vault_combo.setCurrentIndex(index)
        single = len(vaults) == 1
        self.vault_combo.setVisible(not single)
        self.vault_label.setVisible(single)
        if single:
            self.vault_label.setText(vaults[0].vault_name)

    def prepare(self, info: str = "") -> None:
        self.password.reset()
        self.error.hide()
        self.info.setText(info)
        self.info.setVisible(bool(info))
        self.halo.set_icon(ui.BRAND, theme.ACCENT_2)
        self.set_busy(False)
        self.password.setFocus()

    def set_busy(self, busy: bool) -> None:
        for widget in (self.button, self.password, self.vault_combo, self.forgot):
            widget.setEnabled(not busy)
        self.button.setVisible(not busy)
        self.busy_row.setVisible(busy)
        if busy:  # new attempt: previous messages disappear
            self.error.hide()
            self.info.hide()
            self.busy_status.setText(tr("lock.checking"))
            self.spinner.start()
        else:
            self.spinner.stop()

    def show_success(self) -> None:
        """Micro-interaction: an open padlock replaces the logo just before the transition."""
        self.spinner.stop()
        self.busy_status.setText(tr("shell.vault_unlocked"))
        self.halo.set_icon("lock-open", theme.ACCENT_2)

    def show_error(self, message: str) -> None:
        self.info.hide()
        self.error.setText(message)
        self.error.show()
        effects.shake(self.card)
        self.password.setFocus()

    def _forgot(self) -> None:
        vault_id = self.vault_combo.currentData()
        if vault_id:
            self.recovery_requested.emit(vault_id)

    def _submit(self) -> None:
        vault_id = self.vault_combo.currentData()
        password = self.password.text()
        self.password.reset()
        if not vault_id:
            return
        if not password:
            self.show_error(tr("lock.enter_password"))
            return
        self.unlock_requested.emit(vault_id, password)


class CreateVaultScreen(_LockLayout):
    create_requested = Signal(str, str, bool)  # name, master password, recovery key
    restore_requested = Signal()
    back_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(ui.BRAND, tr("create.welcome"),
                         tr("create.intro"))
        if parent is not None:
            self.setParent(parent)
        self.name = QLineEdit(tr("create.default_name"))
        self.name.setPlaceholderText(tr("create.name_placeholder"))
        self.name.addAction(ui.lucide.icon("lock-keyhole", theme.TEXT_3, 16),
                            QLineEdit.LeadingPosition)
        self.password = PasswordField(
            tr("create.password_placeholder", min=MIN_MASTER_PASSWORD_LENGTH),
            leading_icon="lock")
        self.confirm = PasswordField(tr("create.confirm_placeholder"), leading_icon="lock")
        self.confirm.returnPressed.connect(self._submit)
        self.strength = ui.StrengthBar()
        self.strength_label = ui.label("", "Faint")
        self.password.textChanged.connect(self._update_strength)
        for widget in (self.name, self.password):
            widget.setMinimumHeight(42)
        self.confirm.setMinimumHeight(42)
        self.column.addWidget(self.name)
        self.column.addWidget(self.password)
        self.column.addWidget(self.strength)
        self.column.addWidget(self.strength_label)
        self.column.addWidget(self.confirm)
        self.with_recovery = ui.ToggleSwitch(tr("create.with_recovery"))
        self.with_recovery.setToolTip(
            tr("create.with_recovery.tooltip"))
        self.with_recovery.setChecked(True)
        self.column.addWidget(self.with_recovery)
        self.error = ui.label("", "Error", wrap=True)
        self.error.setAlignment(Qt.AlignCenter)
        self.error.hide()
        self.column.addWidget(self.error)
        self.button = ui.button(tr("create.submit"), "shield-check", "Primary",
                                on_click=self._submit)
        self.button.setMinimumHeight(44)
        self.column.addWidget(self.button)
        self.busy_row, self.spinner, self.busy_status = super().busy_row()
        self.column.addWidget(self.busy_row)
        links = QHBoxLayout()
        links.addStretch(1)
        self.back = self.link(tr("common.back"), "log-out")
        self.back.clicked.connect(lambda: self.back_requested.emit())
        restore = self.link(tr("lock.restore_backup"), "rotate-ccw")
        restore.clicked.connect(lambda: self.restore_requested.emit())
        links.addWidget(self.back)
        links.addWidget(restore)
        links.addStretch(1)
        self.column.addLayout(links)

    def set_first_vault(self, first: bool) -> None:
        self.title.setText(tr("create.welcome") if first else tr("lock.new_vault"))
        self.back.setVisible(not first)
        self.name.setText(tr("create.default_name") if first else "")

    def _update_strength(self, text: str) -> None:
        if not text:
            self.strength.set_score(-1, 0)
            self.strength_label.setText("")
            return
        result = estimate_strength(text)
        self.strength.set_score(result.score, result.entropy_bits)
        self.strength_label.setText(tr("strength.summary", label=result.label,
                                       bits=f"{result.entropy_bits:.0f}"))

    def prepare(self) -> None:
        self.password.reset()
        self.confirm.reset()
        self._update_strength("")
        self.error.hide()
        self.set_busy(False)
        self.password.setFocus()

    def set_busy(self, busy: bool) -> None:
        for widget in (self.button, self.name, self.password, self.confirm, self.with_recovery):
            widget.setEnabled(not busy)
        self.button.setVisible(not busy)
        self.busy_row.setVisible(busy)
        if busy:
            self.error.hide()
            self.busy_status.setText(tr("create.generating"))
            self.spinner.start()
        else:
            self.spinner.stop()

    def show_error(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        effects.shake(self.card)

    def _submit(self) -> None:
        name = self.name.text().strip()
        password = self.password.text()
        confirm = self.confirm.text()
        self.password.reset()
        self.confirm.reset()
        if not name:
            self.show_error(tr("create.error.name"))
            return
        if password != confirm:
            self.show_error(tr("create.error.mismatch"))
            self.password.setFocus()
            return
        weak = (len(password) >= MIN_MASTER_PASSWORD_LENGTH
                and estimate_strength(password).score < 2)
        if weak and not dialogs.confirm(
                self, tr("create.weak.title"),
                tr("create.weak.body"), tr("create.weak.confirm"),
                danger=True, icon="shield-alert"):
            self.password.setFocus()
            return
        # The policy (minimum length) is checked by the core (Vault.create).
        self.create_requested.emit(name, password, self.with_recovery.isChecked())
