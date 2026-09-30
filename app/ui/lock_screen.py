"""Écrans du coffre verrouillé : déverrouillage et création d'un coffre.

Composition : fond sombre à halo très doux, icône bouclier-cadenas dans un
halo qui « respire » lentement (seule animation continue), nom de
l'application, état, champ du mot de passe maître, action principale, liens
secondaires, ligne technique en pied de page. Mauvais mot de passe : légère
secousse. Réussite : le cadenas s'ouvre, puis l'interface glisse vers la
gauche (géré par la fenêtre principale).

Ces écrans ne touchent ni au coffre ni à la cryptographie : ils émettent une
demande que la fenêtre principale transmet au cœur. Les champs de mot de
passe sont vidés après chaque tentative.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QRadialGradient
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from app import __version__
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, VaultInfo
from app.ui import components as ui
from app.ui import dialogs, effects, theme
from app.ui.fields import PasswordField

COLUMN_WIDTH = 380


class _LockBackground(QWidget):
    """Fond : halo émeraude très discret derrière la colonne, bords assombris."""

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
        created = datetime.fromisoformat(info.created_at).astimezone().strftime("%d/%m/%Y")
    except ValueError:
        return f"{info.vault_name} ({info.vault_id})"
    return f"{info.vault_name} — créé le {created}"


class _LockLayout(QWidget):
    """Squelette commun : colonne centrée + pied de page technique."""

    def __init__(self, icon: str, title: str, subtitle: str) -> None:
        super().__init__()
        background = _LockBackground(self)
        self._background = background
        self.card = QWidget()  # la colonne (cible de la secousse)
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
        footer.addWidget(ui.label("AES-256-GCM · Argon2id · 100 % hors ligne", "Faint"))
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
    unlock_requested = Signal(str, str)  # vault_id, mot de passe maître
    recovery_requested = Signal(str)     # vault_id : mot de passe maître oublié
    restore_requested = Signal()
    new_vault_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("lock-keyhole", "Mon Coffre-Fort", "Votre coffre est verrouillé")
        if parent is not None:
            self.setParent(parent)
        self.info = ui.label("", "BadgeAccent", wrap=True)
        self.info.setAlignment(Qt.AlignCenter)
        self.info.hide()
        self.column.addWidget(self.info)

        self.vault_combo = QComboBox()
        self.vault_combo.setToolTip("Coffre à déverrouiller")
        self.vault_label = ui.label("", "Badge")
        self.vault_label.setAlignment(Qt.AlignCenter)
        self.column.addWidget(self.vault_combo)
        self.column.addWidget(self.vault_label, 0, Qt.AlignHCenter)

        self.password = PasswordField("Mot de passe maître", leading_icon="lock")
        self.password.setMinimumHeight(44)
        self.password.returnPressed.connect(self._submit)
        self.column.addWidget(self.password)
        self.error = ui.label("", "Error", wrap=True)
        self.error.setAlignment(Qt.AlignCenter)
        self.error.hide()
        self.column.addWidget(self.error)
        self.button = ui.button("Déverrouiller", "lock-open", "Primary",
                                "Déverrouiller  ·  Entrée", self._submit)
        self.button.setMinimumHeight(44)
        self.column.addWidget(self.button)
        self.busy_row, self.spinner, self.busy_status = super().busy_row()
        self.column.addWidget(self.busy_row)
        self.forgot = self.link("Mot de passe oublié ?", "key-round")
        self.forgot.clicked.connect(self._forgot)
        self.column.addWidget(self.forgot, 0, Qt.AlignHCenter)
        links = QHBoxLayout()
        links.setSpacing(4)
        links.addStretch(1)
        new_vault = self.link("Nouveau coffre", "plus")
        new_vault.clicked.connect(lambda: self.new_vault_requested.emit())
        restore = self.link("Restaurer une sauvegarde", "rotate-ccw")
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
        self.halo.set_icon("lock-keyhole", theme.ACCENT_2)
        self.set_busy(False)
        self.password.setFocus()

    def set_busy(self, busy: bool) -> None:
        for widget in (self.button, self.password, self.vault_combo, self.forgot):
            widget.setEnabled(not busy)
        self.button.setVisible(not busy)
        self.busy_row.setVisible(busy)
        if busy:  # nouvelle tentative : les messages précédents disparaissent
            self.error.hide()
            self.info.hide()
            self.busy_status.setText("Vérification du mot de passe maître…")
            self.spinner.start()
        else:
            self.spinner.stop()

    def show_success(self) -> None:
        """Micro-interaction : le cadenas s'ouvre juste avant la transition."""
        self.spinner.stop()
        self.busy_status.setText("Coffre déverrouillé")
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
            self.show_error("Saisissez votre mot de passe maître.")
            return
        self.unlock_requested.emit(vault_id, password)


class CreateVaultScreen(_LockLayout):
    create_requested = Signal(str, str, bool)  # nom, mot de passe maître, clé de récupération
    restore_requested = Signal()
    back_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("shield-check", "Bienvenue",
                         "Créez votre coffre-fort chiffré. Le mot de passe maître n'est "
                         "stocké nulle part : sans lui, seule la clé de récupération permet "
                         "de retrouver l'accès.")
        if parent is not None:
            self.setParent(parent)
        self.name = QLineEdit("Personnel")
        self.name.setPlaceholderText("Nom du coffre")
        self.name.addAction(ui.lucide.icon("lock-keyhole", theme.TEXT_3, 16),
                            QLineEdit.LeadingPosition)
        self.password = PasswordField(
            f"Mot de passe maître ({MIN_MASTER_PASSWORD_LENGTH} caractères minimum)",
            leading_icon="lock")
        self.confirm = PasswordField("Confirmez le mot de passe maître", leading_icon="lock")
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
        self.with_recovery = ui.ToggleSwitch("Créer une clé de récupération (recommandé)")
        self.with_recovery.setToolTip(
            "Un code à noter sur papier, qui permet de choisir un nouveau mot de passe "
            "maître en cas d'oubli.")
        self.with_recovery.setChecked(True)
        self.column.addWidget(self.with_recovery)
        self.error = ui.label("", "Error", wrap=True)
        self.error.setAlignment(Qt.AlignCenter)
        self.error.hide()
        self.column.addWidget(self.error)
        self.button = ui.button("Créer le coffre", "shield-check", "Primary",
                                on_click=self._submit)
        self.button.setMinimumHeight(44)
        self.column.addWidget(self.button)
        self.busy_row, self.spinner, self.busy_status = super().busy_row()
        self.column.addWidget(self.busy_row)
        links = QHBoxLayout()
        links.addStretch(1)
        self.back = self.link("Retour", "log-out")
        self.back.clicked.connect(lambda: self.back_requested.emit())
        restore = self.link("Restaurer une sauvegarde", "rotate-ccw")
        restore.clicked.connect(lambda: self.restore_requested.emit())
        links.addWidget(self.back)
        links.addWidget(restore)
        links.addStretch(1)
        self.column.addLayout(links)

    def set_first_vault(self, first: bool) -> None:
        self.title.setText("Bienvenue" if first else "Nouveau coffre")
        self.back.setVisible(not first)
        self.name.setText("Personnel" if first else "")

    def _update_strength(self, text: str) -> None:
        if not text:
            self.strength.set_score(-1, 0)
            self.strength_label.setText("")
            return
        result = estimate_strength(text)
        self.strength.set_score(result.score, result.entropy_bits)
        self.strength_label.setText(f"{result.label} · ~{result.entropy_bits:.0f} bits")

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
            self.busy_status.setText("Génération des clés (Argon2id)…")
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
            self.show_error("Donnez un nom à votre coffre.")
            return
        if password != confirm:
            self.show_error("Les deux mots de passe ne correspondent pas.")
            self.password.setFocus()
            return
        weak = (len(password) >= MIN_MASTER_PASSWORD_LENGTH
                and estimate_strength(password).score < 2)
        if weak and not dialogs.confirm(
                self, "Mot de passe maître faible",
                "Il protège TOUS vos mots de passe et semble facile à deviner. Une phrase "
                "de passe de 5 à 6 mots est recommandée.", "Utiliser quand même",
                danger=True, icon="shield-alert"):
            self.password.setFocus()
            return
        # La politique (longueur minimale) est vérifiée par le cœur (Vault.create).
        self.create_requested.emit(name, password, self.with_recovery.isChecked())
