"""Password / passphrase generator (premium modal).

All generation is done by app.core.generator (`secrets` randomness). On each
generation, the new value appears with a micro-animation (6 px slide + fade,
150 ms). Two uses: standalone (copy) or from an entry form ("Use").
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from app.core.generator import (
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_LENGTH,
    GeneratorError,
    PassphraseOptions,
    PasswordOptions,
    generate_passphrase,
    generate_password,
    load_passphrase_wordlist,
)
from app.core.strength import LABELS, score_for_bits
from app.i18n import qt as i18n_qt
from app.i18n import tr
from app.services.settings import Settings
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.dialogs import PremiumDialog
from app.ui.secure_clipboard import SecureClipboard

# (translation key of the label, separator)
_SEPARATORS = (("separator.dash", "-"), ("separator.space", " "), ("separator.dot", "."),
               ("separator.underscore", "_"), ("separator.none", ""))


class _GeneratedValue(QLabel):
    """Generated value, shown IN FULL (128 characters, 12 words…).

    It wraps anywhere and its font shrinks if needed; the height is fixed, so
    that the window does not jump while the slider moves. `text()` returns the
    exact value (without the break points).
    """

    LINES = 3
    SIZES = (17, 15, 13, 12)

    def __init__(self) -> None:
        super().__init__()
        self._value = ""
        self._by_words = False
        self.setWordWrap(True)
        self.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setMinimumWidth(40)
        self.setFixedHeight(self.LINES * QFontMetrics(theme.mono_font(self.SIZES[1])).lineSpacing())

    def text(self) -> str:  # the real value, not its display
        return self._value

    def setText(self, value: str, separator: str | None = None) -> None:  # name set by the Qt API
        """`separator` (passphrase): line breaks between words only."""
        self._value = value
        self._by_words = bool(separator)
        if self._by_words:
            super().setText(value.replace(separator, separator + "\u200b"))
        else:
            super().setText(ui.breakable(value))
        self._fit()

    def clear(self) -> None:
        self._value = ""
        super().clear()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit()

    def _fit(self) -> None:
        width = max(self.width(), 40)
        for size in self.SIZES:
            font = theme.mono_font(size)
            wrap = Qt.TextWordWrap if self._by_words else Qt.TextWrapAnywhere
            needed = QFontMetrics(font).boundingRect(0, 0, width, 10_000, wrap,
                                                     super().text()).height()
            if needed <= self.height():
                break
        self.setFont(font)


class GeneratorDialog(PremiumDialog):
    def __init__(self, clipboard: SecureClipboard, use_mode: bool = False,
                 parent: QWidget | None = None, settings: Settings | None = None) -> None:
        super().__init__(parent, tr("settings.generator.title"), tr("generator.subtitle"),
                         icon="wand-sparkles", width=520)
        settings = settings or Settings()
        self._clipboard = clipboard
        self.chosen_value: str | None = None
        self._ready = False

        # --- Result ---------------------------------------------------------------------
        self.result = _GeneratedValue()
        self.copy_button = ui.CopyButton(tr("generator.copy"))
        self.copy_button.clicked.connect(self._copy)
        result_host = QFrame()
        result_host.setObjectName("Generated")
        result_row = QHBoxLayout(result_host)
        result_row.setContentsMargins(16, 12, 10, 12)
        result_row.setSpacing(8)
        result_row.addWidget(self.result, 1)
        result_row.addWidget(self.copy_button, 0, Qt.AlignVCenter)
        self.body.addWidget(result_host)

        self.strength = ui.StrengthBar()
        self.strength_label = ui.label("", "Faint")
        self.body.addWidget(self.strength)
        self.body.addWidget(self.strength_label)

        # --- Mode ---------------------------------------------------------------------------
        self.password_chip = ui.button(tr("generator.mode.password"), "key-round", "Chip")
        self.passphrase_chip = ui.button(tr("generator.mode.passphrase"), "sticky-note", "Chip")
        modes = QButtonGroup(self)
        for chip in (self.password_chip, self.passphrase_chip):
            chip.setCheckable(True)
            modes.addButton(chip)
        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        mode_row.addWidget(self.password_chip)
        mode_row.addWidget(self.passphrase_chip)
        mode_row.addStretch(1)
        self.body.addSpacing(4)
        self.body.addLayout(mode_row)
        # Two option sets shown in turn (no stack: no leftover gap).
        self._mode = 0
        self._option_pages: list[QWidget] = []

        # --- "Password" options ------------------------------------------------------------
        pw = QWidget()
        pw_layout = QVBoxLayout(pw)
        pw_layout.setContentsMargins(0, 6, 0, 0)
        pw_layout.setSpacing(12)
        length_row = QHBoxLayout()
        length_row.addWidget(ui.label(tr("generator.length"), "FieldLabel"))
        length_row.addStretch(1)
        self.length_value = ui.label("", "H2")
        length_row.addWidget(self.length_value)
        pw_layout.addLayout(length_row)
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        self.length_slider.setValue(min(settings.generator_length, MAX_PASSWORD_LENGTH))
        self.length_value.setText(str(self.length_slider.value()))
        pw_layout.addWidget(self.length_slider)
        toggles = QGridLayout()
        toggles.setHorizontalSpacing(24)
        toggles.setVerticalSpacing(10)
        self.uppercase = ui.ToggleSwitch(tr("generator.uppercase"))
        self.lowercase = ui.ToggleSwitch(tr("generator.lowercase"))
        self.digits = ui.ToggleSwitch(tr("generator.digits"))
        self.symbols = ui.ToggleSwitch(tr("generator.symbols"))
        self.exclude_ambiguous = ui.ToggleSwitch(tr("generator.no_ambiguous"))
        for toggle, value in ((self.uppercase, settings.generator_uppercase),
                              (self.lowercase, settings.generator_lowercase),
                              (self.digits, settings.generator_digits),
                              (self.symbols, settings.generator_symbols),
                              (self.exclude_ambiguous, settings.generator_exclude_ambiguous)):
            toggle.setChecked(value)
        toggles.addWidget(self.uppercase, 0, 0)
        toggles.addWidget(self.lowercase, 0, 1)
        toggles.addWidget(self.digits, 1, 0)
        toggles.addWidget(self.symbols, 1, 1)
        toggles.addWidget(self.exclude_ambiguous, 2, 0, 1, 2)
        pw_layout.addLayout(toggles)
        self._option_pages.append(pw)
        self.body.addWidget(pw)

        # --- "Passphrase" options ----------------------------------------------------------
        pp = QWidget()
        pp_layout = QVBoxLayout(pp)
        pp_layout.setContentsMargins(0, 6, 0, 0)
        pp_layout.setSpacing(12)
        words_row = QHBoxLayout()
        words_row.addWidget(ui.label(tr("generator.words"), "FieldLabel"))
        words_row.addStretch(1)
        self.words_value = ui.label("", "H2")
        words_row.addWidget(self.words_value)
        pp_layout.addLayout(words_row)
        self.words_slider = QSlider(Qt.Horizontal)
        self.words_slider.setRange(MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS)
        self.words_slider.setValue(settings.passphrase_words)
        self.words_value.setText(str(self.words_slider.value()))
        pp_layout.addWidget(self.words_slider)
        sep_row = QHBoxLayout()
        sep_row.addWidget(ui.label(tr("generator.separator"), "FieldLabel"))
        sep_row.addStretch(1)
        self.separator = QComboBox()
        for key, value in _SEPARATORS:
            self.separator.addItem(tr(key), value)
        separator_index = self.separator.findData(settings.passphrase_separator)
        self.separator.setCurrentIndex(max(separator_index, 0))
        sep_row.addWidget(self.separator)
        pp_layout.addLayout(sep_row)
        self.capitalize = ui.ToggleSwitch(tr("generator.capitalize"))
        self.capitalize.setChecked(settings.passphrase_capitalize)
        self.add_number = ui.ToggleSwitch(tr("generator.add_number"))
        self.add_number.setChecked(settings.passphrase_add_number)
        pp_layout.addWidget(self.capitalize)
        pp_layout.addWidget(self.add_number)
        self.wordlist_info = ui.label("", "Faint", wrap=True)
        pp_layout.addWidget(self.wordlist_info)
        self._option_pages.append(pp)
        self.body.addWidget(pp)
        try:
            count = len(load_passphrase_wordlist())
            self.wordlist_info.setText(tr("generator.wordlist",
                                          count=i18n_qt.locale().toString(count)))
        except GeneratorError as exc:
            self.passphrase_chip.setEnabled(False)
            self.passphrase_chip.setToolTip(str(exc))

        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)

        # --- Buttons -----------------------------------------------------------------------------
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(ui.button(tr("generator.again"), "refresh-cw", on_click=self.regenerate))
        row.addStretch(1)
        if use_mode:
            row.addWidget(ui.button(tr("common.cancel"), kind="Ghost", on_click=self.reject))
            use = ui.button(tr("generator.use"), "check", "Primary", on_click=self._use)
            use.setDefault(True)
            row.addWidget(use)
        else:
            row.addWidget(ui.button(tr("common.close"), kind="Ghost", on_click=self.reject))
        self.card_layout.addSpacing(4)
        self.card_layout.addLayout(row)

        # --- Connections (after the initial state, so that generation happens only once) ----------
        passphrase = settings.generator_mode == "passphrase" and self.passphrase_chip.isEnabled()
        (self.passphrase_chip if passphrase else self.password_chip).setChecked(True)
        self._show_options(1 if passphrase else 0)
        self.password_chip.clicked.connect(lambda: self._set_mode(0))
        self.passphrase_chip.clicked.connect(lambda: self._set_mode(1))
        self.length_slider.valueChanged.connect(
            lambda v: (self.length_value.setText(str(v)), self.regenerate()))
        self.words_slider.valueChanged.connect(
            lambda v: (self.words_value.setText(str(v)), self.regenerate()))
        self.separator.currentIndexChanged.connect(self.regenerate)
        for toggle in (self.uppercase, self.lowercase, self.digits, self.symbols,
                       self.exclude_ambiguous, self.capitalize, self.add_number):
            toggle.toggled.connect(self.regenerate)
        self._ready = True
        self.regenerate()

    def _show_options(self, index: int) -> None:
        self._mode = index
        for i, page in enumerate(self._option_pages):
            page.setVisible(i == index)
        self.adjustSize()

    def _set_mode(self, index: int) -> None:
        self._show_options(index)
        effects.fade_in(self._option_pages[index], theme.DURATION_FAST)
        self.regenerate()

    @property
    def passphrase_mode(self) -> bool:
        return self._mode == 1

    def regenerate(self, *_args) -> None:
        if not self._ready:
            return
        try:
            if self.passphrase_mode:
                generated = generate_passphrase(PassphraseOptions(
                    words=self.words_slider.value(), separator=self.separator.currentData(),
                    capitalize=self.capitalize.isChecked(), add_number=self.add_number.isChecked()))
            else:
                generated = generate_password(PasswordOptions(
                    length=self.length_slider.value(), lowercase=self.lowercase.isChecked(),
                    uppercase=self.uppercase.isChecked(), digits=self.digits.isChecked(),
                    symbols=self.symbols.isChecked(),
                    exclude_ambiguous=self.exclude_ambiguous.isChecked()))
        except GeneratorError as exc:
            self.result.clear()
            self.strength.set_score(-1, 0)
            self.strength_label.setText("")
            self.error.setText(str(exc))
            self.error.show()
            return
        self.error.hide()
        self.result.setText(generated.value,
                            self.separator.currentData() if self.passphrase_mode else None)
        effects.slide_in(self.result, 0, 6, theme.DURATION_FAST)
        # EXACT entropy of the draw (not an estimate): the value is random.
        score = score_for_bits(generated.entropy_bits)
        self.strength.set_score(score, generated.entropy_bits)
        self.strength_label.setText(
            tr("generator.entropy", label=tr(LABELS[score]),
               bits=f"{generated.entropy_bits:.0f}"))

    def _copy(self) -> None:
        if self.result.text():
            self._clipboard.copy(self.result.text(), tr("generator.generated"))
            self.copy_button.confirm()

    def _use(self) -> None:
        if self.result.text():
            self.chosen_value = self.result.text()
            self.accept()

    def done(self, result: int) -> None:
        self.result.clear()
        super().done(result)
