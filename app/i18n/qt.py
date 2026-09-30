"""Qt side of the interface language: default QLocale and Qt's own translations.

Qt's standard texts (context menu of text fields, file dialogs…) come from the
`qtbase_<language>.qm` files of the system (Debian: qt6-translations-l10n). When a
file is missing (e.g. Luxembourgish), those few texts simply stay in English.
"""

from __future__ import annotations

from PySide6.QtCore import QCoreApplication, QLibraryInfo, QLocale, QTranslator

from app import i18n

_installed: list[QTranslator] = []


def apply(locale: str) -> str:
    """Selects `locale` for the application messages, QLocale and Qt's own texts."""
    locale = i18n.set_language(locale)
    QLocale.setDefault(QLocale(locale))
    app = QCoreApplication.instance()
    if app is None:
        return locale
    for translator in _installed:
        app.removeTranslator(translator)
    _installed.clear()
    folder = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    translator = QTranslator(app)
    if translator.load(QLocale(locale), "qtbase", "_", folder):
        app.installTranslator(translator)
        _installed.append(translator)
    return locale


def locale() -> QLocale:
    """QLocale of the interface language (dates, numbers)."""
    return QLocale(i18n.current())
