"""Interface language: translated messages, detection, current locale.

Pure Python (no Qt), so that core/ and services/ can translate the messages they
show. The chosen language is an application setting (settings.json), never
stored in a vault.

    tr("common.cancel")                      -> "Cancel" / "Annuler" / "キャンセル"
    tr("entries.count", count=3)             -> placeholders filled with str.format
    tr_n("entries.count", 3)                 -> "<key>.one" or "<key>.other"
"""

from __future__ import annotations

from app.i18n import detector
from app.i18n.catalog import LOCALES, REFERENCE, messages
from app.utils.logging import get_logger

SYSTEM = "system"  # setting value: follow the system language

_current = REFERENCE
_messages: dict[str, str] = {}
_reference: dict[str, str] = {}
_reported: set[str] = set()


def current() -> str:
    """Locale in use, e.g. "fr_FR"."""
    return _current


def language() -> str:
    """Language part of the locale in use, e.g. "fr"."""
    return _current.split("_", 1)[0]


def resolve_setting(value: str | None) -> str:
    """Locale for a "language" setting: SYSTEM (or unknown) → detection, else the locale."""
    if value in LOCALES:
        return value
    return detector.detect()


def set_language(locale: str) -> str:
    """Selects the interface locale (unknown → en_US) and returns it."""
    global _current, _messages
    _current = locale if locale in LOCALES else REFERENCE
    _messages = messages(_current)
    return _current


def _missing(key: str) -> str:
    if key not in _reported:
        _reported.add(key)
        get_logger().warning("Missing translation key: %s", key)
    return key


def _reference_text(key: str) -> str | None:
    global _reference
    if not _reference:
        _reference = messages(REFERENCE)
    return _reference.get(key)


def tr(key: str, /, **params) -> str:
    """Message `key` in the current language (fallback: en_US, then the key itself)."""
    if not _messages:
        set_language(_current)
    text = _messages.get(key)
    if text is None:
        return _missing(key)
    if not params:
        return text
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError):  # broken translation: English instead
        reference = _reference_text(key) or key
        try:
            return reference.format(**params)
        except (KeyError, IndexError, ValueError):
            return reference


def plural_form(count: int, lang: str | None = None) -> str:
    """"one" or "other" (CLDR rules, reduced to the supported languages)."""
    lang = lang or language()
    if lang == "ja":
        return "other"
    if lang == "fr":
        return "one" if count in (0, 1) else "other"
    return "one" if count == 1 else "other"


def tr_n(key: str, count: int, /, **params) -> str:
    """Plural message: `<key>.one` or `<key>.other`, with {count} available."""
    return tr(f"{key}.{plural_form(count)}", count=count, **params)


__all__ = ["LOCALES", "REFERENCE", "SYSTEM", "current", "detector", "language",
           "plural_form", "resolve_setting", "set_language", "tr", "tr_n"]
