"""Translation catalogs: one JSON file per locale in app/i18n/locales/.

`en_US.json` is the reference: it holds every official key. A full catalog
(`fr_FR.json`, `ja_JP.json`…) translates all of them. A regional variant only
declares `"@parent"` (e.g. `"fr_FR"`) and the keys that really differ from it.

Lookup order for a key: the locale itself, then its parents, then `en_US`.
A key missing everywhere is shown as is: a missing translation never crashes
the application.

Placeholders use `str.format` names (`{count}`, `{name}`); every translation
must keep exactly the placeholders of `en_US` (checked by the tests).
Plural forms are two keys, `<key>.one` and `<key>.other`, chosen by `tr_n`.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

LOCALES_DIR = Path(__file__).resolve().parent / "locales"
REFERENCE = "en_US"
PARENT_KEY = "@parent"

# Supported locales, in the order of the Settings list, with their native name
# (shown untranslated, as is usual for a language picker).
LOCALES: dict[str, str] = {
    "en_US": "English (US)",
    "en_GB": "English (UK)",
    "fr_FR": "Français (France)",
    "tr_TR": "Türkçe",
    "de_DE": "Deutsch (Deutschland)",
    "es_ES": "Español (España)",
    "it_IT": "Italiano (Italia)",
    "de_CH": "Deutsch (Schweiz)",
    "fr_CH": "Français (Suisse)",
    "it_CH": "Italiano (Svizzera)",
    "fr_LU": "Français (Luxembourg)",
    "de_LU": "Deutsch (Luxemburg)",
    "lb_LU": "Lëtzebuergesch",
    "fr_BE": "Français (Belgique)",
    "nl_BE": "Nederlands (België)",
    "de_BE": "Deutsch (Belgien)",
    "ja_JP": "日本語",
}


@cache
def load(locale: str) -> dict[str, str]:
    """Raw content of a catalog (including "@parent"); {} if absent or unreadable."""
    if locale not in LOCALES:
        return {}
    try:
        data = json.loads((LOCALES_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def chain(locale: str) -> list[str]:
    """`locale`, its parents, then the reference (each locale at most once)."""
    result: list[str] = []
    current: str | None = locale
    while current and current in LOCALES and current not in result:
        result.append(current)
        current = load(current).get(PARENT_KEY)
    if REFERENCE not in result:
        result.append(REFERENCE)
    return result


def messages(locale: str) -> dict[str, str]:
    """All messages of `locale`, resolved through its parents and the reference."""
    merged: dict[str, str] = {}
    for name in reversed(chain(locale)):
        merged.update(load(name))
    merged.pop(PARENT_KEY, None)
    return merged
