"""System language detection and matching to a supported locale.

Detection: the preferred languages of the system, in order. With Qt,
`QLocale.system().uiLanguages()` (Linux: LANGUAGE, LC_ALL, LC_MESSAGES, LANG;
Windows: the display languages of the account), then `QLocale.system().name()`.
Without Qt: the same environment variables, then `locale.getlocale()`.

Normalization accepts the usual spellings: `fr_FR.UTF-8`, `fr-FR`, `fr_FR@euro`,
`zh-Hans-CN` (script ignored), `French_France` (Windows names); `C` and `POSIX`
mean "no preference".

Matching, for each preference in turn (the first one that matches wins):
  1. exact locale (`de_CH` → `de_CH`, `nl_BE` → `nl_BE`);
  2. same language, technical fallback region: `fr_CA` → `fr_FR`, `de_AT` → `de_DE`,
     `es_MX` → `es_ES`, `tr_CY` → `tr_TR`, `it_SM` → `it_IT`, `nl_NL` → `nl_BE` (the only
     Dutch locale available, not a claim that both variants are the same);
     English: `en_GB` for the regions listed in `EN_GB_REGIONS`, `en_US` otherwise
     (a technical rule: a region does not decide which spelling a user prefers,
     which is why the choice can be changed in Settings);
  3. nothing matches (e.g. `pt_BR`, `ko_KR`, `zh_CN`): `en_US`.
"""

from __future__ import annotations

import locale as _locale
import os
import re
from collections.abc import Iterable

from app.i18n.catalog import LOCALES, REFERENCE

# Region used when only the language matches.
DEFAULT_REGION = {"en": "US", "fr": "FR", "tr": "TR", "de": "DE", "es": "ES", "it": "IT",
                  "lb": "LU", "nl": "BE", "ja": "JP"}
# English regions whose conventions are closer to British spelling (technical fallback).
EN_GB_REGIONS = frozenset({"GB", "UK", "IE", "AU", "NZ", "ZA", "IN", "PK", "SG", "HK", "MT",
                           "CY", "GI", "IM", "JE", "GG", "KE", "NG", "GH", "UG", "TZ", "ZW",
                           "ZM", "BW", "NA", "MU", "LK", "BD", "MY", "FJ"})
# Windows spellings (`locale.getlocale()` on Windows: "French_France").
WINDOWS_LANGUAGES = {
    "english": "en", "french": "fr", "german": "de", "spanish": "es", "italian": "it",
    "turkish": "tr", "dutch": "nl", "japanese": "ja", "luxembourgish": "lb",
    "portuguese": "pt", "chinese": "zh", "korean": "ko", "russian": "ru", "polish": "pl",
    "arabic": "ar", "swedish": "sv", "danish": "da", "norwegian": "nb", "finnish": "fi",
    "greek": "el", "czech": "cs", "hungarian": "hu", "romanian": "ro",
}
WINDOWS_REGIONS = {
    "united states": "US", "united kingdom": "GB", "france": "FR", "switzerland": "CH",
    "belgium": "BE", "luxembourg": "LU", "germany": "DE", "austria": "AT", "spain": "ES",
    "mexico": "MX", "italy": "IT", "turkey": "TR", "türkiye": "TR", "japan": "JP",
    "netherlands": "NL", "canada": "CA", "australia": "AU", "ireland": "IE",
    "new zealand": "NZ", "south africa": "ZA", "india": "IN", "brazil": "BR",
    "portugal": "PT", "china": "CN", "korea": "KR", "cyprus": "CY",
}
_TAG = re.compile(r"^[A-Za-z]{2,3}$")
_REGION = re.compile(r"^([A-Za-z]{2}|[0-9]{3})$")


def normalize(raw: str | None) -> tuple[str, str | None] | None:
    """(language, region) of a system locale string, or None if it says nothing."""
    if not raw:
        return None
    text = raw.strip().split(".", 1)[0].split("@", 1)[0].strip()
    if not text or text.upper() in ("C", "POSIX"):
        return None
    parts = [p for p in re.split(r"[-_]", text) if p]
    if not parts:
        return None
    first = parts[0].lower()
    if first in WINDOWS_LANGUAGES:  # "French_France", "English_United States"
        rest = " ".join(parts[1:]).lower()
        return WINDOWS_LANGUAGES[first], WINDOWS_REGIONS.get(rest)
    if not _TAG.match(first):
        return None
    region = next((p.upper() for p in parts[1:] if _REGION.match(p)), None)
    return first, region


def match(language: str, region: str | None) -> str | None:
    """Supported locale for (language, region), or None if the language is not supported."""
    if region and f"{language}_{region}" in LOCALES:
        return f"{language}_{region}"
    if language == "en":
        return "en_GB" if region in EN_GB_REGIONS else "en_US"
    if language in DEFAULT_REGION:
        return f"{language}_{DEFAULT_REGION[language]}"
    return None


def resolve(preferences: Iterable[str]) -> str:
    """First preference that matches a supported locale, otherwise `en_US`."""
    for raw in preferences:
        parsed = normalize(raw)
        if parsed is not None:
            found = match(*parsed)
            if found is not None:
                return found
    return REFERENCE


def system_preferences() -> list[str]:
    """Preferred languages of the system, most preferred first (may be empty)."""
    try:
        from PySide6.QtCore import QLocale
    except ImportError:
        QLocale = None
    if QLocale is not None:
        system = QLocale.system()
        return [*system.uiLanguages(), system.name()]
    result: list[str] = []
    for name in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        result += [v for v in os.environ.get(name, "").split(":") if v]
    try:
        current = _locale.getlocale()[0]
    except ValueError:
        current = None
    if current:
        result.append(current)
    return result


def detect() -> str:
    """Supported locale matching the system languages."""
    return resolve(system_preferences())
