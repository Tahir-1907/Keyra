"""Built-in categories: explicit mapping between technical key and display name.

Single source of truth (app.core.categories derives BUILTIN_CATEGORIES from it,
and the v4 schema its CHECK constraint). Only depends on app.i18n (pure Python),
so it stays importable from the database layer without a circular import.

In v4, a built-in category is identified ONLY by its technical key
(`categories.builtin_key`, in plaintext): these keys are generic and identical
in every vault, so they reveal nothing. The name is supplied by the code.
Custom categories have an encrypted name and never a key: a category is NEVER
deduced to be built-in from its name.

Two name tables:
* BUILTIN_CATEGORY_NAMES — English (reference) labels; the application displays
  them in the interface language (`category.<key>` keys of app/i18n);
* LEGACY_BUILTIN_NAMES — the French names that versions 1.x stored in plaintext
  in v1 to v3 vaults. FROZEN: the v3 → v4 migration identifies built-in
  categories by these exact names, and older files (CSV exports, vaults created
  before built-in categories existed) may still contain them.
"""

from __future__ import annotations

from app.i18n import LOCALES, tr
from app.i18n.catalog import messages

# Order = display order. Keys: ASCII, stable, never to be renamed.
BUILTIN_CATEGORY_NAMES: dict[str, str] = {
    "personal": "Personal",
    "work": "Work",
    "finance": "Finance",
    "social": "Social",
    "email": "Email",
    "shopping": "Shopping",
}
BUILTIN_CATEGORY_KEYS: tuple[str, ...] = tuple(BUILTIN_CATEGORY_NAMES)

# Names stored by v1 to v3 vaults (versions 1.x). Never translate or edit.
LEGACY_BUILTIN_NAMES: dict[str, str] = {
    "personal": "Personnel",
    "work": "Travail",
    "finance": "Finances",
    "social": "Réseaux sociaux",
    "email": "Courriel",
    "shopping": "Achats",
}


def builtin_name(key: str) -> str:
    """Display name of a built-in category, in the interface language; KeyError if unknown."""
    if key not in BUILTIN_CATEGORY_NAMES:
        raise KeyError(key)
    return tr(f"category.{key}")


def legacy_builtin_name(key: str) -> str:
    """Name stored for this built-in category by v1 to v3 vaults; KeyError if unknown."""
    return LEGACY_BUILTIN_NAMES[key]


def legacy_name_for_display(name: str) -> str | None:
    """Legacy (v1.x) name of the built-in category displayed as `name`, or None."""
    for key in BUILTIN_CATEGORY_NAMES:
        if name in (builtin_name(key), BUILTIN_CATEGORY_NAMES[key]):
            return LEGACY_BUILTIN_NAMES[key]
    return None


def every_builtin_name(key: str) -> tuple[str, ...]:
    """Names of this built-in category in every supported language, English and 1.x
    French (import: a file written in another interface language)."""
    names = [*builtin_names(key)]
    names += [messages(locale).get(f"category.{key}", "") for locale in LOCALES]
    return tuple(dict.fromkeys(n for n in names if n))


def builtin_key_for_name(name: str) -> str | None:
    """Key of the built-in category that `name` designates in any supported language,
    in English or in 1.x French; None otherwise."""
    for key in BUILTIN_CATEGORY_NAMES:
        if name in every_builtin_name(key):
            return key
    return None


def builtin_names(key: str) -> tuple[str, ...]:
    """Every name that designates this built-in category: displayed (interface
    language), English reference, then legacy; without duplicates."""
    names = (builtin_name(key), BUILTIN_CATEGORY_NAMES[key], LEGACY_BUILTIN_NAMES[key])
    return tuple(dict.fromkeys(names))


def builtin_key_for_v3_row(name: str, is_builtin: bool) -> str | None:
    """Key of a category of a v3 vault (migration only).

    Only a row flagged as built-in (`is_builtin = 1`) gets a key, based on its
    plaintext v3 name. A custom category that happens to have the same name as
    a built-in one STAYS custom. A row flagged as built-in with an unknown name
    is inconsistent: ValueError (never a silent choice).
    """
    if not is_builtin:
        return None
    for key, legacy in LEGACY_BUILTIN_NAMES.items():
        if legacy == name:
            return key
    raise ValueError("Unknown built-in category in this vault.")
