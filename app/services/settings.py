"""Application settings (non-sensitive), per Linux user.

File: ~/.config/mon-coffre/settings.json (or $XDG_CONFIG_HOME), 0600.
It contains no secret: only preferences (delays, backup folder, generator
options, last vault used, window geometry). Any missing, unknown or invalid
value is replaced by its default: a damaged file can neither prevent startup
nor silently disable a protection (e.g. a delay outside the list).

The choice dictionaries map the translation key of a label (app/i18n) to the
stored value: only the values are written to the file.

Compatibility between versions sharing this file: keys unknown to this version
(written by a newer one) are kept as they are when the file is saved. An older
version (e.g. 1.7.0-rc1) does not know "language" and drops it when it saves its
own settings: the next start then simply follows the system language again.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from app.core.generator import (
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_LENGTH,
)
from app.core.session import AUTO_LOCK_CHOICES_SECONDS
from app.i18n import LOCALES, SYSTEM
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger
from app.utils.paths import config_dir, default_backup_dir

SETTINGS_FILENAME = "settings.json"

AUTO_LOCK_CHOICES = AUTO_LOCK_CHOICES_SECONDS  # label key -> seconds (None = never)
CLIPBOARD_CHOICES: dict[str, int] = {
    "choice.seconds_10": 10, "choice.seconds_20": 20, "choice.seconds_30": 30,
    "choice.minutes_1": 60, "choice.minutes_2": 120, "choice.minutes_5": 300,
}
TRASH_RETENTION_CHOICES: dict[str, int | None] = {
    "choice.days_7": 7, "choice.days_30": 30, "choice.days_90": 90, "choice.year_1": 365,
    "choice.never_empty_manually": None,
}
PASSPHRASE_SEPARATORS = ("-", " ", ".", "_", "")
MIN_AUTO_BACKUPS, MAX_AUTO_BACKUPS = 1, 100


@dataclass(slots=True)
class Settings:
    # Security
    auto_lock_seconds: int | None = 5 * 60
    lock_on_session_lock: bool = True
    clipboard_clear_seconds: int = 30
    # Trash and backups
    trash_retention_days: int | None = 30
    auto_backup: bool = True
    auto_backups_kept: int = 10
    backup_dir: str = ""  # empty = <Documents>/MonCoffre/backup
    # Generator (default values)
    generator_mode: str = "password"  # "password" | "passphrase"
    generator_length: int = 20
    generator_lowercase: bool = True
    generator_uppercase: bool = True
    generator_digits: bool = True
    generator_symbols: bool = True
    generator_exclude_ambiguous: bool = False
    passphrase_words: int = 6
    passphrase_separator: str = "-"  # noqa: S105 - word separator
    passphrase_capitalize: bool = False
    passphrase_add_number: bool = False
    # Interface
    language: str = SYSTEM  # SYSTEM (follow the system language) or a locale, e.g. "fr_FR"
    animations: bool = True
    last_vault_id: str = ""
    window_geometry: str = ""  # QMainWindow.saveGeometry() in base64

    def validated(self) -> Settings:
        """Copy in which every out-of-range value is reset to its default."""
        default = Settings()
        checks = {
            "auto_lock_seconds": lambda v: v in AUTO_LOCK_CHOICES.values(),
            "clipboard_clear_seconds": lambda v: v in CLIPBOARD_CHOICES.values(),
            "trash_retention_days": lambda v: v in TRASH_RETENTION_CHOICES.values(),
            "auto_backups_kept": lambda v: isinstance(v, int) and not isinstance(v, bool)
            and MIN_AUTO_BACKUPS <= v <= MAX_AUTO_BACKUPS,
            "backup_dir": lambda v: isinstance(v, str) and (v == "" or Path(v).is_absolute()),
            "generator_mode": lambda v: v in ("password", "passphrase"),
            "generator_length": lambda v: isinstance(v, int) and not isinstance(v, bool)
            and MIN_PASSWORD_LENGTH <= v <= MAX_PASSWORD_LENGTH,
            "passphrase_words": lambda v: isinstance(v, int) and not isinstance(v, bool)
            and MIN_PASSPHRASE_WORDS <= v <= MAX_PASSPHRASE_WORDS,
            "passphrase_separator": lambda v: v in PASSPHRASE_SEPARATORS,
            "language": lambda v: isinstance(v, str) and (v == SYSTEM or v in LOCALES),
            "last_vault_id": lambda v: isinstance(v, str) and len(v) < 128 and "/" not in v,
            "window_geometry": lambda v: isinstance(v, str) and len(v) < 10_000,
        }
        values = {}
        for f in fields(Settings):
            value = getattr(self, f.name)
            default_value = getattr(default, f.name)
            if isinstance(default_value, bool):
                ok = isinstance(value, bool)
            else:
                ok = checks.get(f.name, lambda v: True)(value)
            values[f.name] = value if ok else default_value
        result = Settings(**values)
        if not any((result.generator_lowercase, result.generator_uppercase,
                    result.generator_digits, result.generator_symbols)):
            result.generator_lowercase = result.generator_uppercase = True
            result.generator_digits = result.generator_symbols = True
        return result


def settings_path() -> Path:
    return config_dir() / SETTINGS_FILENAME


def load_settings() -> Settings:
    path = settings_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Settings()
    except (OSError, ValueError):
        get_logger().warning("Unreadable settings file, defaults used")
        return Settings()
    if not isinstance(raw, dict):
        return Settings()
    known = {f.name for f in fields(Settings)}
    settings = Settings()
    for key, value in raw.items():
        if key in known:
            setattr(settings, key, value)
    return settings.validated()


def _unknown_keys(path: Path) -> dict:
    """Keys of the current file that this version does not know (newer versions)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    known = {f.name for f in fields(Settings)}
    return {k: v for k, v in raw.items() if isinstance(k, str) and k not in known}


def save_settings(settings: Settings) -> None:
    path = settings_path()
    content = _unknown_keys(path)
    content.update(asdict(settings.validated()))
    data = json.dumps(content, ensure_ascii=False, indent=2)
    write_private_atomic(path, data.encode("utf-8"), temp_prefix=".settings-",
                         temp_suffix=".json")


def backup_directory(settings: Settings) -> Path:
    """Backup folder according to the settings (created as 0700 if needed)."""
    if not settings.backup_dir:
        return default_backup_dir()
    path = Path(settings.backup_dir)
    if not path.exists():
        # Only a folder created by the application is restricted: the permissions of
        # an existing folder chosen by the user are never changed.
        path.mkdir(parents=True)
        os.chmod(path, 0o700)
    return path
