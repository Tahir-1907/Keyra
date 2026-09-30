"""Resolution of application paths following the XDG Base Directory conventions.

No data (configuration or vault) must be stored in the project directory
itself: everything goes through these helpers.

The folder names ("mon-coffre", "MonCoffre") are historical identifiers kept
for compatibility with existing installations: renaming them would hide the
vaults, settings and backups of existing users.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

APP_DIR_NAME = "mon-coffre"


def _xdg_path(env_var: str, default_subpath: str) -> Path:
    """Returns an XDG directory, honoring the environment variable when it is
    set, and the standard fallback otherwise."""
    value = os.environ.get(env_var)
    base = Path(value) if value else Path.home() / default_subpath
    return base / APP_DIR_NAME


def config_dir() -> Path:
    """~/.config/mon-coffre/ (or $XDG_CONFIG_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_CONFIG_HOME", ".config")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def data_dir() -> Path:
    """~/.local/share/mon-coffre/ (or $XDG_DATA_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_DATA_HOME", ".local/share")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def cache_dir() -> Path:
    """~/.cache/mon-coffre/ (or $XDG_CACHE_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_CACHE_HOME", ".cache")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def vaults_dir() -> Path:
    """Directory containing all the local vaults."""
    path = data_dir() / "vaults"
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def vault_path(vault_id: str) -> Path:
    """Directory of a given vault."""
    path = vaults_dir() / vault_id
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def documents_dir() -> Path:
    """The user's "Documents" folder (XDG_DOCUMENTS_DIR, otherwise ~/Documents).

    Read from $XDG_CONFIG_HOME/user-dirs.dirs, as xdg-user-dir does: the folder
    may be localized or moved depending on the desktop configuration.
    """
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    try:
        lines = (Path(config_home) / "user-dirs.dirs").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        key, _, value = line.strip().partition("=")
        if key == "XDG_DOCUMENTS_DIR" and value:
            value = value.strip().strip('"').replace("$HOME", str(Path.home()), 1)
            if value.startswith("/") and value.rstrip("/") != str(Path.home()):
                return Path(value)
    return Path.home() / "Documents"


def default_backup_dir() -> Path:
    """Default location of the encrypted backups: <Documents>/MonCoffre/backup.

    Can be changed in the settings (app.services.settings.backup_directory).
    """
    path = documents_dir() / "MonCoffre" / "backup"
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def log_file() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path / "mon-coffre.log"


def _harden_permissions(path: Path) -> None:
    """Restricts access to the directory to its owner only (0700).

    Vaults and configuration contain sensitive data: no other local user of
    the system must be able to read them. No effect on non-POSIX systems
    (silently ignored).
    """
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, 0o700)
