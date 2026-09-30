"""Résolution des chemins applicatifs selon les conventions XDG Base Directory.

Aucune donnée (configuration ou coffre) ne doit être stockée dans le
répertoire du projet lui-même : tout passe par ces helpers.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

APP_DIR_NAME = "mon-coffre"


def _xdg_path(env_var: str, default_subpath: str) -> Path:
    """Retourne un répertoire XDG, en respectant la variable d'environnement
    si elle est définie, sinon en utilisant le repli standard."""
    value = os.environ.get(env_var)
    base = Path(value) if value else Path.home() / default_subpath
    return base / APP_DIR_NAME


def config_dir() -> Path:
    """~/.config/mon-coffre/ (ou $XDG_CONFIG_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_CONFIG_HOME", ".config")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def data_dir() -> Path:
    """~/.local/share/mon-coffre/ (ou $XDG_DATA_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_DATA_HOME", ".local/share")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def cache_dir() -> Path:
    """~/.cache/mon-coffre/ (ou $XDG_CACHE_HOME/mon-coffre/)."""
    path = _xdg_path("XDG_CACHE_HOME", ".cache")
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def vaults_dir() -> Path:
    """Répertoire contenant l'ensemble des coffres locaux."""
    path = data_dir() / "vaults"
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def vault_path(vault_id: str) -> Path:
    """Répertoire propre à un coffre donné."""
    path = vaults_dir() / vault_id
    path.mkdir(parents=True, exist_ok=True)
    _harden_permissions(path)
    return path


def documents_dir() -> Path:
    """Dossier « Documents » de l'utilisateur (XDG_DOCUMENTS_DIR, sinon ~/Documents).

    Lu dans $XDG_CONFIG_HOME/user-dirs.dirs, comme le fait xdg-user-dir : le
    dossier peut être localisé ou déplacé selon la configuration du bureau.
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
    """Emplacement par défaut des sauvegardes chiffrées : <Documents>/MonCoffre/backup.

    Remplaçable dans les paramètres (app.services.settings.backup_directory).
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
    """Restreint l'accès au répertoire au seul propriétaire (0700).

    Les coffres et la configuration contiennent des données sensibles :
    on ne veut pas qu'un autre utilisateur local du système puisse les lire.
    Sans effet sur les systèmes non-POSIX (ignoré silencieusement).
    """
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, 0o700)
