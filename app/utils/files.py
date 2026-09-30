"""Écriture privée et atomique de fichiers (sauvegardes, exports, PDF, paramètres).

Une seule implémentation pour tous les fichiers écrits par l'application :

1. fichier temporaire créé dans le MÊME dossier que la destination (le
   renommage final doit rester sur le même système de fichiers) ;
2. permissions 0600 avant d'écrire le moindre octet ;
3. écriture, puis fsync du fichier ;
4. os.replace : la destination est remplacée d'un seul coup — jamais un
   fichier à moitié écrit, et un fichier existant reste intact si une étape
   précédente échoue ;
5. fsync du dossier (best effort), pour que le renommage survive à une
   coupure de courant.

En cas d'échec, le temporaire est supprimé. Limite : si le processus est tué
brutalement (SIGKILL, coupure) entre les étapes 1 et 4, un fichier caché
`<préfixe>XXXX` (0600) peut rester dans le dossier.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_private_atomic(path: Path, data: bytes, temp_prefix: str = ".tmp-",
                         temp_suffix: str = "") -> None:
    """Écrit `data` dans `path` (0600), de façon atomique. Lève OSError en cas d'échec."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=temp_prefix, suffix=temp_suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)  # mkstemp crée déjà en 0600 : garantie explicite
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Rend le renommage durable ; sans effet si le système ne le permet pas."""
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)
