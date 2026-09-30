"""Private, atomic file writes (backups, exports, PDF, settings).

A single implementation for every file written by the application:

1. temporary file created in the SAME folder as the destination (the final
   rename must stay on the same file system);
2. permissions 0600 before a single byte is written;
3. write, then fsync the file;
4. os.replace: the destination is replaced in one go — never a half-written
   file, and an existing file stays intact if an earlier step fails;
5. fsync the folder (best effort), so that the rename survives a power cut.

On failure, the temporary file is deleted. Limitation: if the process is
killed abruptly (SIGKILL, power cut) between steps 1 and 4, a hidden
`<prefix>XXXX` file (0600) may remain in the folder.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_private_atomic(path: Path, data: bytes, temp_prefix: str = ".tmp-",
                         temp_suffix: str = "") -> None:
    """Writes `data` to `path` (0600), atomically. Raises OSError on failure."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=temp_prefix, suffix=temp_suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)  # mkstemp already creates 0600: explicit guarantee
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
    """Makes the rename durable; no effect if the system does not allow it."""
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)
