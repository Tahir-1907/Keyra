"""Single instance per user.

Two instances open on the same vault would show out-of-sync data (and
double the automatic backups). At startup, the application tries to reach an
existing instance through a local socket: if it answers, it is asked to show
itself and this process quits; otherwise this process becomes the main
instance.

The socket is created in $XDG_RUNTIME_DIR (a 0700 per-user directory managed
by systemd-logind), otherwise in the application cache (0700), with the
"owner access only" option. No data goes through it apart from the "show"
command.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from app.utils.logging import get_logger
from app.utils.paths import cache_dir

_SOCKET_NAME = "mon-coffre-fort.sock"
_SHOW_COMMAND = b"show\n"
_TIMEOUT_MS = 500
# Unix socket path limit (sun_path: 108 bytes, trailing zero included).
_MAX_SOCKET_PATH = 107


def _socket_path() -> str | None:
    """Socket path, or None if no private location is usable.

    No fallback to /tmp: a predictable name there could be reserved by another
    user (who could then prevent the application from starting).
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    candidates = [Path(runtime)] if runtime and Path(runtime).is_dir() else []
    candidates.append(cache_dir())
    for base in candidates:
        path = str(base / _SOCKET_NAME)
        if len(path.encode()) <= _MAX_SOCKET_PATH:
            return path
    return None


def notify_running_instance() -> bool:
    """True if an instance is already running (and was asked to show itself)."""
    path = _socket_path()
    if path is None:
        return False
    socket = QLocalSocket()
    socket.connectToServer(path)
    if not socket.waitForConnected(_TIMEOUT_MS):
        return False
    socket.write(_SHOW_COMMAND)
    socket.waitForBytesWritten(_TIMEOUT_MS)
    socket.disconnectFromServer()
    return True


class SingleInstanceServer(QObject):
    show_requested = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._server = QLocalServer(self)
        self._server.setSocketOptions(QLocalServer.UserAccessOption)
        path = _socket_path()
        if path is None:
            get_logger().warning("Single-instance disabled: socket path too long")
            return
        if not self._server.listen(path):
            # Orphaned socket (previous instance killed): replace it.
            QLocalServer.removeServer(path)
            if not self._server.listen(path):
                get_logger().warning("Single-instance socket unavailable")
                return
        self._server.newConnection.connect(self._on_connection)

    def _on_connection(self) -> None:
        while self._server.hasPendingConnections():
            socket = self._server.nextPendingConnection()
            socket.readyRead.connect(lambda s=socket: self._on_ready(s))
            socket.disconnected.connect(socket.deleteLater)

    def _on_ready(self, socket: QLocalSocket) -> None:
        if bytes(socket.readAll()).startswith(_SHOW_COMMAND.strip()):
            self.show_requested.emit()
