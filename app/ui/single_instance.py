"""Instance unique par utilisateur.

Deux instances ouvertes sur le même coffre afficheraient des données
désynchronisées (et doubleraient les sauvegardes automatiques). Au
lancement, on tente de joindre une instance existante via un socket local :
si elle répond, on lui demande de s'afficher et on quitte ; sinon on
devient l'instance principale.

Le socket est créé dans $XDG_RUNTIME_DIR (répertoire 0700 propre à
l'utilisateur, géré par systemd-logind), à défaut dans le cache de
l'application (0700), avec l'option « accès propriétaire uniquement ».
Aucune donnée n'y transite hormis la commande « show ».
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
# Limite des chemins de socket Unix (sun_path : 108 octets, zéro final compris).
_MAX_SOCKET_PATH = 107


def _socket_path() -> str | None:
    """Chemin du socket, ou None si aucun emplacement privé n'est utilisable.

    Pas de repli sur /tmp : un nom prévisible y serait réservable par un
    autre utilisateur (qui pourrait alors empêcher l'application de démarrer).
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
    """True si une instance tourne déjà (et a été priée de s'afficher)."""
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
            # Socket orphelin (instance précédente tuée) : on le remplace.
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
