"""Verrouillage du coffre quand la session Linux se verrouille ou se met en veille.

Signaux D-Bus écoutés (QtDBus, inclus dans PySide6) :
* bus de session : `org.gnome.ScreenSaver.ActiveChanged(true)` (GNOME) et
  `org.freedesktop.ScreenSaver.ActiveChanged(true)` (KDE, Xfce…) ;
* bus système : `org.freedesktop.login1.Manager.PrepareForSleep(true)`
  (mise en veille / hibernation, systemd-logind).

Si D-Bus n'est pas disponible, la surveillance est simplement inactive
(le verrouillage par inactivité reste en place) et un avertissement est
journalisé. Un signal forgé par un autre processus de l'utilisateur ne
peut que *verrouiller* le coffre : aucun risque de sécurité.
"""

from __future__ import annotations

from PySide6.QtCore import SLOT, QObject, Signal, Slot

from app.utils.logging import get_logger

try:
    from PySide6.QtDBus import QDBusConnection
except ImportError:  # pragma: no cover - module présent dans PySide6 standard
    QDBusConnection = None


class SystemLockMonitor(QObject):
    lock_requested = Signal(str)  # raison, pour le message affiché

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.active_sources: list[str] = []
        logger = get_logger()
        if QDBusConnection is None:
            logger.warning("QtDBus unavailable: session lock detection disabled")
            return
        session = QDBusConnection.sessionBus()
        if session.isConnected():
            for service, path, interface in (
                ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver"),
                ("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver",
                 "org.freedesktop.ScreenSaver"),
            ):
                if session.connect("", path, interface, "ActiveChanged",
                                   self, SLOT("_on_screensaver(bool)")):
                    self.active_sources.append(service)
        system = QDBusConnection.systemBus()
        if system.isConnected() and system.connect(
            "org.freedesktop.login1", "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "PrepareForSleep",
            self, SLOT("_on_prepare_for_sleep(bool)"),
        ):
            self.active_sources.append("org.freedesktop.login1")
        if self.active_sources:
            logger.info("Session lock detection active: %s", ", ".join(self.active_sources))
        else:
            logger.warning("D-Bus unavailable: session lock detection disabled")

    @Slot(bool)
    def _on_screensaver(self, active: bool) -> None:
        if active:
            self.lock_requested.emit("Coffre verrouillé : la session a été verrouillée.")

    @Slot(bool)
    def _on_prepare_for_sleep(self, going_to_sleep: bool) -> None:
        if going_to_sleep:
            self.lock_requested.emit("Coffre verrouillé : mise en veille du système.")
