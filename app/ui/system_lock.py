"""Locks the vault when the Linux session locks or goes to sleep.

D-Bus signals listened to (QtDBus, included in PySide6):
* session bus: `org.gnome.ScreenSaver.ActiveChanged(true)` (GNOME) and
  `org.freedesktop.ScreenSaver.ActiveChanged(true)` (KDE, Xfce…);
* system bus: `org.freedesktop.login1.Manager.PrepareForSleep(true)`
  (sleep / hibernation, systemd-logind).

If D-Bus is not available, monitoring is simply inactive (locking after
inactivity remains in place) and a warning is logged. A signal forged by
another process of the user can only *lock* the vault: no security risk.
"""

from __future__ import annotations

from PySide6.QtCore import SLOT, QObject, Signal, Slot

from app.i18n import tr
from app.utils.logging import get_logger

try:
    from PySide6.QtDBus import QDBusConnection
except ImportError:  # pragma: no cover - module present in standard PySide6
    QDBusConnection = None


class SystemLockMonitor(QObject):
    lock_requested = Signal(str)  # reason, for the displayed message

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
            self.lock_requested.emit(tr("lock.reason.session"))

    @Slot(bool)
    def _on_prepare_for_sleep(self, going_to_sleep: bool) -> None:
        if going_to_sleep:
            self.lock_requested.emit(tr("lock.reason.sleep"))
