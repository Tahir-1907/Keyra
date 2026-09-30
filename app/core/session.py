"""Application session management: automatic locking after inactivity.

This module is deliberately independent of any UI (no QTimer here): it only
exposes the "should we lock now?" logic based on the time elapsed since the
last activity. The UI layer (app/ui/main_window.py) calls `touch()` on every
interaction and polls `should_lock()` every second.

Possible values for the automatic lock delay (section 15 of the
specification): 1 min, 5 min, 10 min, 30 min, 1 h, or never.
Only `None` disables automatic locking (0 would lock immediately).

Clock: on Linux, `time.monotonic()` (CLOCK_MONOTONIC) stops while the system
is asleep; after 8 hours of sleep, the measured inactivity would not have
moved. CLOCK_BOOTTIME, which counts time spent asleep, is therefore used.
Falls back to `time.monotonic()` if this clock does not exist (other system)
or is refused (restricted kernel or sandbox): locking on sleep (D-Bus,
enabled by default) then remains the main protection.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from app.core.vault import Vault
from app.utils.logging import get_logger

AUTO_LOCK_CHOICES_SECONDS: dict[str, int | None] = {
    "1 minute": 60,
    "5 minutes": 5 * 60,
    "10 minutes": 10 * 60,
    "30 minutes": 30 * 60,
    "1 hour": 60 * 60,
    "Never": None,
}


def _select_clock() -> tuple[str, Callable[[], float]]:
    """(name, clock): CLOCK_BOOTTIME if available, otherwise time.monotonic."""
    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if clock_id is not None:
        try:
            time.clock_gettime(clock_id)
        except OSError:
            pass
        else:
            return "CLOCK_BOOTTIME", lambda: time.clock_gettime(clock_id)
    return "monotonic", time.monotonic


CLOCK_NAME, _default_clock = _select_clock()


class SessionManager:
    """Wraps an unlocked `Vault` and manages its automatic locking."""

    def __init__(self, vault: Vault, auto_lock_seconds: int | None = 5 * 60,
                 clock: Callable[[], float] | None = None) -> None:
        self._vault = vault
        self.auto_lock_seconds = auto_lock_seconds
        self._clock = clock or _default_clock  # injectable: deterministic tests
        self._last_activity = self._clock()
        self._logger = get_logger()

    @property
    def vault(self) -> Vault:
        return self._vault

    def touch(self) -> None:
        """To be called on every significant user interaction."""
        self._last_activity = self._clock()

    def idle_seconds(self) -> float:
        return self._clock() - self._last_activity

    def should_lock(self) -> bool:
        if self.auto_lock_seconds is None or self._vault.is_locked:
            return False
        return self.idle_seconds() >= self.auto_lock_seconds

    def lock_if_idle(self) -> bool:
        """Locks the vault if the inactivity delay has been exceeded.

        Returns True if a lock actually took place.
        """
        if self.should_lock():
            self._logger.info("Auto-lock triggered after %.0fs idle", self.idle_seconds())
            self._vault.lock()
            return True
        return False

    def lock_now(self) -> None:
        """Manual lock (e.g. button, Ctrl+L, Linux session lock)."""
        self._vault.lock()
