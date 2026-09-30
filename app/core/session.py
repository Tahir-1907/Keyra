"""Gestion de session applicative : verrouillage automatique par inactivité.

Ce module est volontairement indépendant de toute UI (pas de QTimer ici) :
il expose juste la logique « faut-il verrouiller maintenant ? » en fonction
du temps écoulé depuis la dernière activité. La couche UI
(app/ui/main_window.py) appelle `touch()` à chaque interaction et
interroge `should_lock()` chaque seconde.

Valeurs possibles pour le délai de verrouillage automatique (section 15
du cahier des charges) : 1 min, 5 min, 10 min, 30 min, 1 h, ou jamais.
Seul `None` désactive l'auto-verrouillage (0 verrouillerait immédiatement).

Horloge : sous Linux, `time.monotonic()` (CLOCK_MONOTONIC) s'arrête pendant la
mise en veille ; après 8 h de veille, l'inactivité mesurée n'aurait pas bougé.
On utilise donc CLOCK_BOOTTIME, qui compte le temps passé en veille. Repli sur
`time.monotonic()` si cette horloge n'existe pas (autre système) ou est
refusée (noyau ou bac à sable restreint) : le verrouillage à la mise en veille
(D-Bus, activé par défaut) reste alors la protection principale.
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
    "1 heure": 60 * 60,
    "Jamais": None,
}


def _select_clock() -> tuple[str, Callable[[], float]]:
    """(nom, horloge) : CLOCK_BOOTTIME si disponible, sinon time.monotonic."""
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
    """Enveloppe un `Vault` déverrouillé et gère son verrouillage automatique."""

    def __init__(self, vault: Vault, auto_lock_seconds: int | None = 5 * 60,
                 clock: Callable[[], float] | None = None) -> None:
        self._vault = vault
        self.auto_lock_seconds = auto_lock_seconds
        self._clock = clock or _default_clock  # injectable : tests déterministes
        self._last_activity = self._clock()
        self._logger = get_logger()

    @property
    def vault(self) -> Vault:
        return self._vault

    def touch(self) -> None:
        """À appeler à chaque interaction utilisateur significative."""
        self._last_activity = self._clock()

    def idle_seconds(self) -> float:
        return self._clock() - self._last_activity

    def should_lock(self) -> bool:
        if self.auto_lock_seconds is None or self._vault.is_locked:
            return False
        return self.idle_seconds() >= self.auto_lock_seconds

    def lock_if_idle(self) -> bool:
        """Verrouille le coffre si le délai d'inactivité est dépassé.

        Retourne True si un verrouillage a effectivement eu lieu.
        """
        if self.should_lock():
            self._logger.info("Auto-lock triggered after %.0fs idle", self.idle_seconds())
            self._vault.lock()
            return True
        return False

    def lock_now(self) -> None:
        """Verrouillage manuel (ex: bouton, Ctrl+L, verrouillage de session Linux)."""
        self._vault.lock()
