"""Exécution de tâches lentes (Argon2id) hors du fil de l'interface.

Argon2id prend ~0,5 s par dérivation : exécuté dans le fil principal, il
figerait l'interface et ses animations. Les deux implémentations utilisées
libèrent le GIL (mesuré : le fil principal n'est jamais bloqué plus de
quelques millisecondes), l'interface reste donc fluide.

Le résultat (ou l'exception) est renvoyé au fil principal par un signal
Qt en file d'attente. `BACKGROUND_TASKS = False` exécute les tâches de
façon synchrone (tests d'interface déterministes).
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

BACKGROUND_TASKS = True


class _Relay(QObject):
    succeeded = Signal(object)
    failed = Signal(object)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], object], relay: _Relay) -> None:
        super().__init__()
        self._fn = fn
        self._relay = relay

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - transmis au fil principal
            self._relay.failed.emit(exc)
        else:
            self._relay.succeeded.emit(result)


_pending: set[_Relay] = set()


def run_task(fn: Callable[[], object], on_success: Callable[[object], None],
             on_error: Callable[[Exception], None], parent: QObject | None = None) -> None:
    """Exécute `fn` en arrière-plan ; les rappels s'exécutent dans le fil principal."""
    if not BACKGROUND_TASKS:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - transmis à on_error
            on_error(exc)
        else:
            on_success(result)
        return
    relay = _Relay(parent)
    _pending.add(relay)

    def finish(callback, value) -> None:
        _pending.discard(relay)
        relay.deleteLater()
        callback(value)

    relay.succeeded.connect(lambda value: finish(on_success, value))
    relay.failed.connect(lambda exc: finish(on_error, exc))
    QThreadPool.globalInstance().start(_Task(fn, relay))


def wait_for_tasks(timeout_ms: int = 10_000) -> bool:
    """Attend la fin des tâches (utilisé à la fermeture de l'application et en test)."""
    return QThreadPool.globalInstance().waitForDone(timeout_ms)
