"""Runs slow tasks (Argon2id) outside the interface thread.

Argon2id takes ~0.5 s per derivation: run on the main thread, it would freeze
the interface and its animations. Both implementations used release the GIL
(measured: the main thread is never blocked for more than a few
milliseconds), so the interface stays smooth.

The result (or the exception) is sent back to the main thread through a
queued Qt signal. `BACKGROUND_TASKS = False` runs the tasks synchronously
(deterministic interface tests).
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
        except Exception as exc:  # noqa: BLE001 - passed on to the main thread
            self._relay.failed.emit(exc)
        else:
            self._relay.succeeded.emit(result)


_pending: set[_Relay] = set()


def run_task(fn: Callable[[], object], on_success: Callable[[object], None],
             on_error: Callable[[Exception], None], parent: QObject | None = None) -> None:
    """Runs `fn` in the background; callbacks run on the main thread."""
    if not BACKGROUND_TASKS:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - passed on to on_error
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
    """Waits for the tasks to finish (used when the application closes and in tests)."""
    return QThreadPool.globalInstance().waitForDone(timeout_ms)
