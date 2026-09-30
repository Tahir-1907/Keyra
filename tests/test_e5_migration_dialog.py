"""E5.1: the upgrade window does not retain the master password.

The password goes into the work function (`MigrationDialog._job`, a closure) and,
on failure, into the exception traceback (`last_error`, whose frames keep their
local variables). These tests check that no APPLICATION reference keeps them
after the flow (success, cancel, failure, retry, background work) and that the
window is destroyed.

They do not claim that the memory is erased: a Python `str` cannot be (see
app/ui/migration_dialog.py).
"""

import gc
import threading
import types
import unittest.mock
import weakref

from app.services import vault_upgrade
from app.services.migration_v4 import MigrationError
from tests.test_e3_upgrade import UpgradeUiTestCase, schema_of


def closures_holding(secret: str) -> list:
    """Live functions whose closure contains `secret` (lasting references)."""
    gc.collect()  # only removes ALREADY unreachable cycles: no conclusion is drawn
    #               about the physical erasure of memory.
    return [f for f in gc.get_objects()
            if isinstance(f, types.FunctionType) and f.__closure__
            and any(_cell_is(c, secret) for c in f.__closure__)]


def _cell_is(cell, secret: str) -> bool:
    try:
        return cell.cell_contents == secret
    except ValueError:  # empty cell
        return False


def traceback_chain(exc):
    """All linked exceptions (__cause__ AND __context__), without looping."""
    seen, pending = [], [exc]
    while pending:
        current = pending.pop()
        if current is None or any(current is s for s in seen):
            continue
        seen.append(current)
        pending += [current.__cause__, current.__context__]
    return seen


def failing_engine():
    """The REAL engine, with an injected failure: MigrationError chained (from) to the
    failure, hence multi-level tracebacks (including the vault_upgrade.upgrade frame)."""
    real = vault_upgrade.migrate_to_v4

    def engine(vault, backup_dir, _fault=None):
        def fault(step):
            if step == "entry":
                raise RuntimeError("simulated failure")
        return real(vault, backup_dir, _fault=fault)
    return engine


class MigrationDialogLifetimeTestCase(UpgradeUiTestCase):
    def setUp(self):
        super().setUp()
        self.refs = {}

    def flush_deletions(self):
        from PySide6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        self.app.processEvents()

    def remember(self, dialog):
        """WEAK references: they do not extend the lifetime of what is observed."""
        self.refs["dialog"] = weakref.ref(dialog)
        self.refs["job"] = weakref.ref(dialog._job)

    def assert_released(self):
        from app.ui.migration_dialog import MigrationDialog

        self.flush_deletions()
        self.assertEqual(self.window.findChildren(MigrationDialog), [])
        self.assertIsNone(self.window._blocking_dialog)
        self.assertIsNone(self.refs["job"](), "work function still referenced")
        self.assertEqual(closures_holding(self.manifest["master_password"]), [])


class TestMigrationDialogReleasesSecrets(MigrationDialogLifetimeTestCase):
    def test_success(self):
        manifest = self.install()

        def confirm():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.start()
            self.assertIsNone(dialog._job)  # work over: no password captured anymore

        errors = self.later(confirm)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNotNone(self.window._shell)  # non-regression: session opened
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()

    def test_cancel(self):
        manifest = self.install()

        def cancel():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.reject()

        errors = self.later(cancel)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNone(self.window._shell)
        self.assertEqual(schema_of(self.path), 3)
        self.assert_released()

    def test_failure_then_close(self):
        manifest = self.install()
        seen = {}

        def fail_then_close():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.start()  # fails
            self.assertTrue(dialog.error.isVisibleTo(dialog))
            self.assertEqual(dialog.ok.text(), "Retry")
            self.assertIsNotNone(dialog._job)  # a new attempt is still possible
            chain = traceback_chain(dialog.last_error)
            self.assertIsInstance(chain[0], MigrationError)
            self.assertTrue(any(isinstance(e, RuntimeError) for e in chain))  # real cause
            # No frame (hence no local variable) retained by the error anymore.
            self.assertTrue(all(e.__traceback__ is None for e in chain))
            seen["error"] = weakref.ref(dialog.last_error)
            dialog.reject()

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", failing_engine()):
            errors = self.later(fail_then_close)
            self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNone(self.window._shell)
        self.assertIn("has not been modified", self.window._unlock_screen.error.text())
        self.assertEqual(schema_of(self.path), 3)
        self.assert_released()
        self.assertIsNone(seen["error"](), "error still referenced after closing")

    def test_retry_does_not_keep_the_previous_attempt(self):
        manifest = self.install()
        real = vault_upgrade.migrate_to_v4
        attempts = []

        def flaky(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise MigrationError("simulated failure")
            return real(*args, **kwargs)

        def fail_then_retry():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.start()  # failure
            first = weakref.ref(dialog.last_error)
            self.assertEqual(dialog.ok.text(), "Retry")
            dialog.start()  # retry: succeeds
            self.assertIsNone(first(), "the first attempt's error is still retained")
            self.assertIsNone(dialog.last_error)
            self.assertIsNone(dialog._job)

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", side_effect=flaky):
            errors = self.later(fail_then_retry)
            self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertEqual(len(attempts), 2)
        self.assertIsNotNone(self.window._shell)
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()


class TestMigrationDialogInBackground(MigrationDialogLifetimeTestCase):
    """Real background work (QThreadPool): the result comes back through a signal."""

    def when_dialog_opens(self, fn):
        """The window opens in a nested exec() loop, after a background unlock: a repeating
        timer watches for it from within that loop."""
        from PySide6.QtCore import QTimer

        from app.ui.migration_dialog import MigrationDialog

        errors = []
        timer = QTimer(self.window)
        timer.setInterval(20)

        def tick():
            dialog = next((d for d in self.open_dialogs() if isinstance(d, MigrationDialog)),
                          None)
            if dialog is None:
                return
            timer.stop()
            try:
                fn(dialog)
            except Exception as exc:  # noqa: BLE001 - raised again after exec()
                errors.append(exc)
                dialog._busy = False
                dialog.close_now()

        timer.timeout.connect(tick)
        timer.start()
        self.addCleanup(timer.stop)
        return errors

    def test_background_success_releases_everything(self):
        from app.ui import tasks

        manifest = self.install()
        tasks.BACKGROUND_TASKS = True  # restored by UiTestCase.tearDown
        real, threads = vault_upgrade.migrate_to_v4, []

        def engine(*args, **kwargs):  # records the thread that actually runs the migration
            threads.append(threading.get_ident())
            return real(*args, **kwargs)

        def confirm(dialog):
            self.remember(dialog)
            dialog.start()  # returns control: the work runs in another thread
            self.assertTrue(dialog.is_busy())

        errors = self.when_dialog_opens(confirm)
        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", engine):
            self.unlock_with(manifest["master_password"])  # background unlock
            self.assertTrue(self._wait_until(lambda: self.window._shell is not None, 30000))
            self.assertTrue(tasks.wait_for_tasks(30000))
        self.assertEqual(errors, [])
        # Migration run by a QThreadPool thread, not by the interface thread.
        self.assertEqual(len(threads), 1)
        self.assertNotEqual(threads[0], threading.main_thread().ident)
        self.assertEqual(tasks._pending, set())  # no pending hand-over
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()

    def test_background_failure_is_delivered_then_retry_succeeds(self):
        """Failure in the worker thread: the error comes back to the interface thread (nothing
        lost or silent), the vault stays v3, "Retry" starts real background work again,
        which succeeds; then everything is released."""
        from PySide6.QtCore import QTimer

        from app.ui import tasks

        manifest = self.install()
        tasks.BACKGROUND_TASKS = True  # restored by UiTestCase.tearDown
        real, threads, seen = vault_upgrade.migrate_to_v4, [], {}
        fail_first = failing_engine()

        def engine(*args, **kwargs):
            threads.append(threading.get_ident())
            return (fail_first if len(threads) == 1 else real)(*args, **kwargs)

        def after_failure(dialog, timer):
            if dialog.is_busy() or dialog.last_error is None:
                return  # the error has not come back from the worker thread yet
            timer.stop()
            seen["error"] = dialog.error.text()
            seen["retry"] = dialog.ok.text()
            seen["schema_after_failure"] = schema_of(self.path)
            dialog.start()  # "Retry": second background work

        def confirm(dialog):
            self.remember(dialog)
            dialog.start()
            watcher = QTimer(self.window)
            watcher.setInterval(20)
            watcher.timeout.connect(lambda: after_failure(dialog, watcher))
            watcher.start()
            self.addCleanup(watcher.stop)

        errors = self.when_dialog_opens(confirm)
        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", engine):
            self.unlock_with(manifest["master_password"])
            self.assertTrue(self._wait_until(lambda: self.window._shell is not None, 30000))
            self.assertTrue(tasks.wait_for_tasks(30000))
        self.assertEqual(errors, [])
        self.assertIn("did not complete", seen["error"])
        self.assertIn("has not been modified", seen["error"])
        self.assertEqual(seen["retry"], "Retry")
        self.assertEqual(seen["schema_after_failure"], 3)
        self.assertEqual(len(threads), 2)
        self.assertNotIn(threading.main_thread().ident, threads)
        self.assertEqual(tasks._pending, set())
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()
