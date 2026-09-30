"""E5.1 : la fenêtre de mise à niveau ne retient pas le mot de passe maître.

Le mot de passe entre dans la fonction de travail (`MigrationDialog._job`, une
closure) et, en cas d'échec, dans la trace de l'exception (`last_error`, dont
les frames gardent leurs variables locales). Ces tests vérifient qu'aucune
référence APPLICATIVE ne les conserve après le flux (succès, annulation, échec,
nouvel essai, travail en arrière-plan) et que la fenêtre est détruite.

Ils ne prétendent pas que la mémoire est effacée : une `str` Python ne peut pas
l'être (voir app/ui/migration_dialog.py).
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
    """Fonctions vivantes dont la closure contient `secret` (références durables)."""
    gc.collect()  # élimine seulement les cycles DÉJÀ inaccessibles : aucune conclusion
    #               sur l'effacement physique de la mémoire n'en est tirée.
    return [f for f in gc.get_objects()
            if isinstance(f, types.FunctionType) and f.__closure__
            and any(_cell_is(c, secret) for c in f.__closure__)]


def _cell_is(cell, secret: str) -> bool:
    try:
        return cell.cell_contents == secret
    except ValueError:  # cellule vide
        return False


def traceback_chain(exc):
    """Toutes les exceptions liées (__cause__ ET __context__), sans boucle."""
    seen, pending = [], [exc]
    while pending:
        current = pending.pop()
        if current is None or any(current is s for s in seen):
            continue
        seen.append(current)
        pending += [current.__cause__, current.__context__]
    return seen


def failing_engine():
    """Le VRAI moteur, avec une panne injectée : MigrationError chaînée (from) à la panne,
    donc des traces à plusieurs niveaux (dont la frame de vault_upgrade.upgrade)."""
    real = vault_upgrade.migrate_to_v4

    def engine(vault, backup_dir, _fault=None):
        def fault(step):
            if step == "entry":
                raise RuntimeError("panne simulée")
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
        """Références FAIBLES : n'allongent pas la durée de vie de ce qu'on observe."""
        self.refs["dialog"] = weakref.ref(dialog)
        self.refs["job"] = weakref.ref(dialog._job)

    def assert_released(self):
        from app.ui.migration_dialog import MigrationDialog

        self.flush_deletions()
        self.assertEqual(self.window.findChildren(MigrationDialog), [])
        self.assertIsNone(self.window._blocking_dialog)
        self.assertIsNone(self.refs["job"](), "fonction de travail encore référencée")
        self.assertEqual(closures_holding(self.manifest["master_password"]), [])


class TestMigrationDialogReleasesSecrets(MigrationDialogLifetimeTestCase):
    def test_success(self):
        manifest = self.install()

        def confirm():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.start()
            self.assertIsNone(dialog._job)  # travail terminé : plus de mot de passe capturé

        errors = self.later(confirm)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNotNone(self.window._shell)  # non-régression : session ouverte
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
            dialog.start()  # échoue
            self.assertTrue(dialog.error.isVisibleTo(dialog))
            self.assertEqual(dialog.ok.text(), "Réessayer")
            self.assertIsNotNone(dialog._job)  # nouvel essai encore possible
            chain = traceback_chain(dialog.last_error)
            self.assertIsInstance(chain[0], MigrationError)
            self.assertTrue(any(isinstance(e, RuntimeError) for e in chain))  # cause réelle
            # Plus aucune frame (et donc aucune variable locale) retenue par l'erreur.
            self.assertTrue(all(e.__traceback__ is None for e in chain))
            seen["error"] = weakref.ref(dialog.last_error)
            dialog.reject()

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", failing_engine()):
            errors = self.later(fail_then_close)
            self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNone(self.window._shell)
        self.assertIn("pas été modifié", self.window._unlock_screen.error.text())
        self.assertEqual(schema_of(self.path), 3)
        self.assert_released()
        self.assertIsNone(seen["error"](), "erreur encore référencée après fermeture")

    def test_retry_does_not_keep_the_previous_attempt(self):
        manifest = self.install()
        real = vault_upgrade.migrate_to_v4
        attempts = []

        def flaky(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise MigrationError("panne simulée")
            return real(*args, **kwargs)

        def fail_then_retry():
            dialog = self.migration_dialog()
            self.remember(dialog)
            dialog.start()  # échec
            first = weakref.ref(dialog.last_error)
            self.assertEqual(dialog.ok.text(), "Réessayer")
            dialog.start()  # nouvel essai : réussit
            self.assertIsNone(first(), "l'erreur du premier essai est encore retenue")
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
    """Vrai travail d'arrière-plan (QThreadPool) : le résultat revient par signal."""

    def when_dialog_opens(self, fn):
        """La fenêtre s'ouvre dans une boucle exec() imbriquée, après un déverrouillage en
        arrière-plan : un minuteur répété la guette depuis cette boucle."""
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
            except Exception as exc:  # noqa: BLE001 - remonté après exec()
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
        tasks.BACKGROUND_TASKS = True  # rétabli par UiTestCase.tearDown
        real, threads = vault_upgrade.migrate_to_v4, []

        def engine(*args, **kwargs):  # note le fil qui exécute réellement la migration
            threads.append(threading.get_ident())
            return real(*args, **kwargs)

        def confirm(dialog):
            self.remember(dialog)
            dialog.start()  # rend la main : le travail tourne dans un autre fil
            self.assertTrue(dialog.is_busy())

        errors = self.when_dialog_opens(confirm)
        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", engine):
            self.unlock_with(manifest["master_password"])  # déverrouillage en arrière-plan
            self.assertTrue(self._wait_until(lambda: self.window._shell is not None, 30000))
            self.assertTrue(tasks.wait_for_tasks(30000))
        self.assertEqual(errors, [])
        # Migration exécutée par un fil du QThreadPool, pas par le fil de l'interface.
        self.assertEqual(len(threads), 1)
        self.assertNotEqual(threads[0], threading.main_thread().ident)
        self.assertEqual(tasks._pending, set())  # aucun relais en attente
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()

    def test_background_failure_is_delivered_then_retry_succeeds(self):
        """Échec dans le fil de travail : l'erreur revient au fil de l'interface (rien de
        perdu ni de silencieux), le coffre reste v3, « Réessayer » relance un vrai travail
        d'arrière-plan qui réussit ; puis tout est libéré."""
        from PySide6.QtCore import QTimer

        from app.ui import tasks

        manifest = self.install()
        tasks.BACKGROUND_TASKS = True  # rétabli par UiTestCase.tearDown
        real, threads, seen = vault_upgrade.migrate_to_v4, [], {}
        fail_first = failing_engine()

        def engine(*args, **kwargs):
            threads.append(threading.get_ident())
            return (fail_first if len(threads) == 1 else real)(*args, **kwargs)

        def after_failure(dialog, timer):
            if dialog.is_busy() or dialog.last_error is None:
                return  # l'erreur n'est pas encore revenue du fil de travail
            timer.stop()
            seen["error"] = dialog.error.text()
            seen["retry"] = dialog.ok.text()
            seen["schema_after_failure"] = schema_of(self.path)
            dialog.start()  # « Réessayer » : second travail d'arrière-plan

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
        self.assertIn("n'a pas abouti", seen["error"])
        self.assertIn("pas été modifié", seen["error"])
        self.assertEqual(seen["retry"], "Réessayer")
        self.assertEqual(seen["schema_after_failure"], 3)
        self.assertEqual(len(threads), 2)
        self.assertNotIn(threading.main_thread().ident, threads)
        self.assertEqual(tasks._pending, set())
        self.assertEqual(schema_of(self.path), 4)
        self.assert_released()
