"""Tests d'intégration de l'interface (Qt « offscreen », sans affichage).

Ignorés proprement si PySide6 n'est pas installé.
"""

import os
import secrets
import tempfile
import unittest
import unittest.mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None


@unittest.skipIf(QApplication is None, "PySide6 non installé")
class UiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        env = {
            "XDG_DATA_HOME": os.path.join(self._tmpdir.name, "data"),
            "XDG_CONFIG_HOME": os.path.join(self._tmpdir.name, "config"),
            "XDG_CACHE_HOME": os.path.join(self._tmpdir.name, "cache"),
            # Les sauvegardes automatiques vont dans ~/Documents : HOME isolé aussi.
            "HOME": os.path.join(self._tmpdir.name, "home"),
        }
        self._old_env = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        from app.ui import effects, tasks
        from app.ui.main_window import MainWindow

        # Argon2id synchrone et animations coupées : tests déterministes. Les modes
        # « arrière-plan » et « animé » ont leurs propres tests.
        tasks.BACKGROUND_TASKS = False
        self.window = MainWindow()
        effects.set_animations_enabled(False)
        self.master = secrets.token_urlsafe(16)

    def tearDown(self):
        from app.ui import effects, tasks

        tasks.BACKGROUND_TASKS = True
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        effects.set_animations_enabled(True)
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmpdir.cleanup()

    # --- Aides -----------------------------------------------------------------------

    def _create_vault(self, name: str = "Test UI", recovery: bool = False):
        screen = self.window._create_screen
        screen.with_recovery.setChecked(recovery)
        screen.name.setText(name)
        screen.password.setText(self.master)
        screen.confirm.setText(self.master)
        screen._submit()
        self.assertIsNotNone(self.window._shell)
        return self.window._shell

    def _add(self, shell, **fields):
        from app.core.entries import Entry

        entry_id = shell.ctx.entries.create_entry(Entry(**fields))
        shell.data_changed()
        return entry_id

    def _unlock(self):
        unlock = self.window._unlock_screen
        unlock.password.setText(self.master)
        unlock._submit()
        return self.window._shell

    def _wait_until(self, condition, timeout_ms: int = 10000) -> bool:
        from PySide6.QtTest import QTest

        for _ in range(timeout_ms // 20):
            if condition():
                return True
            QTest.qWait(20)
        return condition()

    def _confirm(self, answer: bool):
        return unittest.mock.patch("app.ui.dialogs.confirm", return_value=answer)


class TestLockScreens(UiTestCase):
    def test_create_vault_errors(self):
        screen = self.window._create_screen
        screen.password.setText(self.master)
        screen.confirm.setText(self.master + "x")
        screen._submit()
        self.assertIn("ne correspondent pas", screen.error.text())
        screen.password.setText("court")
        screen.confirm.setText("court")
        screen._submit()
        self.assertIn("au moins", screen.error.text())
        self.assertEqual(screen.password.text(), "")  # champ vidé après tentative
        self.assertIsNone(self.window._shell)

    def test_weak_master_password_requires_confirmation(self):
        screen = self.window._create_screen
        with self._confirm(False) as confirm:
            screen.password.setText("Soleil2024!")
            screen.confirm.setText("Soleil2024!")
            screen._submit()
        confirm.assert_called_once()
        self.assertIsNone(self.window._shell)

    def test_lock_unlock_cycle(self):
        shell = self._create_vault()
        secret = "pw-" + secrets.token_hex(8)
        entry_id = self._add(shell, service_name="Gmail", password=secret)
        self.window.lock()
        self.assertIsNone(self.window._shell)
        self.assertIsNone(self.window._session)
        self.assertIs(self.window._stack.currentWidget(), self.window._unlock_screen)
        unlock = self.window._unlock_screen
        unlock.password.setText("mauvais-" + secrets.token_hex(4))
        unlock._submit()
        self.assertIn("incorrect", unlock.error.text())
        shell = self._unlock()
        self.assertEqual(shell.ctx.entries.get_entry(entry_id).password, secret)
        self.assertEqual(shell.current_key, "dashboard")

    def test_background_unlock_keeps_ui_responsive(self):
        from app.ui import tasks

        self._create_vault()
        self.window.lock()
        tasks.BACKGROUND_TASKS = True
        unlock = self.window._unlock_screen
        unlock.password.setText(self.master)
        unlock._submit()
        self.assertTrue(self.window._busy)
        self.assertTrue(unlock.busy_row.isVisibleTo(unlock))
        self.assertTrue(self._wait_until(lambda: self.window._shell is not None))
        self.window.lock()
        unlock.password.setText("mauvais-" + secrets.token_hex(4))
        unlock._submit()
        self.assertTrue(self._wait_until(lambda: not self.window._busy))
        self.assertIsNone(self.window._session)
        self.assertIn("incorrect", unlock.error.text())


class TestNavigation(UiTestCase):
    def test_every_view_renders_and_direction(self):
        from app.ui import effects

        shell = self._create_vault()
        self._add(shell, service_name="GitHub", password="azerty123")
        for key in ("vault", "security", "history", "trash", "backups", "settings", "dashboard"):
            shell.navigate(key)
            self.assertEqual(shell.current_key, key)
            self.assertIs(shell.stack.currentWidget(), shell.pages[key])
            self.assertTrue(shell.nav[key].isChecked())
            self.assertEqual(shell.title.text(), shell.pages[key].title)
        # La vue suivante entre par la droite (+1), la précédente par la gauche (-1).
        with unittest.mock.patch.object(effects, "switch_page") as switch:
            shell.navigate("security")
            shell.navigate("vault")
        self.assertEqual([c.args[2] for c in switch.call_args_list], [1, -1])

    def test_search_from_header_opens_vault(self):
        shell = self._create_vault()
        self._add(shell, service_name="Société Générale")
        self._add(shell, service_name="Gmail")
        shell.navigate("dashboard")
        shell.search.setText("societe")
        self.assertEqual(shell.current_key, "vault")
        # Recherche appliquée après le délai de frappe (debounce, E2).
        self.assertTrue(self._wait_until(lambda: not shell.vault_page.has_pending_search()))
        self.assertEqual(shell.vault_page.list.model().rowCount(), 1)
        shell.search.setText("introuvable")
        self.assertTrue(self._wait_until(lambda: not shell.vault_page.has_pending_search()))
        self.assertIs(shell.vault_page.list_stack.currentWidget(), shell.vault_page.empty)
        self.assertEqual(shell.vault_page.empty.title.text(), "Aucun résultat")

    def test_no_ambiguous_shortcuts(self):
        from PySide6.QtGui import QAction

        self._create_vault()
        seen = {}
        for action in self.window.findChildren(QAction):
            key = action.shortcut().toString()
            if not key:
                continue
            self.assertNotIn(key, seen, f"raccourci en double : {key}")
            seen[key] = action
        for expected in ("Ctrl+N", "Ctrl+F", "Ctrl+L", "Ctrl+K", "Ctrl+G", "F1", "Alt+1", "Alt+6"):
            self.assertIn(expected, seen)

    def test_actions_follow_lock_state(self):
        actions = self.window._menus.actions
        self.assertFalse(actions["new_entry"].isEnabled())
        self.assertTrue(actions["settings"].isEnabled())
        self._create_vault()
        self.assertTrue(actions["new_entry"].isEnabled())
        actions["go_security"].trigger()
        self.assertEqual(self.window._shell.current_key, "security")
        self.window.lock()
        self.assertFalse(actions["copy_password"].isEnabled())

    def test_command_palette_filters_and_runs(self):
        from app.ui.command_palette import CommandPalette

        shell = self._create_vault()
        entry_id = self._add(shell, service_name="Société Générale", username="alice")
        palette = CommandPalette(self.window, self.window.command_palette_commands())
        self.assertIn("Société Générale", [c.label for c in palette.matching("societe")])
        self.assertIn("Générateur de mots de passe", [c.label for c in palette.matching("gener")])
        palette.input.setText("societe generale")
        palette._run(palette.results.currentItem())
        self.app.processEvents()
        self.assertEqual(shell.current_key, "vault")
        self.assertEqual(shell.vault_page.detail.current_entry_id(), entry_id)
        palette.deleteLater()


class TestVaultView(UiTestCase):
    def test_empty_vault_state(self):
        shell = self._create_vault()
        shell.navigate("vault")
        page = shell.vault_page
        self.assertIs(page.list_stack.currentWidget(), page.empty)
        self.assertEqual(page.empty.title.text(), "Votre coffre est vide")

    def test_selection_opens_detail_and_favorites(self):
        shell = self._create_vault()
        a = self._add(shell, service_name="A", password="x" * 20)
        self._add(shell, service_name="B")
        shell.navigate("vault")
        page = shell.vault_page
        page.list.select_entry(a)
        self.assertEqual(page.detail.current_entry_id(), a)
        page.list.clearSelection()
        self.assertIsNone(page.detail.current_entry_id())  # jamais de détail sans sélection
        page.set_favorite(a, True)
        page._set_favorites(True)
        self.assertEqual([s.id for s in page.list.model().rows()], [a])

    def test_delete_requires_confirmation_then_trash(self):
        shell = self._create_vault()
        a = self._add(shell, service_name="GitHub")
        shell.navigate("vault")
        page = shell.vault_page
        with self._confirm(False):
            page.delete_entry(a)
        self.assertEqual(shell.ctx.entries.trash_count(), 0)
        with self._confirm(True) as confirm:
            page.delete_entry(a)
        self.assertIn("corbeille", confirm.call_args.args[2])
        self.assertEqual(shell.ctx.entries.trash_count(), 1)
        self.assertEqual(shell.nav["trash"].badge.text(), "1")

    def test_trash_restore_and_reinforced_purge(self):
        shell = self._create_vault()
        a = self._add(shell, service_name="Temp")
        b = self._add(shell, service_name="Temp2")
        shell.ctx.entries.delete_entry(a)
        shell.ctx.entries.delete_entry(b)
        shell.navigate("trash")
        trash = shell.pages["trash"]
        self.assertEqual(trash.list.model().rowCount(), 2)
        trash.restore(a)
        self.assertEqual(shell.ctx.entries.trash_count(), 1)
        trash.list.select_entry(b)
        with self._confirm(True) as confirm:
            trash.purge(b)
        self.assertIsNotNone(confirm.call_args.kwargs.get("acknowledge"))  # confirmation renforcée
        self.assertEqual(shell.ctx.entries.trash_count(), 0)
        self.assertIs(trash.stack.currentWidget(), trash.empty)

    def test_copy_password_toast_and_lock_clears_clipboard(self):
        from PySide6.QtGui import QGuiApplication

        shell = self._create_vault()
        secret = "pw-" + secrets.token_hex(8)
        a = self._add(shell, service_name="Gmail", password=secret)
        shell.navigate("vault")
        shell.vault_page.list.select_entry(a)
        shell.vault_page.copy_selected_password()
        self.assertEqual(QGuiApplication.clipboard().text(), secret)
        self.assertIn("Mot de passe copié", self.window._toasts.active_titles())
        self.window.lock()
        self.assertEqual(QGuiApplication.clipboard().text(), "")
        self.assertEqual(self.window._toasts.active_titles(), [])

    def test_password_show_and_copy_buttons(self):
        from PySide6.QtGui import QGuiApplication

        shell = self._create_vault()
        secret = "pw-" + secrets.token_hex(8)
        a = self._add(shell, service_name="GitHub", password=secret)
        shell.navigate("vault")
        shell.vault_page.list.select_entry(a)
        show, copy = shell.vault_page.detail.secret_buttons()
        self.assertEqual((show.text(), copy.text()), ("Afficher", "Copier"))
        box = shell.vault_page.detail._secret_boxes[0]
        self.assertNotIn(secret, box.value.text())      # masqué par défaut
        show.click()
        # « Afficher » montre le mot de passe (points de coupure invisibles mis à part).
        self.assertEqual(box.value.text().replace("\u200b", ""), secret)
        self.assertEqual(show.text(), "Masquer")
        copy.click()
        self.assertEqual(QGuiApplication.clipboard().text(), secret)
        self.assertEqual(copy.text(), "Copié")
        show.click()
        self.assertNotIn(secret, box.value.text())

    def test_long_values_never_overflow_detail_panel(self):
        from PySide6.QtGui import QGuiApplication

        shell = self._create_vault()
        long_password = "Q7$kV9#pL2!xR8&mN4@zT6%wB1^cY3*hJ5" * 2
        a = self._add(shell, service_name="Compte universitaire avec un nom très long",
                      username="prenom.nom.etudiant@universite-exemple-longue.fr",
                      url="https://authentification.universite-exemple-longue.fr/cas/login"
                          "?service=https%3A%2F%2Fent.exemple.fr",
                      password=long_password)
        self.window.resize(1100, 700)
        self.window.show()
        shell.navigate("vault")
        shell.vault_page.list.select_entry(a)
        detail = shell.vault_page.detail
        show, copy = detail.secret_buttons()
        show.click()
        self.app.processEvents()
        # Le contenu ne dépasse jamais la zone visible : les boutons restent accessibles.
        self.assertLessEqual(detail.content.width(), detail.scroll.viewport().width())
        for button in (show, copy):
            right = button.mapTo(detail, button.rect().topRight()).x()
            self.assertLessEqual(right, detail.width())
        copy.click()  # l'affichage coupe la ligne, la copie reste exacte
        self.assertEqual(QGuiApplication.clipboard().text(), long_password)

    def test_empty_state_texts_are_never_clipped(self):
        from app.ui import components as ui

        shell = self._create_vault()  # coffre vide : états vides partout
        self.window.show()
        checked = 0
        for width in (1320, 800):
            self.window.resize(width, 820)
            for key in ("dashboard", "vault", "security", "history", "trash", "backups"):
                shell.navigate(key)
                self.app.processEvents()
                page = shell.pages[key]
                for empty in page.findChildren(ui.EmptyState):
                    if not empty.isVisibleTo(page):
                        continue
                    text = empty.text
                    self.assertGreaterEqual(text.height(), text.heightForWidth(text.width()),
                                            f"{key} à {width} px : {text.text()!r}")
                    checked += 1
        self.assertGreater(checked, 4)

    def test_window_fits_half_screen_and_compacts(self):
        """Accrochage GNOME (Super+←/→) : chaque vue tient dans une moitié d'écran."""
        from PySide6.QtWidgets import QScrollArea

        from app.ui import theme

        shell = self._create_vault()
        self._add(shell, service_name="Compte au nom particulièrement long pour le test",
                  url="https://un-domaine-vraiment-tres-long.exemple.fr/chemin/connexion",
                  password="Q7$kV9#pL2!xR8&mN4@zT6%wB1^cY3*hJ5")
        self.assertLessEqual(self.window.minimumSize().width(), 800)  # moitié de 1 600 px
        self.window.show()
        for width in (800, 960):
            self.window.resize(width, 700)
            self.app.processEvents()
            self.assertEqual(self.window.width(), width)
            self.assertTrue(shell.is_compact)
            for key in ("dashboard", "vault", "security", "history", "trash", "backups",
                        "settings"):
                shell.navigate(key)
                self.app.processEvents()
                page = shell.pages[key]
                self.assertLessEqual(page.minimumSizeHint().width(), page.width(), key)
                for area in page.findChildren(QScrollArea):
                    if area.isVisibleTo(page) and area.widget() is not None:
                        self.assertLessEqual(area.widget().minimumSizeHint().width(),
                                             area.viewport().width(), f"{key} à {width} px")
        self.window.resize(theme.COMPACT_BREAKPOINT + 100, 800)
        self.app.processEvents()
        self.assertFalse(shell.is_compact)
        self.assertTrue(shell.nav["vault"].text_label.isVisibleTo(shell))

    def test_history_dialog_restores_version(self):
        from app.ui.history_dialog import HistoryDialog

        shell = self._create_vault()
        a = self._add(shell, service_name="Mail", password="v1")
        entry = shell.ctx.entries.get_entry(a)
        entry.password = "v2"
        shell.ctx.entries.update_entry(entry)
        dialog = HistoryDialog(shell.ctx.entries, a, self.window._clipboard, {})
        self.assertEqual(dialog.versions.count(), 1)
        self.assertEqual(dialog.detail.current_entry_id(), a)
        shell.ctx.entries.restore_version(dialog._current().id)
        dialog.close_now()
        self.assertEqual(shell.ctx.entries.get_entry(a).password, "v1")


class TestInsightViews(UiTestCase):
    def test_dashboard_stats_match_audit(self):
        from app.core.audit import run_audit
        from app.core.generator import generate_password

        shell = self._create_vault()
        self._add(shell, service_name="Faible", password="azerty123")
        self._add(shell, service_name="Fort", password=generate_password().value)
        self._add(shell, service_name="Vide")
        shell.navigate("dashboard")
        page = shell.pages["dashboard"]
        page.refresh()
        report = run_audit(shell.ctx.entries)
        flagged = len({f.entry_id for f in report.findings})
        self.assertEqual(page.cards["total"].value.text(), "3")
        self.assertEqual(page.cards["secure"].value.text(), str(3 - flagged))
        self.assertIn("attention", page.status.text())

    def test_security_score_is_the_documented_audit_score(self):
        from app.core.audit import run_audit
        from app.core.generator import generate_password

        shell = self._create_vault()
        self._add(shell, service_name="Faible", password="azerty123")
        self._add(shell, service_name="Fort", password=generate_password().value)
        shell.navigate("security")
        page = shell.pages["security"]
        page.run()
        report = run_audit(shell.ctx.entries)
        self.assertEqual(page.ring._score, report.score)
        self.assertIn("1 sur 2", page.method.text())
        self.assertEqual(page.issue_cards["weak"].count.text(), "1")

    def test_history_timeline_shows_recorded_events_only(self):
        from app.core.activity import vault_activity

        shell = self._create_vault()
        a = self._add(shell, service_name="GitHub", password="1")
        entry = shell.ctx.entries.get_entry(a)
        entry.password = "2"
        shell.ctx.entries.update_entry(entry)
        shell.ctx.entries.delete_entry(a)
        kinds = sorted(e.kind for e in vault_activity(shell.ctx.vault))
        self.assertEqual(kinds, ["created", "modified", "trashed"])
        shell.navigate("history")
        texts = [w.text() for w in shell.pages["history"].findChildren(type(shell.title))]
        self.assertIn("AUJOURD'HUI", texts)
        self.assertIn("Déplacé vers la corbeille", texts)

    def test_backups_page_create_and_list(self):
        from app.services import backup
        from app.services.settings import backup_directory

        shell = self._create_vault()
        shell.navigate("backups")
        page = shell.pages["backups"]
        self.assertEqual(page.last.text(), "Aucune sauvegarde")
        page.create_backup()
        self.assertNotEqual(page.last.text(), "Aucune sauvegarde")
        infos = backup.list_backups(backup_directory(shell.ctx.settings()))
        self.assertEqual(len(infos), 1)
        self.assertTrue(str(infos[0].path).startswith(self._tmpdir.name))


class TestSecurityBehaviours(UiTestCase):
    def test_secure_clipboard_clears_only_its_own_value(self):
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtTest import QTest

        from app.ui.secure_clipboard import SecureClipboard

        clipboard = QGuiApplication.clipboard()
        guard = SecureClipboard(clear_after_seconds=1)
        secret = "pw-" + secrets.token_hex(8)
        guard.copy(secret, "Mot de passe")
        self.assertEqual(clipboard.text(), secret)
        self.assertEqual(bytes(clipboard.mimeData().data("x-kde-passwordManagerHint")), b"secret")
        QTest.qWait(1300)
        self.assertEqual(clipboard.text(), "")
        guard.copy("pw-" + secrets.token_hex(8), "Mot de passe")
        clipboard.setText("texte de l'utilisateur")
        guard.clear_if_ours()
        self.assertEqual(clipboard.text(), "texte de l'utilisateur")

    def test_auto_lock_closes_open_modal(self):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QDialog

        shell = self._create_vault()
        self.window._session.auto_lock_seconds = 0
        seen = {}

        def trigger_idle_check():
            seen["dialog"] = self.app.activeModalWidget()
            self.window._check_idle()

        QTimer.singleShot(200, trigger_idle_check)
        shell.navigate("new_entry")  # boucle modale : le verrouillage doit la fermer
        self.assertIsInstance(seen["dialog"], QDialog)
        self.assertFalse(seen["dialog"].isVisible())
        self.assertIsNone(self.window._session)
        self.assertIn("inactivité", self.window._unlock_screen.info.text())

    def test_activity_postpones_auto_lock(self):
        self._create_vault()
        session = self.window._session
        session.auto_lock_seconds = 60
        session._last_activity -= 59
        self.window._on_activity()
        self.window._check_idle()
        self.assertIsNotNone(self.window._session)

    def test_session_lock_signal_and_setting(self):
        self._create_vault()
        self.window._settings.lock_on_session_lock = False
        self.window._system_lock._on_screensaver(True)
        self.assertIsNotNone(self.window._session)
        self.window._settings.lock_on_session_lock = True
        self.window._system_lock._on_screensaver(True)
        self.assertIsNone(self.window._session)
        self.assertIn("session", self.window._unlock_screen.info.text())

    def test_auto_backup_on_lock_only_when_modified(self):
        from app.services import backup

        self._create_vault()
        self.window.lock()
        self.assertEqual(backup.list_backups(), [])
        shell = self._unlock()
        self._add(shell, service_name="Nouvelle", password="x")
        self.window.lock()
        backups = backup.list_backups()
        self.assertEqual([b.kind for b in backups], ["auto"])
        self.assertTrue(str(backups[0].path).startswith(self._tmpdir.name))

    def _drop_malformed_backup(self) -> None:
        """Fichier .mcfbak à en-tête malformé (version non numérique) dans le dossier."""
        import json
        import struct

        from app.services import backup
        from app.services.settings import backup_directory

        header = json.dumps({"format": "mon-coffre-fort-backup", "version": "x"}).encode()
        path = backup_directory(self.window._settings) / "piege.mcfbak"
        path.write_bytes(backup.MAGIC + struct.pack(">I", len(header)) + header)

    def _assert_fully_locked(self, vault) -> None:
        self.assertIsNone(self.window._session)
        self.assertTrue(vault.is_locked)
        self.assertFalse(self.window._idle_timer.isActive())
        self.assertIsNone(self.window._shell)

    def test_auto_lock_with_malformed_backup_file(self):
        # Régression (audit phase 3, I-1) : la rotation relisait cet en-tête et levait
        # ValueError AVANT le verrouillage — coffre ouvert, minuteur arrêté.
        from app.services import backup

        shell = self._create_vault()
        self._add(shell, service_name="Banque", password="x")
        self._drop_malformed_backup()
        vault = self.window._session.vault
        self.window._session.auto_lock_seconds = 0
        self.window._check_idle()
        self._assert_fully_locked(vault)
        self.assertEqual([b.kind for b in backup.list_backups()], ["auto"])

    def test_manual_lock_with_malformed_backup_file(self):
        shell = self._create_vault()
        self._add(shell, service_name="Banque", password="x")
        self._drop_malformed_backup()
        vault = self.window._session.vault
        self.window._menus.actions["lock"].trigger()  # Ctrl+L
        self._assert_fully_locked(vault)

    def test_lock_when_auto_backup_fails_unexpectedly(self):
        from app.services import backup

        shell = self._create_vault()
        self._add(shell, service_name="Banque", password="x")
        vault = self.window._session.vault
        with unittest.mock.patch.object(backup, "create_backup",
                                        side_effect=RuntimeError("inattendu")), \
                self.assertLogs("mon_coffre", level="ERROR") as logs:
            self.window.lock()
        self._assert_fully_locked(vault)
        self.assertIn("sauvegarde automatique a échoué", self.window._unlock_screen.info.text())
        self.assertIn("RuntimeError", "\n".join(logs.output))

    def test_lock_when_a_ui_step_fails(self):
        # Une étape d'interface qui échoue remonte son erreur, mais après le verrouillage.
        self._create_vault()
        vault = self.window._session.vault
        with unittest.mock.patch.object(self.window._toasts, "clear",
                                        side_effect=RuntimeError("interface")), \
                self.assertRaises(RuntimeError):
            self.window.lock()
        self._assert_fully_locked(vault)

    def test_auto_lock_still_backs_up(self):
        from app.services import backup

        shell = self._create_vault()
        self._add(shell, service_name="A", password="x")
        self.window._session.auto_lock_seconds = 0
        self.window._check_idle()
        self.assertIsNone(self.window._session)
        self.assertEqual(len(backup.list_backups()), 1)


class TestSettingsAndVaults(UiTestCase):
    def test_settings_page_saves_automatically(self):
        from app.services.settings import load_settings

        shell = self._create_vault()
        shell.navigate("settings")
        page = shell.pages["settings"]
        page.auto_lock.setCurrentIndex(page.auto_lock.findData(60))
        page.clipboard.setCurrentIndex(page.clipboard.findData(10))
        self.assertEqual(self.window._session.auto_lock_seconds, 60)
        self.assertEqual(self.window._clipboard.clear_after_seconds, 10)
        self.assertEqual(load_settings().auto_lock_seconds, 60)
        # Impossible de désactiver toutes les classes de caractères du générateur.
        for key in ("generator_uppercase", "generator_lowercase", "generator_digits",
                    "generator_symbols"):
            page.gen_toggles[key].setChecked(False)
        saved = load_settings()
        self.assertTrue(any((saved.generator_uppercase, saved.generator_lowercase,
                             saved.generator_digits, saved.generator_symbols)))

    def test_animations_toggle_persists(self):
        from app.services.settings import load_settings
        from app.ui import effects

        self.window._menus.actions["animations"].setChecked(False)
        self.assertFalse(effects.animations_enabled())
        self.assertFalse(load_settings().animations)
        self.window._menus.actions["animations"].setChecked(True)
        self.assertTrue(effects.animations_enabled())

    def test_generator_uses_settings_and_fills_entry(self):
        from dataclasses import replace

        from app.ui.entry_dialog import EntryDialog
        from app.ui.generator_dialog import GeneratorDialog

        settings = replace(self.window._settings, generator_length=40, generator_symbols=False)
        generator = GeneratorDialog(self.window._clipboard, use_mode=True, settings=settings)
        value = generator.result.text()
        self.assertEqual(len(value), 40)
        self.assertTrue(value.isalnum())
        generator._use()
        self.assertEqual(generator.chosen_value, value)
        shell = self._create_vault()
        dialog = EntryDialog(shell.ctx.entries, [], self.window._clipboard)
        dialog.password.setText(value)
        self.assertTrue(dialog.strength_label.text().startswith("Très fort"))
        dialog.close_now()

    def test_generator_shows_longest_values_entirely(self):
        from dataclasses import replace

        from PySide6.QtCore import Qt
        from PySide6.QtGui import QFontMetrics, QGuiApplication
        from PySide6.QtWidgets import QLabel

        from app.core.generator import MAX_PASSPHRASE_WORDS, MAX_PASSWORD_LENGTH
        from app.ui.generator_dialog import _SEPARATORS, GeneratorDialog

        settings = replace(self.window._settings, generator_length=MAX_PASSWORD_LENGTH)
        generator = GeneratorDialog(self.window._clipboard, settings=settings)
        generator.show()
        self.app.processEvents()
        shown = generator.result

        def fits() -> bool:
            wrap = Qt.TextWordWrap if shown._by_words else Qt.TextWrapAnywhere
            rect = QFontMetrics(shown.font()).boundingRect(
                0, 0, shown.width(), 10_000, wrap, QLabel.text(shown))
            return rect.height() <= shown.height() and rect.width() <= shown.width()

        self.assertEqual(len(shown.text()), MAX_PASSWORD_LENGTH)
        self.assertTrue(fits())
        generator._copy()  # la valeur copiée est exacte (sans points de coupure)
        self.assertEqual(QGuiApplication.clipboard().text(), shown.text())
        self.assertNotIn("\u200b", shown.text())
        generator.passphrase_chip.click()
        generator.words_slider.setValue(MAX_PASSPHRASE_WORDS)
        generator.capitalize.setChecked(True)
        generator.add_number.setChecked(True)
        for index, (_label, separator) in enumerate(_SEPARATORS):
            generator.separator.setCurrentIndex(index)
            self.app.processEvents()
            self.assertTrue(fits(), repr(separator))
            if separator:
                self.assertEqual(len(shown.text().split(separator)), MAX_PASSPHRASE_WORDS)
        generator.close_now()

    def test_second_vault_and_switch(self):
        from app.services.settings import load_settings

        self._create_vault()
        self.window._on_vault_action("new")
        screen = self.window._create_screen
        self.assertIs(self.window._stack.currentWidget(), screen)
        self.assertTrue(screen.back.isVisibleTo(screen))
        other = secrets.token_urlsafe(16)
        screen.name.setText("Travail")
        screen.password.setText(other)
        screen.confirm.setText(other)
        screen._submit()
        self.assertEqual(self.window._session.vault.info.vault_name, "Travail")
        self.window._on_vault_action("switch")
        combo = self.window._unlock_screen.vault_combo
        self.assertEqual(sorted(combo.itemText(i) for i in range(combo.count())),
                         ["Test UI", "Travail"])
        self.assertEqual(combo.currentText(), "Travail")
        self.assertEqual(load_settings().last_vault_id, self.window._last_vault_id)

    def test_delete_current_vault(self):
        from PySide6.QtWidgets import QDialog

        from app.core.vault import list_vaults
        from app.ui import main_window

        self._create_vault()

        class FakeDialog:
            Accepted = QDialog.Accepted

            def __init__(inner, *args, **kwargs):
                inner.entered_password = self.master

            def exec(inner):
                return QDialog.Accepted

        with unittest.mock.patch.object(main_window, "DeleteVaultDialog", FakeDialog):
            self.window._delete_current_vault()
        self.assertEqual(list_vaults(), [])
        self.assertIsNone(self.window._session)
        self.assertIs(self.window._stack.currentWidget(), self.window._create_screen)


class TestBackupsPageUi(UiTestCase):
    def test_delete_one_then_all_backups(self):
        from app.services import backup
        from app.services.settings import backup_directory

        shell = self._create_vault()
        vault = shell.ctx.vault
        directory = backup_directory(self.window._settings)
        backup.create_backup(vault, directory)
        for _ in range(2):
            backup.create_backup(vault, directory, kind=backup.KIND_AUTO)
        page = shell.pages["backups"]
        shell.navigate("backups")
        self.assertEqual(len(page._infos), 3)
        self.assertTrue(page.delete_button.isVisibleTo(page))
        with self._confirm(False):
            page.delete_one(page._infos[0])
        self.assertEqual(len(backup.list_backups(directory, vault.vault_id)), 3)
        with self._confirm(True):
            page.delete_one(page._infos[0])
        self.assertEqual(len(page._infos), 2)
        with self._confirm(True):
            page.delete_all(None)
        self.assertEqual(backup.list_backups(directory, vault.vault_id), [])
        self.assertFalse(page.delete_button.isVisibleTo(page))


    def test_pdf_copy_from_backups_page(self):
        from pathlib import Path

        from PySide6.QtCore import QTimer

        from app.services import pdf_export
        from app.ui.transfer_dialogs import ExportDialog

        if not pdf_export.protection_available():
            self.skipTest("python3-pikepdf absent")
        shell = self._create_vault()
        self._add(shell, service_name="GitHub", password="secret-pdf")
        page = shell.pages["backups"]
        pdf_password = secrets.token_urlsafe(16)
        seen = {}

        def drive(protected: bool) -> None:
            dialog = next(d for d in dialogs_open() if isinstance(d, ExportDialog))
            seen["pdf"] = dialog.pdf.isChecked()
            seen["protected_by_default"] = dialog.protect_pdf.isChecked()
            if protected:
                seen["enabled"] = dialog.go.isEnabled()  # pas d'avertissement à accepter
                dialog.master.setText(self.master)
                dialog.export_password.setText(self.master)
                dialog.export_confirm.setText(self.master)
                dialog._export()
                seen["error"] = dialog.error.text()
                dialog.export_password.setText(pdf_password)
                dialog.export_confirm.setText(pdf_password)
            else:
                dialog.protect_pdf.setChecked(False)
                seen["warning"] = dialog.warning.text()
                seen["locked"] = not dialog.go.isEnabled()
                dialog.acknowledge.setChecked(True)
                dialog.master.setText(self.master)
            dialog._export()

        save = "app.ui.transfer_dialogs.QFileDialog.getSaveFileName"
        for protected in (True, False):
            target = Path(self._tmpdir.name) / f"copie-{protected}.pdf"
            with unittest.mock.patch(save, return_value=(str(target.with_suffix("")), "")):
                QTimer.singleShot(0, lambda p=protected: drive(p))
                page.export_pdf()
            self.assertTrue(target.read_bytes().startswith(b"%PDF-"))
        self.assertTrue(seen["pdf"] and seen["protected_by_default"] and seen["enabled"])
        self.assertIn("différent du mot de passe maître", seen["error"])
        self.assertTrue(seen["locked"])
        self.assertIn("sans aucune protection", seen["warning"])
        import pikepdf
        with self.assertRaises(pikepdf.PasswordError):
            pikepdf.open(Path(self._tmpdir.name) / "copie-True.pdf")
        pikepdf.open(Path(self._tmpdir.name) / "copie-False.pdf").close()

    def test_pdf_protection_disabled_when_dependency_missing(self):
        from app.services import pdf_export
        from app.ui.transfer_dialogs import ExportDialog

        shell = self._create_vault()
        with unittest.mock.patch.object(pdf_export, "pikepdf", None):
            dialog = ExportDialog(shell.ctx.entries, shell.ctx.vault, initial="pdf")
        dialog.show()
        self.app.processEvents()
        self.assertFalse(dialog.protect_pdf.isEnabled())
        self.assertFalse(dialog.protect_pdf.isChecked())
        self.assertTrue(dialog.protection_missing.isVisibleTo(dialog))
        self.assertIn("python3-pikepdf", dialog.protection_missing.text())
        self.assertFalse(dialog.go.isEnabled())  # PDF en clair : avertissement à accepter
        dialog.close_now()


class TestRecoveryKeyUi(UiTestCase):
    """Clé de récupération : affichage unique, abandon, mot de passe oublié, gestion."""

    def _key_dialog(self):
        from app.ui.recovery_dialogs import RecoveryKeyDialog

        found = [d for d in dialogs_open() if isinstance(d, RecoveryKeyDialog)]
        self.assertEqual(len(found), 1)
        return found[0]

    def _create_with_key(self) -> tuple:
        shell = self._create_vault(recovery=True)
        dialog = self._key_dialog()
        key = dialog._key
        self.assertRegex(key, r"^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$")
        self.assertFalse(dialog.done_button.isEnabled())  # confirmation exigée
        dialog.ack.setChecked(True)
        dialog.done_button.click()
        self.app.processEvents()
        self.assertTrue(shell.ctx.vault.has_recovery_key)
        return shell, key

    def test_key_shown_once_at_creation_then_forgotten_password_flow(self):
        from PySide6.QtCore import QTimer

        from app.core.vault import Vault
        from app.ui.recovery_dialogs import RecoverVaultDialog

        shell, key = self._create_with_key()
        self.assertFalse(shell.pages["security"].recovery_card.isVisibleTo(shell))
        self._add(shell, service_name="Banque", password="secret-de-test")
        self.window.lock()
        self.assertIs(self.window._stack.currentWidget(), self.window._unlock_screen)
        new_master = secrets.token_urlsafe(16)

        def fill() -> None:
            dialog = next(d for d in dialogs_open() if isinstance(d, RecoverVaultDialog))
            dialog.key.setText("0000-" + key[5:])  # erreur de saisie : refusée sans dérivation
            dialog.new.setText(new_master)
            dialog.confirm.setText(new_master)
            dialog._submit()
            self.assertIsNone(dialog.vault)
            self.assertTrue(dialog.error.isVisibleTo(dialog))
            dialog.key.setText(key.lower().replace("-", " "))
            dialog.new.setText(new_master)
            dialog.confirm.setText(new_master)
            dialog._submit()

        QTimer.singleShot(0, fill)
        self.window._unlock_screen.forgot.click()
        shell = self.window._shell
        self.assertIsNotNone(shell)
        renewed = self._key_dialog()
        new_key = renewed._key
        self.assertNotEqual(new_key, key)
        renewed.ack.setChecked(True)
        renewed.done_button.click()
        self.app.processEvents()
        self.assertEqual(shell.ctx.entries.list_entries()[0].service_name, "Banque")
        vault_id = shell.ctx.vault.vault_id
        self.window.lock()
        Vault.unlock(vault_id, new_master).close()
        Vault.recover(vault_id, new_key, secrets.token_urlsafe(16))[0].close()

    def test_recovery_key_saved_as_protected_pdf(self):
        from pathlib import Path

        from PySide6.QtCore import QTimer

        from app.services import pdf_export
        from app.ui.recovery_dialogs import RecoveryPdfDialog

        if not pdf_export.protection_available():
            self.skipTest("python3-pikepdf absent")
        import pikepdf

        self._create_vault(recovery=True)
        dialog = self._key_dialog()
        target = Path(self._tmpdir.name) / "ma-cle.pdf"
        pdf_password = "cheval-agrafe-lumiere-orbite-vanille"
        seen = {}

        def drive() -> None:
            pdf = next(d for d in dialogs_open() if isinstance(d, RecoveryPdfDialog))
            pdf.password.setText("faible")
            pdf.confirm.setText("faible")
            pdf._submit()
            seen["weak"] = pdf.error.text()
            pdf.password.setText(pdf_password)
            pdf.confirm.setText(pdf_password)
            pdf._submit()

        save = "app.ui.recovery_dialogs.QFileDialog.getSaveFileName"
        with unittest.mock.patch(save, return_value=(str(target.with_suffix("")), "")):
            QTimer.singleShot(0, drive)
            dialog.pdf_button.click()
        self.assertIn("caractères", seen["weak"])
        self.assertEqual(dialog.saved_pdf, target)
        self.assertIn("ma-cle.pdf", dialog.pdf_status.text())
        with self.assertRaises(pikepdf.PasswordError):
            pikepdf.open(target)
        pikepdf.open(target, password=pdf_password).close()
        dialog.ack.setChecked(True)
        dialog.done_button.click()

    def test_key_is_discarded_if_not_confirmed(self):
        from app.core.vault import vault_has_recovery_key

        shell = self._create_vault(recovery=True)
        vault_id = shell.ctx.vault.vault_id
        self.assertTrue(shell.ctx.vault.has_recovery_key)
        self._key_dialog()
        self.window.lock()  # verrouillage pendant l'affichage : la clé non notée disparaît
        self.assertFalse(vault_has_recovery_key(vault_id))
        self.assertEqual([d for d in dialogs_open()], [])

    def test_escape_asks_before_discarding(self):
        shell = self._create_vault(recovery=True)
        dialog = self._key_dialog()
        with self._confirm(False):
            dialog.reject()
        self.assertTrue(dialog.isVisible())
        self.assertTrue(shell.ctx.vault.has_recovery_key)
        with self._confirm(True):
            dialog.reject()
        self.app.processEvents()
        self.assertFalse(shell.ctx.vault.has_recovery_key)
        self.assertTrue(shell.pages["security"].recovery_card.isVisibleTo(
            shell.pages["security"]))

    def test_forgot_password_without_key_explains(self):
        self._create_vault()
        self.window.lock()
        with unittest.mock.patch("app.ui.dialogs.alert") as alert:
            self.window._unlock_screen.forgot.click()
        self.assertIn("n'a pas de clé", alert.call_args.args[2])

    def test_settings_create_replace_and_remove(self):
        shell = self._create_vault()
        settings = shell.pages["settings"]
        shell.navigate("settings")
        self.assertIn("Aucune clé", settings.recovery_state.text())
        self.assertFalse(settings.recovery_remove.isVisibleTo(settings))
        ask = "app.ui.recovery_dialogs._ask_master_password"
        with unittest.mock.patch(ask, return_value="mauvais-mot-de-passe"), \
                unittest.mock.patch("app.ui.dialogs.alert") as alert:
            settings.recovery_create.click()
        self.assertIn("incorrect", alert.call_args.args[2])
        self.assertFalse(shell.ctx.vault.has_recovery_key)
        with unittest.mock.patch(ask, return_value=self.master):
            settings.recovery_create.click()
        dialog = self._key_dialog()
        first = dialog._key
        dialog.ack.setChecked(True)
        dialog.done_button.click()
        self.app.processEvents()
        self.assertIn("Active", settings.recovery_state.text())
        self.assertEqual(settings.recovery_create.text(), "Remplacer…")
        with unittest.mock.patch(ask, return_value=self.master):
            settings.recovery_create.click()
        replaced = self._key_dialog()
        self.assertNotEqual(replaced._key, first)
        replaced.ack.setChecked(True)
        replaced.done_button.click()
        self.app.processEvents()
        with unittest.mock.patch(ask, return_value=self.master):
            settings.recovery_remove.click()
        self.assertFalse(shell.ctx.vault.has_recovery_key)
        self.assertIn("Aucune clé", settings.recovery_state.text())


def dialogs_open():
    from app.ui import dialogs

    return dialogs.open_dialogs()


class TestAnimatedMode(UiTestCase):
    """Animations activées : l'état réel n'est jamais retardé (règle de conception)."""

    def test_state_is_immediate_even_with_animations(self):
        from app.ui import effects

        shell = self._create_vault()
        effects.set_animations_enabled(True)
        self.window.show()
        a = self._add(shell, service_name="A")
        for key in ("vault", "security", "dashboard"):
            shell.navigate(key)
            self.assertIs(shell.stack.currentWidget(), shell.pages[key])
        with self._confirm(True):
            shell.navigate("vault")
            shell.vault_page.delete_entry(a)
            # La carte sort en animation, puis la suppression réelle a lieu.
            self.assertTrue(self._wait_until(lambda: shell.ctx.entries.trash_count() == 1, 3000))
        self.window.lock()
        self.assertIs(self.window._stack.currentWidget(), self.window._unlock_screen)
        self.assertIsNone(self.window._session)

    def test_generator_result_stays_in_place_when_slider_moves_fast(self):
        from PySide6.QtTest import QTest

        from app.ui import effects
        from app.ui.generator_dialog import GeneratorDialog

        effects.set_animations_enabled(True)
        generator = GeneratorDialog(self.window._clipboard, settings=self.window._settings)
        generator.show()
        QTest.qWait(500)  # fin de l'ouverture animée de la modale
        home = generator.result.pos()
        for value in range(20, 129, 4):  # chaque valeur relance l'animation d'entrée
            generator.length_slider.setValue(value)
            QTest.qWait(10)
        self.assertTrue(self._wait_until(
            lambda: generator.result.graphicsEffect() is None, 2000))
        self.assertEqual(generator.result.pos(), home)
        generator.close_now()
