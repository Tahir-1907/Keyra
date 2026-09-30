"""E2: tags in the interface, `#tag` search, search debounce.

Core (EntryService) on throwaway vaults, Qt interface in "offscreen" mode.
The tag rules remain those of app.core.metadata (normalize_tags, tag_key).
"""

import sys
import unittest.mock
from pathlib import Path

from app.core.entries import Entry, EntryFilter, tag_search_query
from app.core.exceptions import VaultLockedError
from app.core.metadata import MAX_TAGS, normalize_tags
from app.database.repositories import EntryRepository
from app.services import import_export
from tests.test_entries import EntryTestCase
from tests.test_ui import UiTestCase


class TagSearchTestCase(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.linux = self.entries.create_entry(Entry(
            service_name="Serveur maison", password="a", tags=["Linux", "perso"],
            category_id=self.category_id("Personal")))
        self.ecole = self.entries.create_entry(Entry(
            service_name="ENT", password="b", tags=["École"], is_favorite=True))
        self.primaire = self.entries.create_entry(Entry(
            service_name="Mairie", password="c", tags=["Écoles primaires", "Linux"]))
        self.none = self.entries.create_entry(Entry(service_name="Banque", password="d"))

    def ids(self, text="", **kwargs):
        return sorted(s.id for s in self.entries.list_entries(EntryFilter(text=text, **kwargs)))


class TestHashTagSearch(TagSearchTestCase):
    def test_exact_match_ignoring_case_and_accents(self):
        self.assertEqual(self.ids("#linux"), sorted([self.linux, self.primaire]))
        self.assertEqual(self.ids("#LINUX"), sorted([self.linux, self.primaire]))
        self.assertEqual(self.ids("#ecole"), [self.ecole])
        self.assertEqual(self.ids("#ÉCOLE"), [self.ecole])

    def test_no_prefix_or_substring_match(self):
        self.assertEqual(self.ids("#lin"), [])
        self.assertEqual(self.ids("#ecoles"), [])
        self.assertEqual(self.ids("#linuxx"), [])

    def test_tag_with_spaces_needs_quotes(self):
        self.assertEqual(self.ids('#"ecoles primaires"'), [self.primaire])
        self.assertEqual(self.ids('#"  Écoles   primaires "'), [self.primaire])

    def test_several_tags_are_combined_with_and(self):
        self.assertEqual(self.ids("#linux #perso"), [self.linux])
        self.assertEqual(self.ids('#linux #"écoles primaires"'), [self.primaire])
        self.assertEqual(self.ids("#linux #ecole"), [])

    def test_combined_with_text_and_filters(self):
        self.assertEqual(self.ids("#linux mairie"), [self.primaire])
        self.assertEqual(self.ids("mairie #linux"), [self.primaire])
        self.assertEqual(self.ids("#linux", category_id=self.category_id("Personal")),
                         [self.linux])
        self.assertEqual(self.ids("#ecole", favorites_only=True), [self.ecole])
        self.assertEqual(self.ids("#linux", favorites_only=True), [])

    def test_trash(self):
        self.entries.delete_entry(self.linux)
        self.assertEqual(self.ids("#linux"), [self.primaire])
        self.assertEqual(self.ids("#linux", in_trash=True), [self.linux])

    def test_lone_hash_is_ignored(self):
        everything = sorted([self.linux, self.ecole, self.primaire, self.none])
        self.assertEqual(self.ids("#"), everything)
        self.assertEqual(self.ids("  #   "), everything)
        self.assertEqual(self.ids("# mairie"), [self.primaire])

    def test_plain_text_also_finds_tags(self):
        self.assertEqual(self.ids("prim"), [self.primaire])
        self.assertEqual(self.ids("PERSO"), [self.linux])
        self.assertEqual(self.ids("ecole"), sorted([self.ecole, self.primaire]))

    def test_hash_inside_a_word_is_plain_text(self):
        other = self.entries.create_entry(Entry(service_name="Cours C#", password="e"))
        self.assertEqual(self.ids("c#"), [other])

    def test_query_built_for_a_tag_finds_exactly_its_entries(self):
        odd = self.entries.create_entry(Entry(
            service_name="Bizarre", password="f", tags=['a"b', 'x "y', "Ça va", '"cité"']))
        for tag, expected in (("Linux", [self.linux, self.primaire]), ("École", [self.ecole]),
                              ("Écoles primaires", [self.primaire]), ('a"b', [odd]),
                              ('x "y', [odd]), ("Ça va", [odd]), ('"cité"', [odd])):
            with self.subTest(tag=tag):
                self.assertEqual(self.ids(tag_search_query(tag)), sorted(expected))
        self.assertEqual(tag_search_query("Linux"), "#Linux")
        self.assertEqual(tag_search_query("Écoles primaires"), '#"Écoles primaires"')


class TestAllTags(TagSearchTestCase):
    def test_active_entries_deduplicated_and_sorted(self):
        self.assertEqual(self.entries.all_tags(),
                         ("École", "Écoles primaires", "Linux", "perso"))

    def test_most_frequent_form_is_kept(self):
        for name in ("A", "B"):
            self.entries.create_entry(Entry(service_name=name, tags=["LINUX"]))
        self.entries.create_entry(Entry(service_name="C", tags=["LINUX"]))
        self.assertIn("LINUX", self.entries.all_tags())
        self.assertNotIn("Linux", self.entries.all_tags())

    def test_trash_and_unreadable_entries_are_ignored(self):
        self.entries.delete_entry(self.ecole)
        blob = bytearray(EntryRepository(self.vault.connection).get_metadata_blob(self.linux))
        blob[-1] ^= 1
        with self.vault.connection:
            self.vault.connection.execute("UPDATE entries SET metadata_enc = ? WHERE id = ?",
                                          (bytes(blob), self.linux))
        self.vault.metadata.invalidate()
        self.assertEqual(self.entries.all_tags(), ("Écoles primaires", "Linux"))

    def test_follows_every_change(self):
        tags = self.entries.all_tags
        new = self.entries.create_entry(Entry(service_name="N", password="p", tags=["neuf"]))
        self.assertIn("neuf", tags())
        entry = self.entries.get_entry(new)
        entry.tags = ("renommé",)
        self.entries.update_entry(entry)
        self.assertIn("renommé", tags())
        self.assertNotIn("neuf", tags())
        self.entries.delete_entry(new)
        self.assertNotIn("renommé", tags())
        self.entries.restore_entry(new)
        self.assertIn("renommé", tags())
        version = self.entries.list_history(new)[0]
        self.entries.restore_version(version.id)
        self.assertIn("neuf", tags())
        self.assertNotIn("renommé", tags())
        self.entries.delete_entry(new)
        self.entries.delete_permanently(new)
        self.assertNotIn("neuf", tags())

    def test_locked_vault(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.entries.all_tags()


class TestImportDroppedTags(EntryTestCase):
    def test_dropped_tags_are_counted(self):
        path = Path(self._tmpdir.name) / "tags.csv"
        path.write_text(
            "type,name,url,username,email,password,notes,category,favorite,extra,tags\n"
            'login,A,,,,p,,,0,,"Linux, linux, ' + "x" * 33 + '"\n'
            'login,B,,,,p,,,0,,"ok"\n', encoding="utf-8")
        preview = import_export.parse_csv(path)
        self.assertEqual([i.dropped_tags for i in preview.items], [2, 0])
        self.assertEqual(preview.dropped_tags, 2)
        result = import_export.apply_import(self.entries, self.categories, preview)
        self.assertEqual(result.imported, 2)


# --- Interface ------------------------------------------------------------------------------


class TagUiTestCase(UiTestCase):
    def setUp(self):
        super().setUp()
        self.shell = self._create_vault()
        self.entries = self.shell.ctx.entries

    def editor(self, tags=()):
        from app.ui.tag_editor import TagEditor

        editor = TagEditor()
        self.addCleanup(editor.deleteLater)
        editor.set_tags(tags)
        return editor

    def type_tag(self, editor, text):
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest

        editor.input.setText(text)
        QTest.keyClick(editor.input, Qt.Key_Return)


class TestTagEditor(TagUiTestCase):
    def test_add_with_enter_and_comma(self):
        editor = self.editor()
        self.type_tag(editor, "  #Linux ")
        editor.input.setText("perso, École")
        editor.input.insert(",")
        self.assertEqual(editor.tags(), ("Linux", "perso", "École"))
        self.assertEqual(editor.input.text(), "")
        self.assertEqual([c.text() for c in editor.chip_buttons()], ["Linux", "perso", "École"])

    def test_invalid_tags_are_refused_with_a_message(self):
        editor = self.editor(["Linux"])
        for bad in ("linux", "LÍNUX", "x" * 33, "a​b"):
            with self.subTest(tag=bad):
                self.type_tag(editor, bad)
                self.assertEqual(editor.tags(), ("Linux",))
                self.assertTrue(editor.error_text())
                self.assertEqual(editor.input.text(), bad)  # fixable, nothing is lost
        self.type_tag(editor, "ok")
        self.assertEqual(editor.error_text(), "")

    def test_maximum_count(self):
        editor = self.editor([f"t{i}" for i in range(MAX_TAGS)])
        self.type_tag(editor, "un de trop")
        self.assertEqual(len(editor.tags()), MAX_TAGS)
        self.assertIn(str(MAX_TAGS), editor.error_text())

    def test_rules_come_from_normalize_tags(self):
        editor = self.editor()
        with unittest.mock.patch("app.ui.tag_editor.normalize_tags",
                                 wraps=normalize_tags) as rules:
            self.type_tag(editor, "Linux")
        rules.assert_called()

    def test_remove_a_chip(self):
        editor = self.editor(["a", "b", "c"])
        editor.chip_buttons()[1].click()
        self.assertEqual(editor.tags(), ("a", "c"))

    def test_enter_on_empty_input_is_not_consumed(self):
        editor = self.editor()
        self.type_tag(editor, "")
        self.assertEqual(editor.tags(), ())

    def test_pending_text_is_part_of_the_result(self):
        editor = self.editor(["a"])
        editor.input.setText("b")
        self.assertEqual(editor.pending_tags(), ["a", "b"])

    def test_suggestions(self):
        editor = self.editor()
        editor.set_suggestions(("Linux", "École"))
        self.assertEqual(editor.completer_model_strings(), ["Linux", "École"])


class TestEntryDialogTags(TagUiTestCase):
    def dialog(self, entry=None):
        from app.ui.entry_dialog import EntryDialog

        return EntryDialog(self.entries, self.shell.ctx.categories.list_categories(),
                           self.window._clipboard, entry=entry, parent=self.shell)

    def test_create_with_tags(self):
        self.entries.create_entry(Entry(service_name="Autre", tags=["Existant"]))
        dialog = self.dialog()
        self.assertIn("Existant", dialog.tags.completer_model_strings())
        dialog.name.setText("Nouveau")
        self.type_tag(dialog.tags, "Linux")
        dialog.tags.input.setText("en cours")  # not yet confirmed with Enter
        dialog._save()
        got = self.entries.get_entry(dialog.saved_entry_id)
        self.assertEqual(got.tags, ("Linux", "en cours"))

    def test_edit_loads_changes_and_removes_tags(self):
        entry_id = self.entries.create_entry(Entry(service_name="A", tags=["a", "b"]))
        dialog = self.dialog(self.entries.get_entry(entry_id))
        self.assertEqual(dialog.tags.tags(), ("a", "b"))
        dialog.tags.chip_buttons()[0].click()
        self.type_tag(dialog.tags, "c")
        dialog._save()
        self.assertEqual(self.entries.get_entry(entry_id).tags, ("b", "c"))
        self.assertEqual(self.entries.history_count(entry_id), 1)

    def test_invalid_pending_tag_blocks_saving(self):
        entry_id = self.entries.create_entry(Entry(service_name="A", tags=["Linux"]))
        dialog = self.dialog(self.entries.get_entry(entry_id))
        dialog.tags.input.setText("linux")
        dialog._save()
        self.assertTrue(dialog.error.isVisibleTo(dialog))
        self.assertIsNone(dialog.saved_entry_id)
        self.assertEqual(self.entries.history_count(entry_id), 0)


class TestTagDisplay(TagUiTestCase):
    def test_badges_in_detail_and_click_searches(self):
        a = self._add(self.shell, service_name="A", tags=["Linux", "Écoles primaires"])
        b = self._add(self.shell, service_name="B", tags=["Écoles primaires"])
        self._add(self.shell, service_name="C")
        self.shell.navigate("vault")
        page = self.shell.vault_page
        page.list.select_entry(a)
        badges = page.detail.tag_widgets()
        self.assertEqual([w.text() for w in badges], ["Linux", "Écoles primaires"])
        badges[1].click()
        self.assertEqual(self.shell.search.text(), '#"Écoles primaires"')
        self.assertFalse(page.has_pending_search())  # applied immediately
        self.assertEqual(sorted(s.id for s in page.list.model().rows()), sorted([a, b]))
        page.list.select_entry(a)
        page.detail.tag_widgets()[0].click()
        self.assertEqual([s.id for s in page.list.model().rows()], [a])

    def test_no_badge_row_without_tags(self):
        a = self._add(self.shell, service_name="A")
        self.shell.navigate("vault")
        self.shell.vault_page.list.select_entry(a)
        self.assertEqual(self.shell.vault_page.detail.tag_widgets(), [])

    def test_trash_and_history_show_tags_without_searching(self):
        from app.ui.history_dialog import HistoryDialog

        a = self._add(self.shell, service_name="A", tags=["ancien"])
        entry = self.entries.get_entry(a)
        entry.tags = ("nouveau",)
        self.entries.update_entry(entry)
        dialog = HistoryDialog(self.entries, a, self.window._clipboard, {})
        badges = dialog.detail.tag_widgets()
        self.assertEqual([w.text() for w in badges], ["ancien"])
        self.assertFalse(hasattr(badges[0], "click"))  # plain label
        dialog.close_now()
        self.entries.delete_entry(a)
        self.shell.navigate("trash")
        trash = self.shell.pages["trash"]
        trash.list.select_entry(a)
        self.assertEqual([w.text() for w in trash.detail.tag_widgets()], ["nouveau"])
        self.assertEqual(self.shell.search.text(), "")


class TestSearchDebounce(TagUiTestCase):
    def setUp(self):
        super().setUp()
        self.a = self._add(self.shell, service_name="Alpha", tags=["Linux"])
        self._add(self.shell, service_name="Beta")
        self.shell.navigate("vault")
        self.page = self.shell.vault_page
        # Each read of the list records whether the vault was locked at that moment.
        self.locked_reads = []
        vault, real = self.shell.ctx.vault, self.entries.list_entries

        def spy(*args, **kwargs):
            self.locked_reads.append(vault.is_locked)
            return real(*args, **kwargs)

        self.calls = unittest.mock.patch.object(self.entries, "list_entries", side_effect=spy)
        self.spy = self.calls.start()
        self.addCleanup(self.calls.stop)
        # Refreshes of the vault list (the overview reads the entries too).
        refresh = unittest.mock.patch.object(self.page, "refresh", wraps=self.page.refresh)
        self.refreshes = refresh.start()
        self.addCleanup(refresh.stop)

    def rows(self):
        return [s.id for s in self.page.list.model().rows()]

    def test_fast_typing_refreshes_once(self):
        for text in ("a", "al", "alp", "alph", "alpha"):
            self.shell.search.setText(text)
        self.assertEqual(self.refreshes.call_count, 0)
        self.assertTrue(self.page.has_pending_search())
        self.assertTrue(self._wait_until(lambda: not self.page.has_pending_search()))
        self.assertEqual(self.refreshes.call_count, 1)
        self.assertEqual(self.rows(), [self.a])

    def test_clearing_is_immediate(self):
        self.shell.search.setText("alpha")
        self._wait_until(lambda: not self.page.has_pending_search())
        self.shell.search.clear()
        self.assertFalse(self.page.has_pending_search())
        self.assertEqual(len(self.rows()), 2)

    def test_enter_applies_now(self):
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest

        self.shell.search.setText("#linux")
        QTest.keyClick(self.shell.search, Qt.Key_Return)
        self.assertFalse(self.page.has_pending_search())
        self.assertEqual(self.rows(), [self.a])

    def run_timer_out(self):
        from PySide6.QtTest import QTest

        from app.ui.pages import vault as vault_page

        QTest.qWait(vault_page.SEARCH_DEBOUNCE_MS * 3)
        self.app.processEvents()

    def test_pending_search_then_lock(self):
        errors = []
        with unittest.mock.patch.object(sys, "excepthook",
                                        lambda *exc: errors.append(exc)):
            self.shell.search.setText("alpha")
            self.assertTrue(self.page.has_pending_search())
            vault = self.shell.ctx.vault
            self.window.lock()
            self.assertTrue(vault.is_locked)
            before = self.spy.call_count
            self.run_timer_out()
        self.assertEqual(errors, [])
        self.assertEqual(self.spy.call_count, before)
        self.assertNotIn(True, self.locked_reads)
        self.assertIsNone(self.window._shell)

    def test_pending_search_then_animated_lock(self):
        from app.ui import effects

        effects.set_animations_enabled(True)
        self.addCleanup(effects.set_animations_enabled, False)
        errors = []
        with unittest.mock.patch.object(sys, "excepthook",
                                        lambda *exc: errors.append(exc)):
            self.shell.search.setText("alpha")
            self.window.lock()  # deferred teardown (animated transition)
            self.assertTrue(self._wait_until(lambda: self.window._shell is None))
            self.run_timer_out()
        self.assertEqual(errors, [])
        self.assertNotIn(True, self.locked_reads)

    def test_timer_firing_on_a_locked_vault_does_nothing(self):
        errors = []
        with unittest.mock.patch.object(sys, "excepthook",
                                        lambda *exc: errors.append(exc)):
            self.shell.search.setText("alpha")
            self.shell.ctx.vault.lock()  # key erased without going through the interface
            self.run_timer_out()
        self.assertEqual(errors, [])
        self.assertNotIn(True, self.locked_reads)
        self.assertFalse(self.page.has_pending_search())

    def test_unlock_after_pending_search_starts_clean(self):
        self.shell.search.setText("alpha")
        self.window.lock()
        self.run_timer_out()
        shell = self._unlock()
        self.assertEqual(shell.search.text(), "")
        shell.navigate("vault")
        self.assertEqual(len(shell.vault_page.list.model().rows()), 2)


class TestImportPreviewShowsDroppedTags(UiTestCase):
    def test_subtitle_mentions_dropped_tags(self):
        from PySide6.QtWidgets import QLabel

        from app.ui.transfer_dialogs import ImportPreviewDialog

        preview = import_export.ImportPreview("moncoffre", [
            import_export.ImportItem(Entry(service_name="A"), dropped_tags=3)])
        dialog = ImportPreviewDialog(preview)
        self.addCleanup(dialog.deleteLater)
        texts = " ".join(label.text() for label in dialog.findChildren(QLabel))
        self.assertIn("3 invalid or duplicate tag(s)", texts)

