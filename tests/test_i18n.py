"""Interface language: catalogs, detection, fallback, settings, live switch, vault neutrality.

The language is an application setting (settings.json). These tests also prove
that changing it never touches a vault: same file bytes, same schema and rows,
same backup and export formats.
"""

import hashlib
import json
import os
import string
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from app import i18n
from app.i18n import catalog, detector
from tests.test_fixtures import logical_dump
from tests.test_ui import QApplication, UiTestCase

REFERENCE_KEYS = set(catalog.messages("en_US"))
FULL_CATALOGS = [loc for loc in catalog.LOCALES if "@parent" not in catalog.load(loc)]
VARIANTS = [loc for loc in catalog.LOCALES if "@parent" in catalog.load(loc)]


def _fields(text: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(text) if f is not None}


class LanguageTestCase(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en_US")


# --- Normalization, detection, fallback ------------------------------------------------


class TestNormalization(unittest.TestCase):
    def test_common_spellings(self):
        cases = {
            "fr_FR.UTF-8": ("fr", "FR"), "fr-FR": ("fr", "FR"), "French_France": ("fr", "FR"),
            "fr_FR@euro": ("fr", "FR"), "de_CH.utf8": ("de", "CH"), "en": ("en", None),
            "English_United States.1252": ("en", "US"), "zh-Hans-CN": ("zh", "CN"),
            "es-419": ("es", "419"), "lb_LU.UTF-8": ("lb", "LU"), "ja-JP": ("ja", "JP"),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(detector.normalize(raw), expected)

    def test_no_preference(self):
        for raw in ("", None, "C", "POSIX", "C.UTF-8", "  ", "123"):
            with self.subTest(raw=raw):
                self.assertIsNone(detector.normalize(raw))


class TestResolution(unittest.TestCase):
    def test_exact_locales(self):
        cases = {
            "fr_FR.UTF-8": "fr_FR", "en_US.UTF-8": "en_US", "en_GB.UTF-8": "en_GB",
            "de_DE.UTF-8": "de_DE", "de_CH.UTF-8": "de_CH", "fr_CH.UTF-8": "fr_CH",
            "it_CH.UTF-8": "it_CH", "fr_BE.UTF-8": "fr_BE", "nl_BE.UTF-8": "nl_BE",
            "de_BE.UTF-8": "de_BE", "fr_LU.UTF-8": "fr_LU", "de_LU.UTF-8": "de_LU",
            "lb_LU.UTF-8": "lb_LU", "ja_JP.UTF-8": "ja_JP", "tr_TR.UTF-8": "tr_TR",
            "es_ES.UTF-8": "es_ES", "it_IT.UTF-8": "it_IT",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(detector.resolve([raw]), expected)

    def test_every_supported_locale_is_detected_as_itself(self):
        for locale in catalog.LOCALES:
            with self.subTest(locale=locale):
                self.assertEqual(detector.resolve([locale.replace("_", "-")]), locale)

    def test_language_fallback(self):
        cases = {
            "fr_CA": "fr_FR", "de_AT": "de_DE", "en_AU": "en_GB", "en_CA": "en_US",
            "en_IE": "en_GB", "en_NZ": "en_GB", "en_IN": "en_GB", "en": "en_US",
            "es_MX": "es_ES", "tr_CY": "tr_TR", "it_SM": "it_IT", "nl_NL": "nl_BE",
            "lb": "lb_LU", "ja": "ja_JP", "fr": "fr_FR", "de_LI": "de_DE",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(detector.resolve([raw]), expected)

    def test_unsupported_language_falls_back_to_en_us(self):
        for raw in ("pt_BR", "ko_KR", "zh_CN", "ru_RU", "C", "", "xx_YY"):
            with self.subTest(raw=raw):
                self.assertEqual(detector.resolve([raw]), "en_US")
        self.assertEqual(detector.resolve([]), "en_US")

    def test_first_supported_preference_wins(self):
        self.assertEqual(detector.resolve(["pt-BR", "de-CH", "en-US"]), "de_CH")
        self.assertEqual(detector.resolve(["C", "ja_JP.UTF-8"]), "ja_JP")

    def test_detect_uses_system_preferences(self):
        with unittest.mock.patch.object(detector, "system_preferences",
                                        return_value=["it-CH", "en-US"]):
            self.assertEqual(detector.detect(), "it_CH")

    def test_system_preferences_are_strings(self):
        preferences = detector.system_preferences()
        self.assertIsInstance(preferences, list)
        self.assertTrue(all(isinstance(p, str) for p in preferences))


# --- Catalogs ------------------------------------------------------------------------------


class TestCatalogs(LanguageTestCase):
    def test_every_locale_loads(self):
        self.assertEqual(len(catalog.LOCALES), 17)
        for locale in catalog.LOCALES:
            with self.subTest(locale=locale):
                self.assertTrue((catalog.LOCALES_DIR / f"{locale}.json").is_file())
                self.assertEqual(set(catalog.messages(locale)), REFERENCE_KEYS)

    def test_full_catalogs_have_every_key(self):
        self.assertEqual(sorted(FULL_CATALOGS), sorted(
            ["en_US", "fr_FR", "tr_TR", "de_DE", "es_ES", "it_IT", "lb_LU", "nl_BE", "ja_JP"]))
        for locale in FULL_CATALOGS:
            data = catalog.load(locale)
            with self.subTest(locale=locale):
                self.assertEqual(set(data) - {"@parent"}, REFERENCE_KEYS)
                self.assertTrue(all(value.strip() for value in data.values()))

    def test_variants_only_override_known_keys(self):
        for locale in VARIANTS:
            data = catalog.load(locale)
            with self.subTest(locale=locale):
                self.assertIn(data["@parent"], FULL_CATALOGS)
                self.assertLessEqual(set(data) - {"@parent"}, REFERENCE_KEYS)

    def test_placeholders_are_kept(self):
        reference = catalog.messages("en_US")
        for locale in catalog.LOCALES:
            messages = catalog.messages(locale)
            for key, text in messages.items():
                with self.subTest(locale=locale, key=key):
                    self.assertEqual(_fields(text), _fields(reference[key]))
                    text.format(**{name: "X" for name in _fields(text)})

    def test_plural_forms_come_in_pairs(self):
        ones = {k[:-4] for k in REFERENCE_KEYS if k.endswith(".one")}
        others = {k[:-6] for k in REFERENCE_KEYS if k.endswith(".other")}
        self.assertEqual(ones, others)

    def test_native_language_names(self):
        self.assertEqual(catalog.LOCALES["ja_JP"], "日本語")
        self.assertEqual(catalog.LOCALES["lb_LU"], "Lëtzebuergesch")
        self.assertEqual(catalog.LOCALES["tr_TR"], "Türkçe")
        self.assertEqual(list(catalog.LOCALES)[:2], ["en_US", "en_GB"])
        for name in catalog.LOCALES.values():
            self.assertNotIn(name, ("Swiss", "Belgian", "Luxembourg"))

    def test_technical_terms_are_never_translated(self):
        reference = catalog.messages("en_US")
        for locale in catalog.LOCALES:
            messages = catalog.messages(locale)
            for key, text in reference.items():
                for term in ("Keyra", "AES-256-GCM", "Argon2id", ".mcfbak", ".mcfexport",
                             "sudo apt install", "python3-pikepdf"):
                    if term in text:
                        with self.subTest(locale=locale, key=key, term=term):
                            self.assertIn(term, messages[key])


class TestTranslationLookup(LanguageTestCase):
    def test_current_language(self):
        self.assertEqual(i18n.set_language("fr_FR"), "fr_FR")
        self.assertEqual(i18n.current(), "fr_FR")
        self.assertEqual(i18n.language(), "fr")
        self.assertEqual(i18n.tr("common.cancel"), "Annuler")
        self.assertEqual(i18n.set_language("ja_JP"), "ja_JP")
        self.assertEqual(i18n.tr("common.cancel"), "キャンセル")
        self.assertEqual(i18n.set_language("xx_YY"), "en_US")  # unknown: reference

    def test_missing_key_never_crashes(self):
        i18n.set_language("de_DE")
        self.assertEqual(i18n.tr("no.such.key"), "no.such.key")
        self.assertEqual(i18n.tr("no.such.key", count=2), "no.such.key")

    def test_missing_translation_falls_back_to_parent_then_english(self):
        with unittest.mock.patch.dict(catalog.load("fr_FR"), clear=False):
            del catalog.load("fr_FR")["common.cancel"]
            i18n.set_language("fr_CH")
            self.assertEqual(i18n.tr("common.cancel"), "Cancel")
        catalog.load.cache_clear()
        i18n.set_language("fr_CH")
        self.assertEqual(i18n.tr("common.cancel"), "Annuler")  # parent fr_FR

    def test_broken_translation_formats_in_english(self):
        i18n.set_language("fr_FR")
        with unittest.mock.patch.dict(i18n._messages, {"vault.count.other": "{nombre} entrées"}):
            self.assertEqual(i18n.tr_n("vault.count", 3), "3 entries")

    def test_plural_rules(self):
        expectations = {
            "en_US": ("1 entry", "0 entries", "2 entries"),
            "fr_FR": ("1 entrée", "0 entrée", "2 entrées"),
            "de_DE": ("1 Eintrag", "0 Einträge", "2 Einträge"),
            "ja_JP": ("1 件", "0 件", "2 件"),
        }
        for locale, (one, zero, two) in expectations.items():
            i18n.set_language(locale)
            with self.subTest(locale=locale):
                self.assertEqual(i18n.tr_n("vault.count", 1), one)
                self.assertEqual(i18n.tr_n("vault.count", 0), zero)
                self.assertEqual(i18n.tr_n("vault.count", 2), two)

    def test_us_and_uk_english_differ_where_it_matters(self):
        i18n.set_language("en_US")
        us = (i18n.tr("vault.filter.favorites"), i18n.tr("dashboard.analyze"),
              i18n.tr("pdf.uncategorized"))
        i18n.set_language("en_GB")
        gb = (i18n.tr("vault.filter.favorites"), i18n.tr("dashboard.analyze"),
              i18n.tr("pdf.uncategorized"))
        self.assertEqual(us, ("Favorites", "Analyze security", "Uncategorized"))
        self.assertEqual(gb, ("Favourites", "Analyse security", "Uncategorised"))
        # No artificial difference: technical terms are shared.
        self.assertEqual(i18n.tr("common.master_password"), "Master password")

    def test_regional_variants(self):
        german = catalog.messages("de_DE")
        swiss = catalog.messages("de_CH")
        self.assertIn("ß", german["common.close"])
        self.assertTrue(all("ß" not in text for text in swiss.values()))
        self.assertEqual(swiss["common.close"], "Schliessen")
        self.assertEqual(catalog.messages("de_LU"), german)
        self.assertEqual(catalog.messages("de_BE"), german)
        for variant in ("fr_CH", "fr_BE", "fr_LU"):
            self.assertEqual(catalog.messages(variant), catalog.messages("fr_FR"))
        self.assertEqual(catalog.messages("it_CH"), catalog.messages("it_IT"))
        self.assertEqual(catalog.chain("fr_CH"), ["fr_CH", "fr_FR", "en_US"])

    def test_builtin_categories_follow_the_language(self):
        from app.core.builtin_categories import builtin_key_for_name, builtin_name

        i18n.set_language("ja_JP")
        self.assertEqual(builtin_name("work"), "仕事")
        i18n.set_language("fr_FR")
        self.assertEqual(builtin_name("work"), "Travail")
        # Any language, English and 1.x French all designate the same key (import).
        for name in ("Work", "Travail", "Arbeit", "仕事", "Aarbecht", "İş"):
            self.assertEqual(builtin_key_for_name(name), "work")
        self.assertIsNone(builtin_key_for_name("Jeux vidéo"))

    def test_system_setting_resolves_through_detection(self):
        with unittest.mock.patch.object(detector, "system_preferences",
                                        return_value=["nl-BE"]):
            self.assertEqual(i18n.resolve_setting(i18n.SYSTEM), "nl_BE")
            self.assertEqual(i18n.resolve_setting("ja_JP"), "ja_JP")  # manual choice kept
            self.assertEqual(i18n.resolve_setting("xx_YY"), "nl_BE")  # invalid: system


# --- Settings (settings.json) ------------------------------------------------------------


class TestLanguageSetting(LanguageTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name

    def tearDown(self):
        super().tearDown()
        if self._old is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old
        self._tmp.cleanup()

    def test_default_is_system(self):
        from app.services.settings import Settings, load_settings

        self.assertEqual(Settings().language, i18n.SYSTEM)
        self.assertEqual(load_settings().language, i18n.SYSTEM)

    def test_manual_choice_is_saved_and_read_back(self):
        from app.services.settings import load_settings, save_settings, settings_path

        settings = load_settings()
        settings.language = "ja_JP"
        save_settings(settings)
        self.assertEqual(json.loads(settings_path().read_text())["language"], "ja_JP")
        self.assertEqual(load_settings().language, "ja_JP")
        settings.language = i18n.SYSTEM
        save_settings(settings)
        self.assertEqual(load_settings().language, i18n.SYSTEM)

    def test_invalid_value_resets_to_system(self):
        from app.services.settings import load_settings, settings_path

        for value in ("xx_YY", "fr", 42, None, ["fr_FR"]):
            with self.subTest(value=value):
                settings_path().write_text(json.dumps({"language": value}))
                self.assertEqual(load_settings().language, i18n.SYSTEM)

    def test_compatibility_with_versions_without_language(self):
        """1.7.0-rc1 shares settings.json, ignores "language" and drops it when it saves:
        the next start simply follows the system language again. Keys unknown to this
        version (written by a newer one) are kept when it saves."""
        from app.services.settings import load_settings, save_settings, settings_path

        path = settings_path()
        path.write_text(json.dumps({"language": "fr_FR", "future_option": [1, 2]}))
        settings = load_settings()
        self.assertEqual(settings.language, "fr_FR")
        save_settings(settings)
        saved = json.loads(path.read_text())
        self.assertEqual(saved["future_option"], [1, 2])
        self.assertEqual(saved["language"], "fr_FR")
        # What an older version writes back: its own fields only.
        older = {k: v for k, v in saved.items() if k not in ("language", "future_option")}
        path.write_text(json.dumps(older))
        self.assertEqual(load_settings().language, i18n.SYSTEM)

    def test_language_is_not_a_vault_field(self):
        from app.database import database

        schema = Path(database.__file__).read_text(encoding="utf-8")
        self.assertNotIn("language", schema)


# --- Interface: live switch, Unicode, layout -----------------------------------------------


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class TestLanguageSwitchUi(UiTestCase):
    def _switch(self, value: str) -> None:
        from dataclasses import replace

        from PySide6.QtWidgets import QApplication as App

        self.window.update_settings(replace(self.window._settings, language=value))
        App.processEvents()  # the views are rebuilt right after the settings signal
        self.app.processEvents()

    def test_first_start_follows_the_system_and_records_system(self):
        from app.services.settings import settings_path

        self.assertEqual(i18n.current(), "en_US")
        self.assertEqual(json.loads(settings_path().read_text())["language"], i18n.SYSTEM)
        self.assertEqual(self.window._unlock_screen.subtitle.text()
                         if self.window._stack.currentWidget() is self.window._unlock_screen
                         else self.window._create_screen.button.text(), "Create vault")

    def test_french_system_starts_in_french(self):
        from app.ui.main_window import MainWindow

        with unittest.mock.patch.object(detector, "system_preferences",
                                        return_value=["fr-FR"]):
            window = MainWindow()
        self.addCleanup(window.deleteLater)
        self.addCleanup(window.close)
        self.assertEqual(i18n.current(), "fr_FR")
        self.assertEqual(window._create_screen.button.text(), "Créer le coffre")

    def test_manual_switch_rebuilds_the_views_and_keeps_the_session(self):
        shell = self._create_vault()
        self._add(shell, service_name="GitHub", category_id=None)
        vault = self.window._session.vault
        shell.navigate("settings")

        self._switch("fr_FR")
        shell = self.window._shell
        self.assertIs(self.window._session.vault, vault)  # same open vault
        self.assertEqual(shell.title.text(), "Paramètres")
        self.assertEqual(shell.nav["vault"].text_label.text(), "Coffre")
        self.assertEqual(self.window._menus.actions["lock"].text(), "Verrouiller")
        self.assertEqual(shell.pages["settings"].language.currentData(), "fr_FR")
        names = {c.name for c in shell.ctx.categories.list_categories()}
        self.assertIn("Travail", names)  # built-in category, new language

        self._switch("ja_JP")
        shell = self.window._shell
        self.assertEqual(shell.title.text(), "設定")
        self.assertIn("仕事", {c.name for c in shell.ctx.categories.list_categories()})
        shell.navigate("vault")
        self.assertEqual(shell.vault_page.count_label.text(), "1 件")

        self._switch(i18n.SYSTEM)  # the test "system" is en-US
        self.assertEqual(i18n.current(), "en_US")
        self.assertEqual(self.window._shell.title.text(), "Settings")
        self.assertEqual(self.window._settings.language, i18n.SYSTEM)

    def test_language_list_in_settings(self):
        shell = self._create_vault()
        combo = shell.pages["settings"].language
        values = [combo.itemData(i) for i in range(combo.count())]
        texts = [combo.itemText(i) for i in range(combo.count())]
        self.assertEqual(values, [i18n.SYSTEM, *catalog.LOCALES])
        self.assertTrue(texts[0].startswith("System default"))
        self.assertIn("日本語", texts)
        self.assertIn("Lëtzebuergesch", texts)
        self.assertIn("Deutsch (Schweiz)", texts)

    def test_lock_and_unlock_after_a_switch(self):
        self._create_vault()
        self._switch("de_DE")
        self.window.lock()
        self.app.processEvents()
        self.assertIsNone(self.window._shell)
        self.assertEqual(self.window._unlock_screen.subtitle.text(), "Ihr Tresor ist gesperrt")
        self.assertIsNotNone(self._unlock())

    def test_every_language_builds_every_view(self):
        """Each language builds every view at the minimum window width (long German,
        compact Japanese): texts come from the catalog (no raw key, no replacement
        character). Visual review of the layouts: README, Languages section."""
        from PySide6.QtWidgets import QLabel

        from app.ui import theme

        shell = self._create_vault()
        self._add(shell, service_name="Exemple é è ê ë à ç ù ş ğ ı İ ä ö ü ß ñ 日本語")
        self.window.resize(theme.WINDOW_MIN_WIDTH, theme.WINDOW_MIN_HEIGHT)
        for locale in catalog.LOCALES:
            with self.subTest(locale=locale):
                self._switch(locale)
                shell = self.window._shell
                for key in shell.pages:
                    shell.navigate(key)
                    self.app.processEvents()
                    self.assertEqual(shell.title.text(), shell.pages[key].title)
                    for label in shell.pages[key].findChildren(QLabel):
                        self.assertNotIn("�", label.text())
                        self.assertFalse(label.text().startswith(("page.", "settings.")))

    def test_unicode_is_displayed_with_real_glyphs(self):
        from PySide6.QtGui import QFontDatabase, QTextLayout

        from app.ui import theme

        samples = ["é è ê ë à ç ù", "ş ğ ı İ ç", "ä ö ü ß", "ñ á í ó ú", "Lëtzebuergesch",
                   "日本語", catalog.messages("ja_JP")["lock.subtitle"],
                   catalog.messages("tr_TR")["action.go_trash"]]
        has_japanese = bool(QFontDatabase.families(QFontDatabase.WritingSystem.Japanese))
        for text in samples:
            if not has_japanese and any("　" <= c <= "鿿" for c in text):
                continue  # no Japanese font on this machine: nothing to measure
            with self.subTest(text=text):
                layout = QTextLayout(text, theme.font(14))
                layout.beginLayout()
                layout.createLine()
                layout.endLayout()
                glyphs = [i for run in layout.glyphRuns() for i in run.glyphIndexes()]
                self.assertTrue(glyphs)
                self.assertNotIn(0, glyphs)  # 0 = missing glyph (empty box)


# --- Vault neutrality -----------------------------------------------------------------------


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class TestLanguageNeverTouchesTheVault(UiTestCase):
    def _switch(self, value: str) -> None:
        from dataclasses import replace

        self.window.update_settings(replace(self.window._settings, language=value))
        self.app.processEvents()
        self.app.processEvents()

    def _db(self) -> Path:
        from app.utils.paths import vault_path

        return vault_path(self.vault_id) / "vault.db"

    def _prepare_vault(self):
        from app.core.entries import Entry

        shell = self._create_vault("Neutral")
        self.vault_id = self.window._session.vault.vault_id
        work = next(c.id for c in shell.ctx.categories.list_categories() if c.name == "Work")
        shell.ctx.entries.create_entry(Entry(service_name="Mail", password="Pw-1!aZ",
                                             category_id=work, tags=("perso",)))
        shell.ctx.entries.create_entry(Entry(service_name="Bank", password="Pw-2!aZ"))
        self.window.lock()
        self.app.processEvents()

    def test_sha256_identical_after_several_language_changes(self):
        """Required: fingerprint, open and use the vault, change the language several
        times, lock, fingerprint again: strictly identical (no data was modified)."""
        self._prepare_vault()
        before_sha, before_dump = _sha256(self._db()), logical_dump(self._db())
        backups_before = sorted(Path(self._tmpdir.name).rglob("*.mcfbak"))

        shell = self._unlock()
        for locale in ("fr_FR", "ja_JP", "de_CH", "tr_TR", "lb_LU", i18n.SYSTEM):
            self._switch(locale)
            shell = self.window._shell
            for key in ("dashboard", "vault", "security", "history", "trash", "backups"):
                shell.navigate(key)  # reading only
                self.app.processEvents()
        self.window.lock()
        self.app.processEvents()

        self.assertEqual(_sha256(self._db()), before_sha)
        self.assertEqual(logical_dump(self._db()), before_dump)
        # Unchanged vault: no automatic backup was produced by the language changes.
        self.assertEqual(sorted(Path(self._tmpdir.name).rglob("*.mcfbak")), backups_before)

    def test_schema_data_backup_and_export_formats_do_not_depend_on_language(self):
        from app.services import backup, import_export

        self._prepare_vault()
        schema_before = logical_dump(self._db())["__schema__"]
        headers, exports = {}, {}
        for locale in ("en_US", "ja_JP", "fr_FR"):
            i18n.set_language(locale)
            shell = self._unlock()
            vault = self.window._session.vault
            path = backup.create_backup(vault, directory=Path(self._tmpdir.name) / locale)
            info = backup.read_backup_info(path)
            data = path.read_bytes()
            self.assertTrue(data.startswith(backup.MAGIC))
            self.assertEqual(info.kind, backup.KIND_MANUAL)  # persisted value, never translated
            header_length = int.from_bytes(data[8:12], "big")
            headers[locale] = sorted(json.loads(data[12:12 + header_length]))
            target = Path(self._tmpdir.name) / f"{locale}.mcfexport"
            import_export.export_encrypted(shell.ctx.entries, vault, self.master,
                                           "export-passphrase", target)
            exports[locale] = sorted(json.loads(target.read_text()))
            csv_path = Path(self._tmpdir.name) / f"{locale}.csv"
            import_export.export_csv(shell.ctx.entries, vault, self.master, csv_path)
            self.assertEqual(csv_path.read_text(encoding="utf-8").splitlines()[0],
                             ",".join(import_export.CSV_COLUMNS))
            preview = import_export.parse_encrypted_export(target, "export-passphrase")
            self.assertEqual(preview.format_key, "moncoffre_encrypted")
            self.window.lock()
            self.app.processEvents()
        self.assertEqual(headers["en_US"], headers["ja_JP"])
        self.assertEqual(headers["en_US"], headers["fr_FR"])
        self.assertEqual(exports["en_US"], exports["ja_JP"])
        self.assertEqual(logical_dump(self._db())["__schema__"], schema_before)

    def test_export_in_one_language_imports_into_builtin_categories_in_another(self):
        from app.core.entries import EntryFilter
        from app.services import import_export

        self._prepare_vault()
        i18n.set_language("ja_JP")
        shell = self._unlock()
        target = Path(self._tmpdir.name) / "ja.mcfexport"
        import_export.export_encrypted(shell.ctx.entries, self.window._session.vault,
                                       self.master, "export-passphrase", target)
        self.window.lock()
        self.app.processEvents()
        i18n.set_language("en_US")
        other = self._create_vault_second()
        preview = import_export.parse_encrypted_export(target, "export-passphrase")
        result = import_export.apply_import(other.ctx.entries, other.ctx.categories, preview)
        self.assertEqual(result.imported, 2)
        self.assertEqual(result.categories_created, [])  # "仕事" is the built-in "Work"
        work = next(c.id for c in other.ctx.categories.list_categories() if c.name == "Work")
        self.assertEqual([s.service_name for s in other.ctx.entries.list_entries(
            EntryFilter(category_id=work))], ["Mail"])

    def _create_vault_second(self):
        self.window._show_create_screen(False)
        return self._create_vault("Second")
