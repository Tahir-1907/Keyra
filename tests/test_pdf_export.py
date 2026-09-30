"""PDF "paper copy" export: master password, content, escaping, permissions."""

import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from PySide6.QtWidgets import QApplication

from app.core.categories import CategoryService
from app.core.entries import Entry, EntryService
from app.core.exceptions import InvalidMasterPasswordPolicyError, WrongMasterPasswordError
from app.core.vault import Vault
from app.services import pdf_export
from tests.test_vault import VaultTestCase


def _text(path, password: str) -> str:
    """Text of an encrypted PDF (decrypted copy in memory: pdftotext cuts at 32 chars)."""
    import pikepdf

    plain = Path(tempfile.mkdtemp()) / "clair.pdf"
    try:
        with pikepdf.open(path, password=password) as document:
            document.save(plain)
        return subprocess.run(["pdftotext", str(plain), "-"], capture_output=True, text=True,
                              check=True).stdout
    finally:
        shutil.rmtree(plain.parent)


class TestPdfExport(VaultTestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        super().setUp()
        self.master = secrets.token_urlsafe(16)
        self.vault = Vault.create(self.vault_id, "Perso <b>", self.master)
        categories = CategoryService(self.vault)
        categories.ensure_builtin_categories()
        work = next(c.id for c in categories.list_categories() if c.name == "Work")
        self.entries = EntryService(self.vault)
        self.password = "Q7$kV9#pL2!xR8&mN4@zT6%wB1"
        self.entries.create_entry(Entry(service_name="GitHub", username="utilisateur.test",
                                        password=self.password, category_id=work,
                                        notes="<script>alert(1)</script>"))
        self.entries.create_entry(Entry(entry_type="card", service_name="Carte",
                                        extra={"card_number": "4970 1234 5678 9012",
                                               "cvv": "123"}))
        trashed = self.entries.create_entry(Entry(service_name="Supprimé",
                                                  password="mot-de-passe-supprime"))
        self.entries.delete_entry(trashed)  # to the Trash
        self.out = Path(tempfile.mkdtemp(dir=self._tmpdir.name)) / "copie.pdf"

    def tearDown(self):
        self.vault.close()
        super().tearDown()

    def test_requires_master_password_and_writes_nothing_otherwise(self):
        with self.assertRaises(WrongMasterPasswordError):
            pdf_export.export_pdf(self.entries, self.vault, "mauvais", self.out)
        self.assertFalse(self.out.exists())
        self.assertEqual(os.listdir(self.out.parent), [])  # no temporary file

    def test_pdf_written_privately_with_active_entries_only(self):
        count = pdf_export.export_pdf(self.entries, self.vault, self.master, self.out)
        self.assertEqual(count, 2)
        data = self.out.read_bytes()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertEqual(oct(self.out.stat().st_mode & 0o777), "0o600")
        self.assertEqual(os.listdir(self.out.parent), ["copie.pdf"])
        if shutil.which("pdftotext") is None:
            self.skipTest("pdftotext missing: PDF content not checked")
        text = subprocess.run(["pdftotext", str(self.out), "-"], capture_output=True,
                              text=True, check=True).stdout
        self.assertIn(self.password, text)
        self.assertIn("4970 1234 5678 9012", text)
        self.assertNotIn("Supprimé", text)
        self.assertNotIn("mot-de-passe-supprime", text)

    def test_html_escapes_every_value_and_excludes_trash(self):
        document, count = pdf_export.vault_html(self.entries, self.vault)
        self.assertEqual(count, 2)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("Perso &lt;b&gt;", document)
        self.assertNotIn("mot-de-passe-supprime", document)
        self.assertIn("Work", document)


class TestProtectedPdf(TestPdfExport):
    def setUp(self):
        super().setUp()
        if not pdf_export.protection_available():
            self.skipTest("python3-pikepdf missing")
        self.pdf_password = secrets.token_urlsafe(16)

    def test_protected_pdf_needs_its_password(self):
        import pikepdf

        pdf_export.export_pdf(self.entries, self.vault, self.master, self.out, self.pdf_password)
        self.assertEqual(oct(self.out.stat().st_mode & 0o777), "0o600")
        data = self.out.read_bytes()
        self.assertNotIn(self.password.encode(), data)
        with self.assertRaises(pikepdf.PasswordError):
            pikepdf.open(self.out)
        with self.assertRaises(pikepdf.PasswordError):
            pikepdf.open(self.out, password=self.master)
        with pikepdf.open(self.out, password=self.pdf_password) as document:
            self.assertTrue(document.is_encrypted)
            self.assertEqual(document.encryption.R, 6)  # AES-256 (PDF 2.0)
            self.assertEqual(document.encryption.stream_method.name, "aesv3")
        if shutil.which("pdftotext") is None:
            return
        locked = subprocess.run(["pdftotext", str(self.out), "-"], capture_output=True)
        self.assertNotEqual(locked.returncode, 0)
        self.assertIn(self.password, _text(self.out, self.pdf_password))

    def test_pdf_password_rules(self):
        with self.assertRaises(InvalidMasterPasswordPolicyError):
            pdf_export.export_pdf(self.entries, self.vault, self.master, self.out, "court")
        with self.assertRaises(InvalidMasterPasswordPolicyError) as ctx:
            pdf_export.export_pdf(self.entries, self.vault, self.master, self.out, self.master)
        self.assertIn("different from the master password", str(ctx.exception))
        self.assertFalse(self.out.exists())

    def test_missing_dependency_is_reported_not_bypassed(self):
        with mock.patch.object(pdf_export, "pikepdf", None):
            self.assertFalse(pdf_export.protection_available())
            with self.assertRaises(pdf_export.PdfProtectionUnavailable) as ctx:
                pdf_export.export_pdf(self.entries, self.vault, self.master, self.out,
                                      self.pdf_password)
        self.assertIn("python3-pikepdf", str(ctx.exception))
        self.assertFalse(self.out.exists())  # never a silent fallback to a plaintext PDF


class TestRecoveryKeyPdf(TestPdfExport):
    def setUp(self):
        super().setUp()
        if not pdf_export.protection_available():
            self.skipTest("python3-pikepdf missing")
        from app.core import recovery

        self.key = recovery.generate()
        self.pdf_password = "cheval-agrafe-lumiere-orbite-vanille"

    def test_recovery_pdf_is_encrypted_and_contains_the_key(self):
        import pikepdf

        pdf_export.export_recovery_pdf(self.key, "Perso", self.out, self.pdf_password,
                                       self.vault)
        self.assertEqual(oct(self.out.stat().st_mode & 0o777), "0o600")
        self.assertNotIn(self.key.encode(), self.out.read_bytes())
        with self.assertRaises(pikepdf.PasswordError):
            pikepdf.open(self.out)
        with pikepdf.open(self.out, password=self.pdf_password) as document:
            self.assertEqual(document.encryption.R, 6)
        if shutil.which("pdftotext") is None:
            return
        text = _text(self.out, self.pdf_password)
        compact = "".join(text.split())
        self.assertIn(self.key.replace("-", ""), compact.replace("-", ""))
        self.assertIn("Forgot password", " ".join(text.split()))
        self.assertNotIn("<br>", text)

    def test_long_passwords_open_and_too_long_is_refused(self):
        import pikepdf

        long_password = "phrase-de-passe-tres-longue-" * 4  # 112 characters
        pdf_export.export_recovery_pdf(self.key, "Perso", self.out, long_password)
        pikepdf.open(self.out, password=long_password).close()
        with self.assertRaises(InvalidMasterPasswordPolicyError):
            pdf_export.export_recovery_pdf(self.key, "Perso", self.out, "é" * 64)  # 128 bytes

    def test_recovery_pdf_password_rules(self):
        for weak in ("court", "motdepasse", "azertyuiop"):
            with self.assertRaises(InvalidMasterPasswordPolicyError):
                pdf_export.export_recovery_pdf(self.key, "Perso", self.out, weak, self.vault)
        with self.assertRaises(InvalidMasterPasswordPolicyError) as ctx:
            pdf_export.export_recovery_pdf(self.key, "Perso", self.out, self.key.lower(),
                                           self.vault)
        self.assertIn("cannot be the key", str(ctx.exception))
        strong_master = "tulipe-gravier-horizon-melodie-cactus"
        self.vault.change_master_password(self.master, strong_master)
        with self.assertRaises(InvalidMasterPasswordPolicyError) as ctx:
            pdf_export.export_recovery_pdf(self.key, "Perso", self.out, strong_master,
                                           self.vault)
        self.assertIn("master password", str(ctx.exception))
        with (mock.patch.object(pdf_export, "pikepdf", None),
              self.assertRaises(pdf_export.PdfProtectionUnavailable)):
            pdf_export.export_recovery_pdf(self.key, "Perso", self.out, self.pdf_password)
        self.assertFalse(self.out.exists())


class TestPdfRenderingInsideTheApp(VaultTestCase):
    """Rendering in real conditions: interface font defined in pixels."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_headings_stay_visible_with_pixel_sized_app_font(self):
        from PySide6.QtGui import QFont

        if shutil.which("pdftotext") is None:
            self.skipTest("pdftotext missing")
        previous = self.app.font()
        font = QFont("Inter")
        font.setPixelSize(13)  # like app.ui.theme.apply_theme
        self.app.setFont(font)
        try:
            data = pdf_export.render_pdf(
                "<html><head><style>" + pdf_export._CSS + "</style></head><body>"
                "<h1>Titreun</h1><h2>Rubriquedeux</h2><p>Corpstrois</p></body></html>", "t")
        finally:
            self.app.setFont(previous)
        folder = Path(tempfile.mkdtemp())
        try:
            pdf = folder / "t.pdf"
            pdf.write_bytes(data)
            boxes = subprocess.run(["pdftotext", "-bbox", str(pdf), "-"], capture_output=True,
                                   text=True, check=True).stdout
        finally:
            shutil.rmtree(folder)
        import re
        heights = {m.group(5): float(m.group(4)) - float(m.group(2)) for m in re.finditer(
            r'xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">(\w+)<', boxes)}
        self.assertGreater(heights["Titreun"], heights["Corpstrois"] * 1.4)
        self.assertGreater(heights["Rubriquedeux"], heights["Corpstrois"] * 1.1)
