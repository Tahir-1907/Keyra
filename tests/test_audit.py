from datetime import date

from app.core.audit import (
    KIND_EMPTY,
    KIND_EXPIRED_CARD,
    KIND_REUSED,
    KIND_UNREADABLE,
    KIND_WEAK,
    run_audit,
)
from app.core.entries import Entry
from app.core.generator import generate_password
from tests.test_entries import EntryTestCase


class TestAudit(EntryTestCase):
    def ids(self, report, kind):
        return sorted(f.entry_id for f in report.by_kind(kind))

    def test_empty_vault_is_healthy(self):
        report = run_audit(self.entries)
        self.assertEqual((report.score, report.findings), (100, []))

    def test_detects_all_problem_kinds(self):
        shared = generate_password().value
        strong = self.entries.create_entry(
            Entry(service_name="Fort", password=generate_password().value)
        )
        weak = self.entries.create_entry(Entry(service_name="Faible", password="azerty123"))
        reuse_a = self.entries.create_entry(Entry(service_name="A", password=shared))
        reuse_b = self.entries.create_entry(Entry(service_name="B", password=shared))
        empty = self.entries.create_entry(Entry(service_name="Vide"))
        note = self.entries.create_entry(
            Entry(service_name="Note", entry_type="secure_note", notes="x")
        )
        card_old = self.entries.create_entry(Entry(service_name="Vieille carte", entry_type="card",
                                                   extra={"expiry": "01/24"}))
        card_ok = self.entries.create_entry(Entry(service_name="Carte", entry_type="card",
                                                  extra={"expiry": "09/26"}))

        report = run_audit(self.entries, today=date(2026, 9, 26))
        self.assertEqual(self.ids(report, KIND_WEAK), [weak])
        self.assertEqual(self.ids(report, KIND_REUSED), sorted([reuse_a, reuse_b]))
        self.assertEqual(self.ids(report, KIND_EMPTY), [empty])
        self.assertEqual(self.ids(report, KIND_EXPIRED_CARD), [card_old])
        flagged = {f.entry_id for f in report.findings}
        for healthy in (strong, note, card_ok):
            self.assertNotIn(healthy, flagged)
        self.assertEqual(report.checked_entries, 8)
        self.assertEqual(report.score, round(100 * 3 / 8))

    def test_report_never_contains_passwords(self):
        secret = generate_password().value
        self.entries.create_entry(Entry(service_name="A", password=secret))
        self.entries.create_entry(Entry(service_name="B", password=secret))
        self.entries.create_entry(Entry(service_name="C", password="azerty123"))
        report = run_audit(self.entries)
        dump = repr(report) + "".join(f.detail + f.service_name for f in report.findings)
        self.assertNotIn(secret, dump)
        self.assertNotIn("azerty123", dump)

    def test_unreadable_entry_is_reported_not_raised(self):
        a = self.entries.create_entry(Entry(service_name="A", password="x" * 20))
        conn = self.vault.connection
        with conn:
            conn.execute("UPDATE entries SET password_enc = X'0100' WHERE id = ?", (a,))
        report = run_audit(self.entries)
        self.assertEqual(self.ids(report, KIND_UNREADABLE), [a])
