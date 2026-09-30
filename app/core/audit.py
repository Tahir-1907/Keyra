"""Vault security audit (fully offline).

Decrypts entries one at a time, in memory, and produces a report that contains
**no secret**: only entry identifiers, service names and the reason for the
finding. Service names are not secrets (they are shown in the interface), but
they stay encrypted at rest (v4 metadata): the report exists only in memory
and is never written. In the Trash, only entries with unreadable metadata are
reported.

Checks performed:
* weak passwords (score ≤ 1, see app.core.strength);
* passwords reused across several entries;
* entries without a password (types that expect one);
* passwords unchanged for more than `OLD_PASSWORD_DAYS` days;
* expired payment cards;
* unreadable entries (tampered encrypted field).

Entries in the Trash are not audited. Not covered: online breach checks
(contrary to the "offline" principle).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import date, datetime

from app.core.entries import ENTRY_TYPES, EntryService
from app.core.exceptions import EntryDecryptionError
from app.core.strength import estimate_strength
from app.utils.logging import get_logger

WEAK_SCORE_MAX = 1
OLD_PASSWORD_DAYS = 365
_EXPIRY_PATTERN = re.compile(r"^\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*$")

KIND_WEAK = "weak"
KIND_REUSED = "reused"
KIND_EMPTY = "empty"
KIND_OLD = "old"
KIND_EXPIRED_CARD = "expired_card"
KIND_UNREADABLE = "unreadable"

KIND_LABELS = {
    KIND_UNREADABLE: "Unreadable entries (tampered)",
    KIND_REUSED: "Reused passwords",
    KIND_WEAK: "Weak passwords",
    KIND_EMPTY: "Entries without a password",
    KIND_OLD: "Passwords older than one year",
    KIND_EXPIRED_CARD: "Expired cards",
}


@dataclass(frozen=True, slots=True)
class AuditFinding:
    kind: str
    entry_id: int
    service_name: str
    detail: str


@dataclass(slots=True)
class AuditReport:
    findings: list[AuditFinding] = field(default_factory=list)
    checked_entries: int = 0
    passwords_checked: int = 0
    score: int = 100  # 0-100: share of entries without any finding

    def by_kind(self, kind: str) -> list[AuditFinding]:
        return [f for f in self.findings if f.kind == kind]


def _card_expired(expiry: str, today: date) -> bool:
    match = _EXPIRY_PATTERN.match(expiry)
    if not match:
        return False
    month, year = int(match.group(1)), int(match.group(2))
    if not 1 <= month <= 12:
        return False
    if year < 100:
        year += 2000
    # A card is valid until the last day of the month shown.
    return (year, month) < (today.year, today.month)


def _age_in_days(iso: str, today: date) -> int | None:
    try:
        return (today - datetime.fromisoformat(iso).astimezone().date()).days
    except ValueError:
        return None


def run_audit(service: EntryService, today: date | None = None) -> AuditReport:
    today = today or datetime.now().astimezone().date()  # the user's local date
    report = AuditReport()
    # Passwords are grouped by HMAC fingerprint, with an ephemeral key
    # specific to this audit: no plaintext password is ever used as a key.
    reuse_key = secrets.token_bytes(32)
    groups: dict[bytes, list[tuple[int, str]]] = {}
    entries_with_issue: set[int] = set()

    summaries = service.list_entries()
    report.checked_entries = len(summaries)
    for summary in summaries:
        try:
            entry = service.get_entry(summary.id)
        except EntryDecryptionError:
            report.findings.append(
                AuditFinding(KIND_UNREADABLE, summary.id, summary.service_name,
                             "An encrypted field is corrupted or has been tampered with.")
            )
            entries_with_issue.add(summary.id)
            continue

        spec = ENTRY_TYPES[entry.entry_type]
        if spec.uses_password:
            if not entry.password:
                report.findings.append(
                    AuditFinding(KIND_EMPTY, summary.id, summary.service_name,
                                 f"No {spec.password_label.lower()} set.")
                )
                entries_with_issue.add(summary.id)
            else:
                report.passwords_checked += 1
                strength = estimate_strength(entry.password)
                if strength.score <= WEAK_SCORE_MAX:
                    report.findings.append(
                        AuditFinding(KIND_WEAK, summary.id, summary.service_name,
                                     f"{strength.label} (~{strength.entropy_bits:.0f} bits)")
                    )
                    entries_with_issue.add(summary.id)
                age = _age_in_days(entry.password_changed_at, today)
                if age is not None and age > OLD_PASSWORD_DAYS:
                    report.findings.append(
                        AuditFinding(KIND_OLD, summary.id, summary.service_name,
                                     f"Unchanged for {age // 30} months.")
                    )
                    entries_with_issue.add(summary.id)
                digest = hmac.new(reuse_key, entry.password.encode("utf-8"),
                                  hashlib.sha256).digest()
                groups.setdefault(digest, []).append((summary.id, summary.service_name))

        if entry.entry_type == "card" and _card_expired(entry.extra.get("expiry", ""), today):
            report.findings.append(
                AuditFinding(KIND_EXPIRED_CARD, summary.id, summary.service_name,
                             f"Expired ({entry.extra.get('expiry', '').strip()}).")
            )
            entries_with_issue.add(summary.id)

    # Tampered metadata: the entry no longer appears in the list, so it is reported here.
    for entry_id in service.unreadable_entries():
        report.checked_entries += 1
        report.findings.append(
            AuditFinding(KIND_UNREADABLE, entry_id, f"Entry #{entry_id}",
                         "Its encrypted data is corrupted or has been tampered with.")
        )
        entries_with_issue.add(entry_id)

    for members in groups.values():
        if len(members) < 2:
            continue
        for entry_id, name in members:
            others = ", ".join(n for i, n in members if i != entry_id)
            report.findings.append(
                AuditFinding(KIND_REUSED, entry_id, name, f"Same as: {others}")
            )
            entries_with_issue.add(entry_id)

    if report.checked_entries:
        healthy = report.checked_entries - len(entries_with_issue)
        report.score = round(100 * healthy / report.checked_entries)
    get_logger().info(
        "Security audit run: %d entries, %d findings",
        report.checked_entries, len(report.findings),
    )
    return report
