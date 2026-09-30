"""Audit de sécurité du coffre (entièrement hors ligne).

Déchiffre les entrées une à une, en mémoire, et produit un rapport qui ne
contient **aucun secret** : uniquement des identifiants d'entrées, des noms
de services et le motif du problème. Les noms de services ne sont pas des
secrets (ils sont affichés dans l'interface), mais ils restent chiffrés au repos
(métadonnées v4) : le rapport n'existe qu'en mémoire et n'est jamais écrit.
Dans la corbeille, seules les entrées aux métadonnées illisibles sont signalées.

Contrôles effectués :
* mots de passe faibles (score ≤ 1, voir app.core.strength) ;
* mots de passe réutilisés entre plusieurs entrées ;
* entrées sans mot de passe (types qui en attendent un) ;
* mots de passe inchangés depuis plus de `OLD_PASSWORD_DAYS` jours ;
* cartes bancaires expirées ;
* entrées illisibles (champ chiffré altéré).

Les entrées de la corbeille ne sont pas auditées. Non couvert : la
vérification de fuites en ligne (contraire au principe « hors ligne »).
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
    KIND_UNREADABLE: "Entrées illisibles (altérées)",
    KIND_REUSED: "Mots de passe réutilisés",
    KIND_WEAK: "Mots de passe faibles",
    KIND_EMPTY: "Entrées sans mot de passe",
    KIND_OLD: "Mots de passe de plus d'un an",
    KIND_EXPIRED_CARD: "Cartes expirées",
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
    score: int = 100  # 0-100 : part des entrées sans problème

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
    # Une carte est valable jusqu'au dernier jour du mois indiqué.
    return (year, month) < (today.year, today.month)


def _age_in_days(iso: str, today: date) -> int | None:
    try:
        return (today - datetime.fromisoformat(iso).astimezone().date()).days
    except ValueError:
        return None


def run_audit(service: EntryService, today: date | None = None) -> AuditReport:
    today = today or datetime.now().astimezone().date()  # date locale de l'utilisateur
    report = AuditReport()
    # Les mots de passe sont regroupés par empreinte HMAC avec une clé
    # éphémère propre à cet audit : aucun mot de passe en clair ne sert de clé.
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
                             "Un champ chiffré est corrompu ou a été altéré.")
            )
            entries_with_issue.add(summary.id)
            continue

        spec = ENTRY_TYPES[entry.entry_type]
        if spec.uses_password:
            if not entry.password:
                report.findings.append(
                    AuditFinding(KIND_EMPTY, summary.id, summary.service_name,
                                 f"Aucun {spec.password_label.lower()} renseigné.")
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
                                     f"Inchangé depuis {age // 30} mois.")
                    )
                    entries_with_issue.add(summary.id)
                digest = hmac.new(reuse_key, entry.password.encode("utf-8"),
                                  hashlib.sha256).digest()
                groups.setdefault(digest, []).append((summary.id, summary.service_name))

        if entry.entry_type == "card" and _card_expired(entry.extra.get("expiry", ""), today):
            report.findings.append(
                AuditFinding(KIND_EXPIRED_CARD, summary.id, summary.service_name,
                             f"Expirée ({entry.extra.get('expiry', '').strip()}).")
            )
            entries_with_issue.add(summary.id)

    # Métadonnées altérées : l'entrée n'apparaît plus dans la liste, elle est signalée ici.
    for entry_id in service.unreadable_entries():
        report.checked_entries += 1
        report.findings.append(
            AuditFinding(KIND_UNREADABLE, entry_id, f"Entrée n° {entry_id}",
                         "Ses informations chiffrées sont corrompues ou ont été altérées.")
        )
        entries_with_issue.add(entry_id)

    for members in groups.values():
        if len(members) < 2:
            continue
        for entry_id, name in members:
            others = ", ".join(n for i, n in members if i != entry_id)
            report.findings.append(
                AuditFinding(KIND_REUSED, entry_id, name, f"Identique à : {others}")
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
