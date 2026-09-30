"""Export PDF « à imprimer » : tous les comptes du coffre, mots de passe EN CLAIR.

Même régime que l'export CSV non chiffré (voir import_export) :
* le mot de passe maître est redemandé (une session ouverte ne suffit pas) ;
* le PDF est construit entièrement en mémoire (QPdfWriter sur un QBuffer :
  aucun fichier temporaire en clair), puis écrit d'un bloc en 0600 ;
* la corbeille et l'historique ne sont jamais inclus.

Protection par mot de passe (facultative, recommandée) : chiffrement PDF
AES-256 (révision 6, PDF 2.0) par pikepdf / qpdf (paquet Debian
python3-pikepdf), en mémoire. Le mot de passe du PDF doit différer du mot de
passe maître : un PDF chiffré se teste bien plus vite qu'un coffre protégé
par Argon2id. Sans protection, le fichier est en clair : à imprimer puis
supprimer.

Rendu : QTextDocument (HTML simple, valeurs échappées) paginé par Qt, avec
numéros de page. Aucune dépendance en plus de QtGui.
"""

from __future__ import annotations

import html
import io
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QMarginsF
from PySide6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument

from app.core import recovery
from app.core.categories import CategoryService
from app.core.entries import DEFAULT_ENTRY_TYPE, ENTRY_TYPES, Entry, EntryService
from app.core.exceptions import InvalidMasterPasswordPolicyError, VaultError
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault
from app.services.import_export import EXPORT_TEMP_PREFIX, _require_master_password
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger

try:  # dépendance du paquet Debian ; absente => protection indisponible, signalée
    import pikepdf
except ImportError:  # pragma: no cover - dépend de l'installation
    pikepdf = None

PDF_SUFFIX = ".pdf"
MISSING_DEPENDENCY = ("La protection par mot de passe nécessite le paquet Debian "
                      "python3-pikepdf (sudo apt install python3-pikepdf).")


class PdfProtectionUnavailable(VaultError):
    """pikepdf (python3-pikepdf) n'est pas installé."""


def protection_available() -> bool:
    return pikepdf is not None


# Norme PDF (révision 6) : au-delà, le mot de passe est tronqué et le fichier
# pourrait ne plus s'ouvrir avec le mot de passe tapé.
MAX_PDF_PASSWORD_BYTES = 127


def check_pdf_password_length(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            f"Le mot de passe du PDF doit contenir au moins {MIN_MASTER_PASSWORD_LENGTH} "
            "caractères.")
    if len(password.encode("utf-8")) > MAX_PDF_PASSWORD_BYTES:
        raise InvalidMasterPasswordPolicyError(
            "Mot de passe trop long pour un PDF (127 octets au maximum).")


def protect(pdf: bytes, password: str) -> bytes:
    """Chiffre le PDF en AES-256 (R6) ; le mot de passe est exigé à l'ouverture.

    Le résultat est rouvert avec le mot de passe avant d'être rendu : un PDF
    qui ne s'ouvrirait pas n'est jamais écrit.
    """
    if pikepdf is None:
        raise PdfProtectionUnavailable(MISSING_DEPENDENCY)
    check_pdf_password_length(password)
    output = io.BytesIO()
    with pikepdf.open(io.BytesIO(pdf)) as document:
        document.save(output, encryption=pikepdf.Encryption(
            user=password, owner=password, R=6, aes=True, metadata=True))
    data = output.getvalue()
    try:
        with pikepdf.open(io.BytesIO(data), password=password) as check:
            if not check.is_encrypted or len(check.pages) == 0:
                raise VaultError("Le PDF chiffré est invalide.")
    except pikepdf.PdfError as exc:
        raise VaultError("Le PDF chiffré n'a pas pu être vérifié ; rien n'a été écrit.") from exc
    return data
_NO_CATEGORY = "Sans catégorie"

_CSS = """
body { font-family: 'Inter', 'DejaVu Sans', 'Liberation Sans', sans-serif; font-size: 10pt;
       color: #111827; }
h1 { font-size: 18pt; margin: 0; }
h2 { font-size: 13pt; margin-top: 18pt; margin-bottom: 4pt; color: #047857;
     border-bottom: 1px solid #10B981; }
.meta { color: #4B5563; font-size: 9pt; }
.warning { background: #FEF3C7; color: #92400E; padding: 6pt; font-size: 9pt; }
td.name { font-size: 11pt; font-weight: 600; }
.type { color: #6B7280; font-size: 8.5pt; font-weight: 400; }
td.label { color: #4B5563; vertical-align: top; }
td.value { vertical-align: top; }
.secret { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 10pt; }
"""


def _cell(value: str, secret: bool = False) -> str:
    text = html.escape(value).replace("\n", "<br>")
    return f'<span class="secret">{text}</span>' if secret else text


def _rows(entry: Entry) -> list[tuple[str, str, bool]]:
    """(libellé, valeur, secret) des champs non vides, dans l'ordre de l'interface."""
    spec = ENTRY_TYPES.get(entry.entry_type) or ENTRY_TYPES[DEFAULT_ENTRY_TYPE]
    rows: list[tuple[str, str, bool]] = []
    if spec.uses_url:
        rows.append(("Adresse (URL)", entry.url, False))
    if spec.uses_username:
        rows.append(("Identifiant", entry.username, True))
    if spec.uses_email:
        rows.append(("E-mail", entry.email, False))
    if spec.uses_password:
        rows.append((spec.password_label, entry.password, True))
    for field in spec.extra_fields:
        rows.append((field.label, entry.extra.get(field.key, ""), field.secret))
    rows.append(("Notes", entry.notes, False))
    return [(label, value, secret) for label, value, secret in rows if value.strip()]


def build_html(vault_name: str, entries: list[Entry], category_names: dict[int, str],
               generated_at: datetime | None = None) -> str:
    """Document HTML (toutes les valeurs sont échappées)."""
    generated_at = generated_at or datetime.now().astimezone()
    groups: dict[str, list[Entry]] = {}
    for entry in entries:
        name = category_names.get(entry.category_id, "") if entry.category_id else ""
        groups.setdefault(name or _NO_CATEGORY, []).append(entry)
    parts = [
        f"<html><head><style>{_CSS}</style></head><body>",
        f"<h1>Mon Coffre-Fort — {html.escape(vault_name)}</h1>",
        f'<p class="meta">{len(entries)} compte{"s" if len(entries) > 1 else ""} · '
        f"document généré le {generated_at:%d/%m/%Y à %H:%M}</p>",
        '<p class="warning"><b>Document confidentiel.</b> Il contient vos mots de passe EN '
        "CLAIR. Conservez-le sous clé, loin de l'ordinateur ; détruisez-le (broyeur) quand il "
        "ne sert plus, et supprimez le fichier PDF après impression.<br>Un mot de passe long "
        "peut continuer à la ligne suivante : aucun caractère (tiret, espace) n'est ajouté à "
        "la coupure.</p>",
    ]
    ordered = sorted(groups, key=lambda g: (g == _NO_CATEGORY, g.casefold()))
    for group in ordered:
        parts.append(f"<h2>{html.escape(group)}</h2>")
        # Un tableau par catégorie, colonnes de largeur fixe (Qt ignore la largeur CSS
        # des cellules) ; chaque compte commence par un bandeau grisé.
        parts.append('<table cellspacing="0" cellpadding="3" width="100%">')
        for entry in sorted(groups[group], key=lambda e: e.service_name.casefold()):
            spec = ENTRY_TYPES.get(entry.entry_type) or ENTRY_TYPES[DEFAULT_ENTRY_TYPE]
            favorite = " ★" if entry.is_favorite else ""
            parts.append(f'<tr><td class="name" colspan="2" bgcolor="#EEF2F6">'
                         f"{html.escape(entry.service_name)}{favorite} "
                         f'<span class="type">· {html.escape(spec.label)}</span></td></tr>')
            for label, value, secret in _rows(entry):
                parts.append(f'<tr><td class="label" width="30%">{html.escape(label)}</td>'
                             f'<td class="value" width="70%">{_cell(value, secret)}</td></tr>')
            parts.append('<tr><td colspan="2" height="6"></td></tr>')
        parts.append("</table>")
    if not entries:
        parts.append("<p>Ce coffre ne contient aucun compte.</p>")
    parts.append("</body></html>")
    return "".join(parts)


def render_pdf(document_html: str, title: str) -> bytes:
    """PDF A4 en mémoire (nécessite une QGuiApplication, comme toute l'interface)."""
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    writer = QPdfWriter(buffer)
    writer.setTitle(title)
    writer.setCreator("Mon Coffre-Fort")
    # Marges de Qt (2 cm) ajoutées par QTextDocument.print_, avec numéros de page.
    writer.setPageLayout(QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait,
                                     QMarginsF(0, 0, 0, 0), QPageLayout.Millimeter))
    document = QTextDocument()
    # Police propre au document, en POINTS : sinon il hérite de celle de l'interface,
    # définie en pixels (taille en points = -1), et les titres h1/h2 — calculés à
    # partir de la taille en points — deviennent invisibles.
    base = QFont(["Inter", "DejaVu Sans", "Liberation Sans"])
    base.setPointSizeF(10)
    document.setDefaultFont(base)
    document.setHtml(document_html)
    document.print_(writer)
    del writer  # termine le PDF (écrit la fin du fichier dans le tampon)
    buffer.close()
    document.clear()
    return bytes(data)


def export_pdf(service: EntryService, vault: Vault, master_password: str,
               destination: Path, pdf_password: str | None = None) -> int:
    """Écrit le PDF (0600) et retourne le nombre de comptes. Mot de passe maître exigé.

    `pdf_password` : PDF chiffré (AES-256) ; None : PDF en clair.
    """
    _require_master_password(vault, master_password)
    if pdf_password is not None:
        if pikepdf is None:
            raise PdfProtectionUnavailable(MISSING_DEPENDENCY)
        check_pdf_password_length(pdf_password)
        if vault.verify_master_password(pdf_password, log_failure=False):
            raise InvalidMasterPasswordPolicyError(
                "Choisissez un mot de passe différent du mot de passe maître : un PDF "
                "protégé résiste bien moins longtemps qu'un coffre aux tentatives.")
    document_html, count = vault_html(service, vault)
    data = render_pdf(document_html, f"Mon Coffre-Fort — {vault.info.vault_name}")
    if pdf_password is not None:
        data = protect(data, pdf_password)
    write_private_atomic(destination, data, temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().warning("%s PDF export written: %d entries",
                         "Password-protected" if pdf_password is not None else "Unencrypted",
                         count)
    return count


def vault_html(service: EntryService, vault: Vault) -> tuple[str, int]:
    """Document des comptes actifs (ni corbeille, ni historique) et leur nombre."""
    entries = [service.get_entry(summary.id) for summary in service.list_entries()]
    names = {c.id: c.name for c in CategoryService(vault).list_categories()}
    return build_html(vault.info.vault_name, entries, names), len(entries)


# --- Clé de récupération -----------------------------------------------------------------------

# La clé ouvre le coffre à elle seule : son PDF est TOUJOURS chiffré, avec un mot de
# passe au moins « fort » (le chiffrement PDF se teste vite, contrairement à Argon2id).
RECOVERY_PDF_MIN_SCORE = 3


def recovery_html(vault_name: str, key: str, generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now().astimezone()
    groups = key.split("-")
    lines = "<br>".join(html.escape("-".join(groups[i:i + 4]))
                        for i in range(0, len(groups), 4))
    return (
        f"<html><head><style>{_CSS}"
        ".key { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 22pt;"
        " font-weight: 600; }</style></head><body>"
        "<h1>Clé de récupération</h1>"
        f'<p class="meta">Mon Coffre-Fort · coffre « {html.escape(vault_name)} » · '
        f"créée le {generated_at:%d/%m/%Y à %H:%M}</p>"
        '<table cellpadding="14" width="100%"><tr><td bgcolor="#EEF2F6" align="center">'
        f'<span class="key">{lines}</span></td></tr></table>'
        "<h2>En cas d'oubli du mot de passe maître</h2>"
        "<ol><li>Ouvrez Mon Coffre-Fort : sur l'écran de verrouillage, cliquez sur "
        "<b>« Mot de passe oublié ? »</b>.</li>"
        "<li>Saisissez cette clé (majuscules ou minuscules, avec ou sans tirets).</li>"
        "<li>Choisissez un nouveau mot de passe maître. Une <b>nouvelle</b> clé vous est alors "
        "donnée : celle-ci ne fonctionnera plus.</li></ol>"
        '<p class="warning"><b>Cette clé ouvre votre coffre SANS le mot de passe maître.</b> '
        "Conservez ce document hors de l'ordinateur (clé USB, copie imprimée rangée sous clé). "
        "Seule la clé la plus récente de ce coffre fonctionne.</p>"
        "</body></html>")


def check_recovery_pdf_password(pdf_password: str, key: str, vault: Vault | None = None) -> None:
    """Refuse un mot de passe de PDF trop faible, égal à la clé ou au mot de passe maître."""
    if pikepdf is None:
        raise PdfProtectionUnavailable(MISSING_DEPENDENCY)
    check_pdf_password_length(pdf_password)
    if estimate_strength(pdf_password).score < RECOVERY_PDF_MIN_SCORE:
        raise InvalidMasterPasswordPolicyError(
            "Ce mot de passe est trop faible pour protéger une clé de récupération : "
            "une phrase de passe de 5 à 6 mots est recommandée.")
    try:
        same_as_key = recovery.normalize(pdf_password) == recovery.normalize(key)
    except VaultError:
        same_as_key = False
    if same_as_key:
        raise InvalidMasterPasswordPolicyError("Le mot de passe du PDF ne peut pas être la clé.")
    if vault is not None and not vault.is_locked and \
            vault.verify_master_password(pdf_password, log_failure=False):
        raise InvalidMasterPasswordPolicyError(
            "Choisissez un mot de passe différent du mot de passe maître.")


def export_recovery_pdf(key: str, vault_name: str, destination: Path, pdf_password: str,
                        vault: Vault | None = None) -> None:
    """PDF de la clé de récupération, toujours chiffré (AES-256), écrit en 0600."""
    check_recovery_pdf_password(pdf_password, key, vault)
    data = render_pdf(recovery_html(vault_name, key),
                      f"Clé de récupération — {vault_name}")
    write_private_atomic(destination, protect(data, pdf_password),
                         temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().info("Password-protected recovery key PDF written")
