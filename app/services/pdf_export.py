"""Printable PDF export: every entry of the vault, passwords IN PLAINTEXT.

Same rules as the unencrypted CSV export (see import_export):
* the master password is asked again (an open session is not enough);
* the PDF is built entirely in memory (QPdfWriter on a QBuffer: no plaintext
  temporary file), then written in one go as 0600;
* the Trash and the history are never included.

Password protection (optional, recommended): AES-256 PDF encryption
(revision 6, PDF 2.0) through pikepdf / qpdf (Debian package python3-pikepdf),
in memory. The PDF password must differ from the master password: an
encrypted PDF can be brute-forced much faster than an Argon2id-protected
vault. Without protection, the file is in plaintext: print it, then delete it.

Rendering: QTextDocument (simple HTML, escaped values) paginated by Qt, with
page numbers. No dependency beyond QtGui.
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
from app.i18n import tr, tr_n
from app.services.import_export import EXPORT_TEMP_PREFIX, _require_master_password
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger

try:  # Debian package dependency; missing => protection unavailable, reported
    import pikepdf
except ImportError:  # pragma: no cover - depends on the installation
    pikepdf = None

PDF_SUFFIX = ".pdf"
MISSING_DEPENDENCY = "pdf.error.missing_pikepdf"  # translation key (app/i18n)


class PdfProtectionUnavailable(VaultError):
    """pikepdf (python3-pikepdf) is not installed."""


def protection_available() -> bool:
    return pikepdf is not None


# PDF standard (revision 6): beyond this, the password is truncated and the file
# might no longer open with the password typed.
MAX_PDF_PASSWORD_BYTES = 127


def check_pdf_password_length(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            tr("pdf.error.password_too_short", min=MIN_MASTER_PASSWORD_LENGTH))
    if len(password.encode("utf-8")) > MAX_PDF_PASSWORD_BYTES:
        raise InvalidMasterPasswordPolicyError(
            tr("pdf.error.password_too_long", max=MAX_PDF_PASSWORD_BYTES))


def protect(pdf: bytes, password: str) -> bytes:
    """Encrypts the PDF with AES-256 (R6); the password is required to open it.

    The result is reopened with the password before being returned: a PDF that
    would not open is never written.
    """
    if pikepdf is None:
        raise PdfProtectionUnavailable(tr(MISSING_DEPENDENCY))
    check_pdf_password_length(password)
    output = io.BytesIO()
    with pikepdf.open(io.BytesIO(pdf)) as document:
        document.save(output, encryption=pikepdf.Encryption(
            user=password, owner=password, R=6, aes=True, metadata=True))
    data = output.getvalue()
    try:
        with pikepdf.open(io.BytesIO(data), password=password) as check:
            if not check.is_encrypted or len(check.pages) == 0:
                raise VaultError(tr("pdf.error.invalid"))
    except pikepdf.PdfError as exc:
        raise VaultError(tr("pdf.error.unverified")) from exc
    return data

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
    """(label, value, secret) of the non-empty fields, in interface order."""
    spec = ENTRY_TYPES.get(entry.entry_type) or ENTRY_TYPES[DEFAULT_ENTRY_TYPE]
    rows: list[tuple[str, str, bool]] = []
    if spec.uses_url:
        rows.append((tr("pdf.field.url"), entry.url, False))
    if spec.uses_username:
        rows.append((tr("field.username"), entry.username, True))
    if spec.uses_email:
        rows.append((tr("field.email"), entry.email, False))
    if spec.uses_password:
        rows.append((spec.password_label, entry.password, True))
    for field in spec.extra_fields:
        rows.append((field.label, entry.extra.get(field.key, ""), field.secret))
    rows.append((tr("field.notes"), entry.notes, False))
    return [(label, value, secret) for label, value, secret in rows if value.strip()]


def build_html(vault_name: str, entries: list[Entry], category_names: dict[int, str],
               generated_at: datetime | None = None) -> str:
    """HTML document (every value is escaped)."""
    generated_at = generated_at or datetime.now().astimezone()
    no_category = tr("pdf.uncategorized")
    groups: dict[str, list[Entry]] = {}
    for entry in entries:
        name = category_names.get(entry.category_id, "") if entry.category_id else ""
        groups.setdefault(name or no_category, []).append(entry)
    generated = tr("pdf.generated_on", date=f"{generated_at:%Y-%m-%d}",
                   time=f"{generated_at:%H:%M}")
    parts = [
        f"<html><head><style>{_CSS}</style></head><body>",
        f"<h1>Keyra — {html.escape(vault_name)}</h1>",
        f'<p class="meta">{html.escape(tr_n("pdf.entries", len(entries)))} · '
        f"{html.escape(generated)}</p>",
        f'<p class="warning"><b>{html.escape(tr("pdf.warning.title"))}</b> '
        f"{html.escape(tr('pdf.warning.body'))}<br>{html.escape(tr('pdf.warning.wrap'))}</p>",
    ]
    ordered = sorted(groups, key=lambda g: (g == no_category, g.casefold()))
    for group in ordered:
        parts.append(f"<h2>{html.escape(group)}</h2>")
        # One table per category, fixed-width columns (Qt ignores the CSS width of
        # cells); each entry starts with a grey band.
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
        parts.append(f"<p>{html.escape(tr('pdf.empty'))}</p>")
    parts.append("</body></html>")
    return "".join(parts)


def render_pdf(document_html: str, title: str) -> bytes:
    """A4 PDF in memory (requires a QGuiApplication, like the whole interface)."""
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    writer = QPdfWriter(buffer)
    writer.setTitle(title)
    writer.setCreator("Keyra")
    # Qt margins (2 cm) added by QTextDocument.print_, with page numbers.
    writer.setPageLayout(QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait,
                                     QMarginsF(0, 0, 0, 0), QPageLayout.Millimeter))
    document = QTextDocument()
    # Document-specific font, in POINTS: otherwise it inherits the interface font,
    # defined in pixels (point size = -1), and the h1/h2 headings — computed from
    # the point size — become invisible.
    base = QFont(["Inter", "DejaVu Sans", "Liberation Sans"])
    base.setPointSizeF(10)
    document.setDefaultFont(base)
    document.setHtml(document_html)
    document.print_(writer)
    del writer  # finishes the PDF (writes the end of the file into the buffer)
    buffer.close()
    document.clear()
    return bytes(data)


def export_pdf(service: EntryService, vault: Vault, master_password: str,
               destination: Path, pdf_password: str | None = None) -> int:
    """Writes the PDF (0600) and returns the number of entries. Master password required.

    `pdf_password`: encrypted PDF (AES-256); None: plaintext PDF.
    """
    _require_master_password(vault, master_password)
    if pdf_password is not None:
        if pikepdf is None:
            raise PdfProtectionUnavailable(tr(MISSING_DEPENDENCY))
        check_pdf_password_length(pdf_password)
        if vault.verify_master_password(pdf_password, log_failure=False):
            raise InvalidMasterPasswordPolicyError(tr("pdf.error.same_as_master_long"))
    document_html, count = vault_html(service, vault)
    data = render_pdf(document_html, f"Keyra — {vault.info.vault_name}")
    if pdf_password is not None:
        data = protect(data, pdf_password)
    write_private_atomic(destination, data, temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().warning("%s PDF export written: %d entries",
                         "Password-protected" if pdf_password is not None else "Unencrypted",
                         count)
    return count


def vault_html(service: EntryService, vault: Vault) -> tuple[str, int]:
    """Document of the active entries (no Trash, no history) and their number."""
    entries = [service.get_entry(summary.id) for summary in service.list_entries()]
    names = {c.id: c.name for c in CategoryService(vault).list_categories()}
    return build_html(vault.info.vault_name, entries, names), len(entries)


# --- Recovery key -----------------------------------------------------------------------

# The key opens the vault on its own: its PDF is ALWAYS encrypted, with a password
# rated at least "strong" (PDF encryption is fast to test, unlike Argon2id).
RECOVERY_PDF_MIN_SCORE = 3


def recovery_html(vault_name: str, key: str, generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now().astimezone()
    groups = key.split("-")
    lines = "<br>".join(html.escape("-".join(groups[i:i + 4]))
                        for i in range(0, len(groups), 4))
    def t(key: str, **params) -> str:
        return html.escape(tr(key, **params))

    meta = t("pdf.recovery.meta", vault=vault_name, date=f"{generated_at:%Y-%m-%d}",
             time=f"{generated_at:%H:%M}")
    return (
        f"<html><head><style>{_CSS}"
        ".key { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 22pt;"
        " font-weight: 600; }</style></head><body>"
        f"<h1>{t('pdf.recovery.title')}</h1>"
        f'<p class="meta">{meta}</p>'
        '<table cellpadding="14" width="100%"><tr><td bgcolor="#EEF2F6" align="center">'
        f'<span class="key">{lines}</span></td></tr></table>'
        f"<h2>{t('pdf.recovery.forgot_title')}</h2>"
        f"<ol><li>{t('pdf.recovery.step1', button=tr('lock.forgot_password'))}</li>"
        f"<li>{t('pdf.recovery.step2')}</li>"
        f"<li>{t('pdf.recovery.step3')}</li></ol>"
        f'<p class="warning"><b>{t("pdf.recovery.warning_title")}</b> '
        f"{t('pdf.recovery.warning_body')}</p>"
        "</body></html>")


def check_recovery_pdf_password(pdf_password: str, key: str, vault: Vault | None = None) -> None:
    """Rejects a PDF password that is too weak, equal to the key or to the master password."""
    if pikepdf is None:
        raise PdfProtectionUnavailable(tr(MISSING_DEPENDENCY))
    check_pdf_password_length(pdf_password)
    if estimate_strength(pdf_password).score < RECOVERY_PDF_MIN_SCORE:
        raise InvalidMasterPasswordPolicyError(tr("pdf.error.recovery_password_weak"))
    try:
        same_as_key = recovery.normalize(pdf_password) == recovery.normalize(key)
    except VaultError:
        same_as_key = False
    if same_as_key:
        raise InvalidMasterPasswordPolicyError(tr("pdf.error.password_is_key"))
    if vault is not None and not vault.is_locked and \
            vault.verify_master_password(pdf_password, log_failure=False):
        raise InvalidMasterPasswordPolicyError(tr("pdf.error.same_as_master"))


def export_recovery_pdf(key: str, vault_name: str, destination: Path, pdf_password: str,
                        vault: Vault | None = None) -> None:
    """Recovery key PDF, always encrypted (AES-256), written as 0600."""
    check_recovery_pdf_password(pdf_password, key, vault)
    data = render_pdf(recovery_html(vault_name, key),
                      tr("pdf.recovery.document_title", vault=vault_name))
    write_private_atomic(destination, protect(data, pdf_password),
                         temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().info("Password-protected recovery key PDF written")
