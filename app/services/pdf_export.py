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
from app.services.import_export import EXPORT_TEMP_PREFIX, _require_master_password
from app.utils.files import write_private_atomic
from app.utils.logging import get_logger

try:  # Debian package dependency; missing => protection unavailable, reported
    import pikepdf
except ImportError:  # pragma: no cover - depends on the installation
    pikepdf = None

PDF_SUFFIX = ".pdf"
MISSING_DEPENDENCY = ("Password protection requires the Debian package "
                      "python3-pikepdf (sudo apt install python3-pikepdf).")


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
            f"The PDF password must contain at least {MIN_MASTER_PASSWORD_LENGTH} "
            "characters.")
    if len(password.encode("utf-8")) > MAX_PDF_PASSWORD_BYTES:
        raise InvalidMasterPasswordPolicyError(
            "Password too long for a PDF (127 bytes maximum).")


def protect(pdf: bytes, password: str) -> bytes:
    """Encrypts the PDF with AES-256 (R6); the password is required to open it.

    The result is reopened with the password before being returned: a PDF that
    would not open is never written.
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
                raise VaultError("The encrypted PDF is invalid.")
    except pikepdf.PdfError as exc:
        raise VaultError("The encrypted PDF could not be verified; nothing was written.") from exc
    return data
_NO_CATEGORY = "Uncategorized"

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
        rows.append(("Address (URL)", entry.url, False))
    if spec.uses_username:
        rows.append(("Username", entry.username, True))
    if spec.uses_email:
        rows.append(("Email", entry.email, False))
    if spec.uses_password:
        rows.append((spec.password_label, entry.password, True))
    for field in spec.extra_fields:
        rows.append((field.label, entry.extra.get(field.key, ""), field.secret))
    rows.append(("Notes", entry.notes, False))
    return [(label, value, secret) for label, value, secret in rows if value.strip()]


def build_html(vault_name: str, entries: list[Entry], category_names: dict[int, str],
               generated_at: datetime | None = None) -> str:
    """HTML document (every value is escaped)."""
    generated_at = generated_at or datetime.now().astimezone()
    groups: dict[str, list[Entry]] = {}
    for entry in entries:
        name = category_names.get(entry.category_id, "") if entry.category_id else ""
        groups.setdefault(name or _NO_CATEGORY, []).append(entry)
    parts = [
        f"<html><head><style>{_CSS}</style></head><body>",
        f"<h1>Keyra — {html.escape(vault_name)}</h1>",
        f'<p class="meta">{len(entries)} entr{"ies" if len(entries) > 1 else "y"} · '
        f"generated on {generated_at:%Y-%m-%d at %H:%M}</p>",
        '<p class="warning"><b>Confidential document.</b> It contains your passwords IN '
        "PLAINTEXT. Keep it locked away, far from the computer; destroy it (shredder) when it "
        "is no longer needed, and delete the PDF file after printing.<br>A long password "
        "may continue on the next line: no character (hyphen, space) is added at the "
        "break.</p>",
    ]
    ordered = sorted(groups, key=lambda g: (g == _NO_CATEGORY, g.casefold()))
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
        parts.append("<p>This vault contains no entries.</p>")
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
            raise PdfProtectionUnavailable(MISSING_DEPENDENCY)
        check_pdf_password_length(pdf_password)
        if vault.verify_master_password(pdf_password, log_failure=False):
            raise InvalidMasterPasswordPolicyError(
                "Choose a password different from the master password: a protected PDF "
                "withstands guessing attempts for much less time than a vault.")
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
    return (
        f"<html><head><style>{_CSS}"
        ".key { font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace; font-size: 22pt;"
        " font-weight: 600; }</style></head><body>"
        "<h1>Recovery key</h1>"
        f'<p class="meta">Keyra · vault "{html.escape(vault_name)}" · '
        f"created on {generated_at:%Y-%m-%d at %H:%M}</p>"
        '<table cellpadding="14" width="100%"><tr><td bgcolor="#EEF2F6" align="center">'
        f'<span class="key">{lines}</span></td></tr></table>'
        "<h2>If you forget the master password</h2>"
        "<ol><li>Open Keyra: on the lock screen, click "
        "<b>\"Forgot password?\"</b>.</li>"
        "<li>Enter this key (upper or lower case, with or without dashes).</li>"
        "<li>Choose a new master password. A <b>new</b> key is then given to you: "
        "this one will no longer work.</li></ol>"
        '<p class="warning"><b>This key opens your vault WITHOUT the master password.</b> '
        "Keep this document away from the computer (USB drive, printed copy kept locked "
        "away). Only the most recent key of this vault works.</p>"
        "</body></html>")


def check_recovery_pdf_password(pdf_password: str, key: str, vault: Vault | None = None) -> None:
    """Rejects a PDF password that is too weak, equal to the key or to the master password."""
    if pikepdf is None:
        raise PdfProtectionUnavailable(MISSING_DEPENDENCY)
    check_pdf_password_length(pdf_password)
    if estimate_strength(pdf_password).score < RECOVERY_PDF_MIN_SCORE:
        raise InvalidMasterPasswordPolicyError(
            "This password is too weak to protect a recovery key: "
            "a passphrase of 5 to 6 words is recommended.")
    try:
        same_as_key = recovery.normalize(pdf_password) == recovery.normalize(key)
    except VaultError:
        same_as_key = False
    if same_as_key:
        raise InvalidMasterPasswordPolicyError("The PDF password cannot be the key itself.")
    if vault is not None and not vault.is_locked and \
            vault.verify_master_password(pdf_password, log_failure=False):
        raise InvalidMasterPasswordPolicyError(
            "Choose a password different from the master password.")


def export_recovery_pdf(key: str, vault_name: str, destination: Path, pdf_password: str,
                        vault: Vault | None = None) -> None:
    """Recovery key PDF, always encrypted (AES-256), written as 0600."""
    check_recovery_pdf_password(pdf_password, key, vault)
    data = render_pdf(recovery_html(vault_name, key),
                      f"Recovery key — {vault_name}")
    write_private_atomic(destination, protect(data, pdf_password),
                         temp_prefix=EXPORT_TEMP_PREFIX)
    get_logger().info("Password-protected recovery key PDF written")
