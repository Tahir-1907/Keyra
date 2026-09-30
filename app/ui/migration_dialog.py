"""Upgrade of a vault created by an earlier version (v1 to v3 -> v4).

Two uses:
* `job` provided (unlocking): explicit confirmation, then the upgrade runs in
  the background (app.ui.tasks); on failure, the error is shown with "Retry".
* `job=None` (forgotten password): confirmation only; the upgrade is then done
  by the recovery window.

During the upgrade, the window cannot be closed (Esc, close button, Cancel,
locking): the result would be lost. Closing the application is refused too
(MainWindow.closeEvent).

Master password: the work function (`job`) captures it. The window releases it
as soon as it is no longer needed (work succeeded, window closed), keeps no
exception traceback (whose frames would retain the local variables), and the
caller destroys it after use (`take_outcome` then `deleteLater`). Limitation:
Python cannot erase a `str`; the references are dropped so that the memory is
returned as early as possible, without any guarantee about its content (same
limitation as app.core.crypto.wipe).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QDialog, QHBoxLayout, QWidget

from app.core.exceptions import VaultError
from app.services.vault_upgrade import UpgradeCheck, UpgradeVerificationError, failure_details
from app.ui import components as ui
from app.ui import effects, tasks
from app.ui.dialogs import PremiumDialog


class MigrationDialog(PremiumDialog):
    def __init__(self, check: UpgradeCheck, vault_name: str, backup_dir: Path,
                 job: Callable[[], object] | None, parent: QWidget | None = None) -> None:
        super().__init__(parent, "Upgrade the vault",
                         f"\"{vault_name}\" was created by an earlier version of the "
                         f"application (format v{check.schema_version}).",
                         icon="shield-check", width=580)
        self._job = job
        self._busy = False
        self.result = None  # UpgradeResult after success
        self.last_error: Exception | None = None
        self.attempts = 0

        self.body.addWidget(ui.label(
            "This version also encrypts the names, addresses, usernames, categories, tags "
            "and dates of your entries (only the date each history version was recorded "
            "stays readable). To do so, the vault must be upgraded:",
            wrap=True))
        for text in (
            "before any modification, an encrypted backup of the vault, in its current "
            f"format, is created and verified in \"{backup_dir}\". It is kept and "
            "opens with your current master password;",
            "if a problem occurs during the upgrade, everything is cancelled: the vault "
            "stays as it is;",
            "the upgrade is final: a version 1.6 will no longer be able to open this "
            "vault.",
            "to go back, you will need a version 1.6 of the application: its "
            "\"Restore a backup\" function opens the backup above as a new "
            "vault. Depending on how it was installed (Debian package, for "
            "example), version 1.7 may replace 1.6: keep a way to reinstall it "
            "if you think you may need it.",
        ):
            self.body.addWidget(ui.label("•  " + text, "Muted", wrap=True))
        if check.legacy_plaintext_copies:
            names = ", ".join(p.name for p in check.legacy_plaintext_copies)
            self.body.addWidget(ui.label(
                f"Warning: {len(check.legacy_plaintext_copies)} old UNENCRYPTED "
                f"copy(ies) are next to the vault ({names}). They are neither "
                "used nor deleted: delete them yourself once the vault has been "
                "verified.", "Error", wrap=True))

        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        busy = QWidget()
        row = QHBoxLayout(busy)
        row.setContentsMargins(0, 0, 0, 0)
        self.spinner = effects.Spinner(16)
        row.addStretch(1)
        row.addWidget(self.spinner)
        row.addWidget(ui.label("Upgrade in progress — do not close the application…",
                               "Muted"))
        row.addStretch(1)
        busy.hide()
        self.busy_row = busy
        self.body.addWidget(busy)
        self.cancel, self.ok = self.add_buttons(
            "Cancel", "Upgrade" if job is not None else "Continue",
            confirm_icon="shield-check")
        self.ok.clicked.connect(self.start)

    # --- API ---------------------------------------------------------------------------

    def is_busy(self) -> bool:
        return self._busy

    def start(self) -> None:
        """Explicit confirmation by the user ("Upgrade" button)."""
        if self._busy:
            return
        if self._job is None:
            self.accept()
            return
        self.attempts += 1
        self.last_error = None  # the error of the previous attempt is no longer kept
        self._set_busy(True)
        tasks.run_task(self._job, self._on_done, self._on_failed, self)

    def take_outcome(self) -> tuple[object, Exception | None]:
        """(result, error) handed to the caller, then forgotten by the window."""
        outcome = (self.result, self.last_error)
        self.result = self.last_error = None
        return outcome

    # --- Internal -------------------------------------------------------------------------

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.ok.setEnabled(not busy)
        self.cancel.setEnabled(not busy)
        self.busy_row.setVisible(busy)
        if busy:
            self.error.hide()
            self.spinner.start()
        else:
            self.spinner.stop()

    def _on_done(self, result) -> None:
        # The work is over (this callback runs on the interface thread, after the
        # worker thread): the function that captures the password is no longer needed.
        self._job = None
        self.result = result
        self._set_busy(False)
        self.accept()

    def _on_failed(self, exc: Exception) -> None:
        # The work function is kept: "Retry" needs it while the window is open.
        # The traceback, however, would retain the local variables of the frames it
        # went through (including the password): only the error is kept.
        self.last_error = _without_tracebacks(exc)
        self._set_busy(False)
        self.error.setText(_failure_text(exc))
        self.error.show()
        effects.shake(self.card)
        if isinstance(exc, UpgradeVerificationError):
            # Migration already applied: retrying makes no sense.
            self.ok.hide()
            self.cancel.setText("Close")
        else:
            self.ok.setText("Retry")

    def reject(self) -> None:
        if not self._busy:
            super().reject()

    def done(self, result: int) -> None:
        if self._busy:  # never during the work: the worker thread callback is on its way
            return
        self._job = None  # window closed: no retry possible
        super().done(result)

    def close_now(self, result: int = QDialog.Rejected) -> None:
        if not self._busy:
            self._job = None
            super().close_now(result)


def _failure_text(exc: Exception) -> str:
    """Short, understandable message, then the technical detail useful for diagnosis
    (application message, path and cause of a file failure)."""
    if not isinstance(exc, VaultError):
        return "The upgrade failed."
    if isinstance(exc, UpgradeVerificationError):
        return str(exc)
    lines = ["The upgrade did not complete.", f"Detail: {exc}"]
    return "\n".join(lines + failure_details(exc))


def _without_tracebacks(exc: Exception) -> Exception:
    """Detaches the tracebacks of `exc` and its causes: their frames (and the local
    variables they carry, password included) are no longer retained. The message
    and type, the only things used for display, are kept."""
    seen: set[int] = set()
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        current.__traceback__ = None
        pending += [current.__cause__, current.__context__]
    return exc
