"""Mise à niveau d'un coffre créé par une version précédente (v1 à v3 -> v4).

Deux usages :
* `job` fourni (déverrouillage) : confirmation explicite, puis mise à niveau en
  arrière-plan (app.ui.tasks) ; en cas d'échec, erreur affichée et « Réessayer ».
* `job=None` (mot de passe oublié) : confirmation seule ; la mise à niveau est
  ensuite faite par la fenêtre de récupération.

Pendant la mise à niveau, la fenêtre ne peut pas être fermée (Échap, croix,
Annuler, verrouillage) : le résultat serait perdu. La fermeture de
l'application est elle aussi refusée (MainWindow.closeEvent).

Mot de passe maître : la fonction de travail (`job`) le capture. La fenêtre la
libère dès qu'elle n'est plus utile (travail réussi, fenêtre fermée), ne garde
aucune trace d'exception (dont les frames retiendraient les variables locales),
et l'appelant la détruit après usage (`take_outcome` puis `deleteLater`). Limite :
Python ne permet pas d'effacer une `str` ; on supprime les références pour que la
mémoire soit rendue au plus tôt, sans garantie sur son contenu (même limite que
app.core.crypto.wipe).
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
        super().__init__(parent, "Mettre à niveau le coffre",
                         f"« {vault_name} » a été créé par une version précédente de Mon "
                         f"Coffre-Fort (format v{check.schema_version}).",
                         icon="shield-check", width=580)
        self._job = job
        self._busy = False
        self.result = None  # UpgradeResult après succès
        self.last_error: Exception | None = None
        self.attempts = 0

        self.body.addWidget(ui.label(
            "Cette version chiffre aussi les noms, adresses, identifiants, catégories, tags "
            "et dates de vos comptes (seule la date d'enregistrement de chaque version de "
            "l'historique reste lisible). Pour cela, le coffre doit être mis à niveau :",
            wrap=True))
        for text in (
            "avant toute modification, une sauvegarde chiffrée du coffre, dans son format "
            f"actuel, est créée et vérifiée dans « {backup_dir} ». Elle est conservée et "
            "s'ouvre avec votre mot de passe maître actuel ;",
            "en cas de problème pendant la mise à niveau, tout est annulé : le coffre reste "
            "tel qu'il est ;",
            "la mise à niveau est définitive : une version 1.6 ne pourra plus ouvrir ce "
            "coffre.",
            "pour revenir en arrière, il faudra une version 1.6 de Mon Coffre-Fort : sa "
            "fonction « Restaurer une sauvegarde » ouvre la sauvegarde ci-dessus, sous "
            "forme d'un nouveau coffre. Selon la façon dont elle a été installée (paquet "
            "Debian, par exemple), la version 1.7 peut remplacer la 1.6 : gardez de quoi la "
            "réinstaller si vous pensez en avoir besoin.",
        ):
            self.body.addWidget(ui.label("•  " + text, "Muted", wrap=True))
        if check.legacy_plaintext_copies:
            names = ", ".join(p.name for p in check.legacy_plaintext_copies)
            self.body.addWidget(ui.label(
                f"Attention : {len(check.legacy_plaintext_copies)} ancienne(s) copie(s) NON "
                f"chiffrée(s) se trouvent à côté du coffre ({names}). Elles ne sont ni "
                "utilisées ni supprimées : supprimez-les vous-même une fois le coffre "
                "vérifié.", "Error", wrap=True))

        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        busy = QWidget()
        row = QHBoxLayout(busy)
        row.setContentsMargins(0, 0, 0, 0)
        self.spinner = effects.Spinner(16)
        row.addStretch(1)
        row.addWidget(self.spinner)
        row.addWidget(ui.label("Mise à niveau en cours — ne fermez pas l'application…",
                               "Muted"))
        row.addStretch(1)
        busy.hide()
        self.busy_row = busy
        self.body.addWidget(busy)
        self.cancel, self.ok = self.add_buttons(
            "Annuler", "Mettre à niveau" if job is not None else "Continuer",
            confirm_icon="shield-check")
        self.ok.clicked.connect(self.start)

    # --- API ---------------------------------------------------------------------------

    def is_busy(self) -> bool:
        return self._busy

    def start(self) -> None:
        """Confirmation explicite de l'utilisateur (bouton « Mettre à niveau »)."""
        if self._busy:
            return
        if self._job is None:
            self.accept()
            return
        self.attempts += 1
        self.last_error = None  # l'erreur de l'essai précédent n'est plus retenue
        self._set_busy(True)
        tasks.run_task(self._job, self._on_done, self._on_failed, self)

    def take_outcome(self) -> tuple[object, Exception | None]:
        """(résultat, erreur) remis à l'appelant, puis oubliés par la fenêtre."""
        outcome = (self.result, self.last_error)
        self.result = self.last_error = None
        return outcome

    # --- Interne -------------------------------------------------------------------------

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
        # Le travail est terminé (ce rappel s'exécute dans le fil de l'interface, après
        # le fil de travail) : la fonction qui capture le mot de passe n'est plus utile.
        self._job = None
        self.result = result
        self._set_busy(False)
        self.accept()

    def _on_failed(self, exc: Exception) -> None:
        # La fonction de travail est gardée : « Réessayer » en a besoin tant que la
        # fenêtre est ouverte. La trace, elle, retiendrait les variables locales des
        # frames traversées (dont le mot de passe) : seule l'erreur est conservée.
        self.last_error = _without_tracebacks(exc)
        self._set_busy(False)
        self.error.setText(_failure_text(exc))
        self.error.show()
        effects.shake(self.card)
        if isinstance(exc, UpgradeVerificationError):
            # Migration déjà appliquée : un nouvel essai n'a pas de sens.
            self.ok.hide()
            self.cancel.setText("Fermer")
        else:
            self.ok.setText("Réessayer")

    def reject(self) -> None:
        if not self._busy:
            super().reject()

    def done(self, result: int) -> None:
        if self._busy:  # jamais pendant le travail : le rappel du fil de travail arrive
            return
        self._job = None  # fenêtre fermée : aucun nouvel essai possible
        super().done(result)

    def close_now(self, result: int = QDialog.Rejected) -> None:
        if not self._busy:
            self._job = None
            super().close_now(result)


def _failure_text(exc: Exception) -> str:
    """Message court et compréhensible, puis le détail technique utile au diagnostic
    (message de l'application, chemin et cause d'un échec de fichier)."""
    if not isinstance(exc, VaultError):
        return "La mise à niveau a échoué."
    if isinstance(exc, UpgradeVerificationError):
        return str(exc)
    lines = ["La mise à niveau n'a pas abouti.", f"Détail : {exc}"]
    return "\n".join(lines + failure_details(exc))


def _without_tracebacks(exc: Exception) -> Exception:
    """Détache les traces de `exc` et de ses causes : leurs frames (et les variables
    locales qu'elles portent, mot de passe compris) ne sont plus retenues. Le message
    et le type, seuls utilisés pour l'affichage, sont conservés."""
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
