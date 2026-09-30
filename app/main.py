"""Point d'entrée de l'application.

Ce fichier reste volontairement un simple « bootstrap » : toute la logique
vit dans app/core, app/database et app/ui — jamais directement ici.
"""

from __future__ import annotations

import os
import sys
import threading

from app import __version__
from app.core import strength
from app.utils.logging import setup_logging

# Doit correspondre au nom du fichier .desktop (packaging/mon-coffre-fort.desktop)
# pour que l'environnement de bureau associe la fenêtre à l'icône du lanceur.
DESKTOP_FILE_NAME = "mon-coffre-fort"


def _check_user_environment() -> str | None:
    """Isolation entre utilisateurs Linux : message d'erreur, ou None si tout va bien.

    * Jamais en root : les coffres et la configuration créés appartiendraient
      à root, et une interface graphique n'a pas à tourner avec ces droits.
    * Les dossiers de données doivent appartenir à l'utilisateur courant
      (sinon : lancé une fois avec sudo, ou HOME partagé/mal configuré).
    """
    if os.geteuid() == 0:
        return ("Mon Coffre-Fort ne doit pas être lancé en tant que root (sudo).\n"
                "Lancez-le avec votre compte utilisateur habituel.")
    for env, default in (("XDG_DATA_HOME", ".local/share"), ("XDG_CONFIG_HOME", ".config")):
        base = os.environ.get(env) or os.path.join(os.path.expanduser("~"), default)
        path = os.path.join(base, "mon-coffre")
        try:
            owner = os.stat(path).st_uid
        except FileNotFoundError:
            continue
        if owner != os.getuid():
            return (f"Le dossier {path} n'appartient pas à l'utilisateur courant.\n"
                    "Il a probablement été créé en lançant l'application avec sudo.\n"
                    f"Corrigez-le avec : sudo chown -R $USER: {path}")
    return None


def main() -> int:
    # Tout fichier créé par l'application (coffres, WAL, logs) n'est lisible
    # que par son propriétaire, en plus des répertoires déjà restreints en 0700.
    os.umask(0o077)
    problem = _check_user_environment()
    if problem:
        print(problem, file=sys.stderr)
        try:  # lancé depuis le menu des applications : message visible
            from PySide6.QtWidgets import QApplication, QMessageBox

            _app = QApplication(sys.argv)
            QMessageBox.critical(None, "Mon Coffre-Fort", problem)
        except Exception:  # noqa: BLE001, S110 - l'erreur est déjà sur stderr
            pass
        return 2
    logger = setup_logging()
    logger.info("Starting Mon Coffre-Fort %s", __version__)

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "PySide6 n'est pas installé dans cet environnement.\n"
            "Installez les dépendances avec :\n"
            "    pip install -r requirements.txt\n",
            file=sys.stderr,
        )
        return 1

    from app.ui.icons import app_icon
    from app.ui.main_window import APP_DISPLAY_NAME, MainWindow
    from app.ui.single_instance import SingleInstanceServer, notify_running_instance
    from app.ui.theme import apply_theme

    app = QApplication(sys.argv)
    if notify_running_instance():
        logger.info("Already running: existing window brought to front")
        return 0
    app.setApplicationName(DESKTOP_FILE_NAME)  # nom technique (WM_CLASS)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setApplicationVersion(__version__)
    app.setDesktopFileName(DESKTOP_FILE_NAME)
    app.setWindowIcon(app_icon())
    apply_theme(app)

    # Préchargement des dictionnaires de l'estimateur de robustesse (lecture de
    # fichiers texte uniquement, sans accès au coffre) pour ne pas figer la
    # première saisie d'un mot de passe.
    threading.Thread(target=strength.dictionary_available, daemon=True).start()

    window = MainWindow()
    instance_server = SingleInstanceServer(app)
    instance_server.show_requested.connect(window.bring_to_front)
    window.show()
    code = app.exec()
    logger.info("Exiting Mon Coffre-Fort")
    return code


if __name__ == "__main__":
    sys.exit(main())
