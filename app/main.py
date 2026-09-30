"""Application entry point.

This file deliberately remains a simple bootstrap: all the logic lives in
app/core, app/database and app/ui — never directly here.
"""

from __future__ import annotations

import os
import sys
import threading

from app import __version__, i18n
from app.core import strength
from app.i18n import tr
from app.utils.logging import setup_logging

# Must match the name of the .desktop file (packaging/mon-coffre-fort.desktop)
# so that the desktop environment associates the window with the launcher icon.
DESKTOP_FILE_NAME = "mon-coffre-fort"


def _check_user_environment() -> str | None:
    """Isolation between Linux users: error message, or None if all is well.

    * Never as root: the vaults and configuration created would belong to
      root, and a graphical interface has no business running with those rights.
    * The data folders must belong to the current user (otherwise: launched
      once with sudo, or a shared/misconfigured HOME).
    """
    if os.geteuid() == 0:
        return tr("startup.root")
    for env, default in (("XDG_DATA_HOME", ".local/share"), ("XDG_CONFIG_HOME", ".config")):
        base = os.environ.get(env) or os.path.join(os.path.expanduser("~"), default)
        path = os.path.join(base, "mon-coffre")
        try:
            owner = os.stat(path).st_uid
        except FileNotFoundError:
            continue
        if owner != os.getuid():
            return tr("startup.foreign_folder", path=path)
    return None


def main() -> int:
    # Every file created by the application (vaults, WAL, logs) is readable
    # only by its owner, in addition to the directories already restricted to 0700.
    os.umask(0o077)
    # Messages before the settings are read: system language (MainWindow then applies
    # the "language" setting).
    i18n.set_language(i18n.detector.detect())
    problem = _check_user_environment()
    if problem:
        print(problem, file=sys.stderr)
        try:  # launched from the applications menu: visible message
            from PySide6.QtWidgets import QApplication, QMessageBox

            _app = QApplication(sys.argv)
            QMessageBox.critical(None, "Keyra", problem)
        except Exception:  # noqa: BLE001, S110 - the error is already on stderr
            pass
        return 2
    logger = setup_logging()
    logger.info("Starting Keyra %s", __version__)

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(tr("startup.no_pyside6"), file=sys.stderr)
        return 1

    from app.ui.icons import app_icon
    from app.ui.main_window import APP_DISPLAY_NAME, MainWindow
    from app.ui.single_instance import SingleInstanceServer, notify_running_instance
    from app.ui.theme import apply_theme

    app = QApplication(sys.argv)
    if notify_running_instance():
        logger.info("Already running: existing window brought to front")
        return 0
    app.setApplicationName(DESKTOP_FILE_NAME)  # technical name (WM_CLASS)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setApplicationVersion(__version__)
    app.setDesktopFileName(DESKTOP_FILE_NAME)
    app.setWindowIcon(app_icon())
    apply_theme(app)

    # Preload the strength estimator dictionaries (text files only, no vault
    # access) so that the first password typed does not freeze the
    # interface.
    threading.Thread(target=strength.dictionary_available, daemon=True).start()

    window = MainWindow()
    instance_server = SingleInstanceServer(app)
    instance_server.show_requested.connect(window.bring_to_front)
    window.show()
    code = app.exec()
    logger.info("Exiting Keyra")
    return code


if __name__ == "__main__":
    sys.exit(main())
