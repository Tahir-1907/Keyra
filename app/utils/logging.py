"""Configuration du logging applicatif.

Règle absolue : aucun secret (mot de passe maître, mots de passe stockés,
clés dérivées, tokens, contenu de notes sécurisées, numéros de carte...)
ne doit jamais atteindre un log, même en niveau DEBUG.

Les modules métier ne doivent journaliser que des événements
(ex: "Vault opened", "Entry created", "Failed unlock attempt"), jamais
les valeurs sensibles associées.
"""

from __future__ import annotations

import logging
import logging.handlers
import re

from app.utils.paths import log_file

_LOGGER_NAME = "mon_coffre"

# Filet de sécurité : si une valeur sensible finissait accidentellement dans
# un message de log (bug de développement), on tente de la masquer via des
# motifs génériques plutôt que de faire confiance uniquement à la discipline
# des appelants. Ce n'est PAS une garantie absolue, seulement une défense
# en profondeur.
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|mot_de_passe|master_password|secret|token|cvv|private_key)"
    r"\s*[=:]\s*\S+"
)


class RedactingFilter(logging.Filter):
    """Filtre défensif masquant les motifs `cle=valeur` évoquant un secret.

    Le message est d'abord **formaté avec ses arguments**, puis masqué, et les
    arguments sont retirés : un secret passé en argument (`"password=%s"`)
    est donc lui aussi masqué. (Masquer seulement le gabarit rendait le
    formatage impossible, et le module logging affichait alors les arguments
    bruts — donc le secret — dans son message d'erreur.)
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - gabarit invalide : ne rien laisser passer
            message = f"[message de log illisible, arguments masqués] {record.msg!s:.80}"
        record.msg = _SENSITIVE_KEY_PATTERN.sub(
            lambda m: m.group(0).split("=")[0].split(":")[0] + "=[REDACTED]",
            message,
        )
        record.args = ()
        return True


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger  # déjà configuré

    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_file(), maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(RedactingFilter())

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(RedactingFilter())

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
