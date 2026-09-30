"""Application logging configuration.

Absolute rule: no secret (master password, stored passwords, derived keys,
tokens, secure note content, card numbers...) must ever reach a log, not
even at DEBUG level.

Domain modules must only log events (e.g. "Vault opened", "Entry created",
"Failed unlock attempt"), never the associated sensitive values.
"""

from __future__ import annotations

import logging
import logging.handlers
import re

from app.utils.paths import log_file

_LOGGER_NAME = "mon_coffre"

# Safety net: if a sensitive value ever ended up in a log message by accident
# (development bug), try to redact it through generic patterns instead of
# relying only on the discipline of the callers. This is NOT an absolute
# guarantee, only defense
# in depth.
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|mot_de_passe|master_password|secret|token|cvv|private_key)"
    r"\s*[=:]\s*\S+"
)


class RedactingFilter(logging.Filter):
    """Defensive filter that redacts `key=value` patterns suggesting a secret.

    The message is first **formatted with its arguments**, then redacted, and
    the arguments are removed: a secret passed as an argument (`"password=%s"`)
    is therefore redacted too. (Redacting only the template made formatting
    impossible, and the logging module then printed the raw arguments — hence
    the secret — in its error message.)
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - invalid template: let nothing through
            message = f"[unreadable log message, arguments redacted] {record.msg!s:.80}"
        record.msg = _SENSITIVE_KEY_PATTERN.sub(
            lambda m: m.group(0).split("=")[0].split(":")[0] + "=[REDACTED]",
            message,
        )
        record.args = ()
        return True


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger  # already configured

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
