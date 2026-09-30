"""Password and passphrase generator.

All randomness comes exclusively from `secrets` (the system CSPRNG):
`secrets.choice` for draws and a Fisher-Yates shuffle based on
`secrets.randbelow`. The `random` module is never imported (a test checks
this across the whole `app` package).

Passphrases: the word list comes from `/usr/share/dict/french` (Debian
package `wfrench`). It is not bundled with the project; if it is missing,
`WordlistUnavailableError` is raised with the name of the package to install.
"""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.exceptions import VaultError

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_PASSPHRASE_WORDS = 4
MAX_PASSPHRASE_WORDS = 12

SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
AMBIGUOUS = set("Il1O0o|`'\"")

FRENCH_WORDLIST_PATH = Path("/usr/share/dict/french")
FRENCH_WORDLIST_PACKAGE = "wfrench"
_WORD_PATTERN = re.compile(r"^[a-z]{4,8}$")


class GeneratorError(VaultError):
    """Invalid generation options."""


class WordlistUnavailableError(GeneratorError):
    """The word list required for passphrases cannot be found."""


@dataclass(frozen=True, slots=True)
class PasswordOptions:
    length: int = 20
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class PassphraseOptions:
    words: int = 6
    separator: str = "-"
    capitalize: bool = False
    add_number: bool = False


@dataclass(frozen=True, slots=True)
class GeneratedSecret:
    value: str
    entropy_bits: float

    def __repr__(self) -> str:  # never the value in a repr
        return f"GeneratedSecret(entropy_bits={self.entropy_bits:.1f})"


def _shuffle(items: list[str]) -> None:
    """Fisher-Yates shuffle, `secrets` randomness only."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def _character_classes(options: PasswordOptions) -> list[str]:
    classes = []
    if options.lowercase:
        classes.append(string.ascii_lowercase)
    if options.uppercase:
        classes.append(string.ascii_uppercase)
    if options.digits:
        classes.append(string.digits)
    if options.symbols:
        classes.append(SYMBOLS)
    if options.exclude_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    return [cls for cls in classes if cls]


def generate_password(options: PasswordOptions = PasswordOptions()) -> GeneratedSecret:
    """Random password containing at least one character from each selected class."""
    if not MIN_PASSWORD_LENGTH <= options.length <= MAX_PASSWORD_LENGTH:
        raise GeneratorError(
            f"The length must be between {MIN_PASSWORD_LENGTH} "
            f"and {MAX_PASSWORD_LENGTH} characters."
        )
    classes = _character_classes(options)
    if not classes:
        raise GeneratorError("Select at least one character type.")
    alphabet = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(alphabet) for _ in range(options.length - len(chars))]
    _shuffle(chars)
    # Conservative lower bound: the randomness of placing the required classes is not counted.
    entropy = options.length * math.log2(len(alphabet))
    return GeneratedSecret("".join(chars), entropy)


@lru_cache(maxsize=1)
def load_passphrase_wordlist() -> tuple[str, ...]:
    """French words of 4 to 8 letters, without accents or capitals, deduplicated."""
    try:
        text = FRENCH_WORDLIST_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise WordlistUnavailableError(
            f"Word list not found ({FRENCH_WORDLIST_PATH}). Install the "
            f"Debian package \"{FRENCH_WORDLIST_PACKAGE}\": "
            f"sudo apt install {FRENCH_WORDLIST_PACKAGE}"
        ) from exc
    words = sorted({w for w in text.split() if _WORD_PATTERN.match(w)})
    if len(words) < 2048:
        raise WordlistUnavailableError(
            f"Word list too short in {FRENCH_WORDLIST_PATH} ({len(words)} words)."
        )
    return tuple(words)


def passphrase_available() -> bool:
    try:
        load_passphrase_wordlist()
    except WordlistUnavailableError:
        return False
    return True


def generate_passphrase(options: PassphraseOptions = PassphraseOptions()) -> GeneratedSecret:
    if not MIN_PASSPHRASE_WORDS <= options.words <= MAX_PASSPHRASE_WORDS:
        raise GeneratorError(
            f"The number of words must be between {MIN_PASSPHRASE_WORDS} "
            f"and {MAX_PASSPHRASE_WORDS}."
        )
    wordlist = load_passphrase_wordlist()
    words = [secrets.choice(wordlist) for _ in range(options.words)]
    if options.capitalize:
        words = [w.capitalize() for w in words]
    entropy = options.words * math.log2(len(wordlist))
    if options.add_number:
        index = secrets.randbelow(len(words))
        words[index] += str(secrets.randbelow(10))
        entropy += math.log2(10) + math.log2(len(words))
    return GeneratedSecret(options.separator.join(words), entropy)
