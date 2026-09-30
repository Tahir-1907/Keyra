"""Générateur de mots de passe et de phrases de passe.

Tout l'aléa provient exclusivement de `secrets` (CSPRNG du système) :
`secrets.choice` pour les tirages et un mélange de Fisher-Yates basé sur
`secrets.randbelow`. Le module `random` n'est jamais importé (un test le
vérifie sur tout le paquet `app`).

Phrases de passe : la liste de mots provient de `/usr/share/dict/french`
(paquet Debian `wfrench`). Elle n'est pas embarquée dans le projet ; si
elle est absente, `WordlistUnavailableError` est levée avec le nom du
paquet à installer.
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
    """Options de génération invalides."""


class WordlistUnavailableError(GeneratorError):
    """La liste de mots nécessaire aux phrases de passe est introuvable."""


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

    def __repr__(self) -> str:  # jamais la valeur dans un repr
        return f"GeneratedSecret(entropy_bits={self.entropy_bits:.1f})"


def _shuffle(items: list[str]) -> None:
    """Mélange de Fisher-Yates, aléa `secrets` uniquement."""
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
    """Mot de passe aléatoire contenant au moins un caractère de chaque classe choisie."""
    if not MIN_PASSWORD_LENGTH <= options.length <= MAX_PASSWORD_LENGTH:
        raise GeneratorError(
            f"La longueur doit être comprise entre {MIN_PASSWORD_LENGTH} "
            f"et {MAX_PASSWORD_LENGTH} caractères."
        )
    classes = _character_classes(options)
    if not classes:
        raise GeneratorError("Choisissez au moins un type de caractères.")
    alphabet = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(alphabet) for _ in range(options.length - len(chars))]
    _shuffle(chars)
    # Borne basse prudente : on ne compte pas l'aléa du placement des classes imposées.
    entropy = options.length * math.log2(len(alphabet))
    return GeneratedSecret("".join(chars), entropy)


@lru_cache(maxsize=1)
def load_passphrase_wordlist() -> tuple[str, ...]:
    """Mots français de 4 à 8 lettres, sans accent ni majuscule, dédoublonnés."""
    try:
        text = FRENCH_WORDLIST_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise WordlistUnavailableError(
            f"Liste de mots introuvable ({FRENCH_WORDLIST_PATH}). Installez le "
            f"paquet Debian « {FRENCH_WORDLIST_PACKAGE} » : "
            f"sudo apt install {FRENCH_WORDLIST_PACKAGE}"
        ) from exc
    words = sorted({w for w in text.split() if _WORD_PATTERN.match(w)})
    if len(words) < 2048:
        raise WordlistUnavailableError(
            f"Liste de mots trop courte dans {FRENCH_WORDLIST_PATH} ({len(words)} mots)."
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
            f"Le nombre de mots doit être compris entre {MIN_PASSPHRASE_WORDS} "
            f"et {MAX_PASSPHRASE_WORDS}."
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
