"""Password strength estimation (offline).

Approach inspired by zxcvbn, deliberately simple and dependency-free: the
password is split from left to right into predictable patterns (common
password, dictionary word possibly in "leet", year, repetition, sequence,
keyboard row), each costing an attacker only a few bits, and the rest is
counted as random characters from the alphabet in use. The result is an
**estimate** of the effective entropy, not a guarantee: a randomly generated
password remains the only way to be sure.

Dictionaries used when present: /usr/share/dict/french (package `wfrench`)
and /usr/share/dict/american-english (`wamerican`). Without them, only the
built-in detection of common passwords below applies (the estimate is then
more optimistic).

No evaluated value is logged or kept.
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DICTIONARY_PATHS = (
    Path("/usr/share/dict/french"),
    Path("/usr/share/dict/american-english"),
)

# Some of the most widespread passwords (public breach lists):
# an attacker would try them first.
COMMON_PASSWORDS = frozenset(
    """
    password motdepasse azerty qwerty qwertz azertyuiop qwertyuiop 123456 1234567
    12345678 123456789 1234567890 000000 111111 123123 654321 abc123 password1
    iloveyou jetaime soleil bonjour doudou chouchou marseille loulou coucou
    admin administrator root toor letmein welcome monkey dragon master sunshine
    princess football baseball superman batman trustno1 passw0rd changeme secret
    motdepass nicolas camille julien thomas chocolat
    """.split()  # noqa: SIM905 - a block of words reads better than a list literal
)

KEYBOARD_ROWS = (
    "azertyuiop", "qsdfghjklm", "wxcvbn",      # AZERTY
    "qwertyuiop", "asdfghjkl", "zxcvbnm",      # QWERTY
    "1234567890", "&é\"'(-è_çà",
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                       "7": "t", "@": "a", "$": "s", "!": "i", "8": "b"})

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
_SCORE_THRESHOLDS = (28, 40, 60, 80)  # bits: <28 => 0, <40 => 1, ...


@dataclass(frozen=True, slots=True)
class StrengthResult:
    score: int            # 0 (very weak) to 4 (very strong)
    entropy_bits: float   # estimate of the effective entropy
    label: str
    warnings: tuple[str, ...]


def _strip_accents(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


@lru_cache(maxsize=1)
def _dictionary() -> frozenset[str]:
    words: set[str] = set()
    for path in DICTIONARY_PATHS:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for word in text.split():
            w = _strip_accents(word).lower()
            if 4 <= len(w) <= 16 and w.isalpha():
                words.add(w)
    return frozenset(words)


def dictionary_available() -> bool:
    return bool(_dictionary())


def _pool_size(password: str) -> int:
    pool = 0
    if any(c.islower() and c.isascii() for c in password):
        pool += 26
    if any(c.isupper() and c.isascii() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() and c.isascii() for c in password):
        pool += 33
    if any(not c.isascii() for c in password):
        pool += 100
    return max(pool, 1)


def _run_length(s: str, i: int, step_ok) -> int:
    j = i + 1
    while j < len(s) and step_ok(s[j - 1], s[j]):
        j += 1
    return j - i


def _keyboard_run(lower: str, i: int) -> int:
    best = 0
    for row in KEYBOARD_ROWS:
        for seq in (row, row[::-1]):
            for length in range(min(len(seq), len(lower) - i), 3, -1):
                if lower[i : i + length] in seq:
                    best = max(best, length)
                    break
    return best


def score_for_bits(bits: float) -> int:
    return sum(bits >= threshold for threshold in _SCORE_THRESHOLDS)


def estimate_strength(password: str) -> StrengthResult:
    if not password:
        return StrengthResult(0, 0.0, LABELS[0], ("Empty password.",))

    pool_bits = math.log2(_pool_size(password))
    lower = _strip_accents(password).lower()
    unleet = lower.translate(_LEET)
    dictionary = _dictionary()
    warnings: list[str] = []

    if unleet in COMMON_PASSWORDS or lower in COMMON_PASSWORDS:
        return StrengthResult(0, math.log2(len(COMMON_PASSWORDS)), LABELS[0],
                              ("This password is one of the most used in the world.",))

    bits = 0.0
    i = 0
    n = len(password)
    while i < n:
        candidates: list[tuple[int, float, str]] = []  # (length, cost, warning)

        repeat = _run_length(lower, i, lambda a, b: a == b)
        if repeat >= 3:
            candidates.append((repeat, pool_bits + math.log2(repeat),
                               "Avoid repeated characters (aaa, 111…)."))

        for step in (1, -1):
            seq = _run_length(lower, i, lambda a, b, s=step: ord(b) - ord(a) == s)
            if seq >= 3:
                candidates.append((seq, pool_bits + math.log2(seq) + 1,
                                   "Avoid sequences (abc, 123, 987…)."))

        kb = _keyboard_run(lower, i)
        if kb >= 4:
            candidates.append((kb, pool_bits + math.log2(kb) + 2,
                               "Avoid keyboard patterns (qwerty, asdf…)."))

        if password[i : i + 4].isdigit() and password[i : i + 2] in ("19", "20"):
            candidates.append((4, math.log2(150), "Avoid years (dates of birth…)."))

        for length in range(min(16, n - i), 3, -1):
            fragment = unleet[i : i + length]
            if fragment in COMMON_PASSWORDS or fragment in dictionary:
                cost = math.log2(max(len(dictionary), len(COMMON_PASSWORDS)))
                if fragment in COMMON_PASSWORDS:
                    cost = math.log2(len(COMMON_PASSWORDS))
                original = password[i : i + length]
                if original != original.lower():
                    cost += 1  # capitalization variants
                if unleet[i : i + length] != lower[i : i + length]:
                    cost += 1  # "leet" substitutions (p4ssw0rd)
                candidates.append((length, cost,
                                   "Avoid dictionary words, even modified ones (p4ssw0rd)."))
                break

        if candidates:
            # The pattern that covers the most characters, at the lowest cost.
            length, cost, warning = max(candidates, key=lambda c: (c[0], -c[1]))
            if cost < length * pool_bits:
                bits += cost
                if warning not in warnings:
                    warnings.append(warning)
                i += length
                continue
        bits += pool_bits
        i += 1

    if n < 12:
        warnings.append("Use at least 12 characters (16 or more recommended).")

    score = score_for_bits(bits)
    if score >= 3:
        # Strong enough: the advice is no longer useful (e.g. a generated
        # passphrase is made of dictionary words, by design).
        warnings = []
    return StrengthResult(score, bits, LABELS[score], tuple(warnings))
