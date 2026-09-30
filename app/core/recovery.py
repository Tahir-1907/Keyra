"""Format de la clé de récupération.

La clé est affichée une seule fois à l'utilisateur, qui la note sur papier.
Elle n'est jamais stockée : le coffre ne garde que la DEK enveloppée par une
clé dérivée d'elle (voir `Vault.create_recovery_key`).

Format : 32 caractères en 8 groupes de 4, alphabet base32 de Crockford
(sans I, L, O, U : pas de confusion avec 1 et 0) :

    30 caractères aléatoires (150 bits, module `secrets`)
    + 2 caractères de contrôle (10 bits de SHA-256 des 30 premiers)

Les caractères de contrôle ne protègent rien : ils servent seulement à
signaler une faute de frappe immédiatement, au lieu d'un « clé incorrecte »
après la dérivation Argon2id. 150 bits d'aléa rendent toute recherche
exhaustive impossible.
"""

from __future__ import annotations

import hashlib
import secrets

from app.core.exceptions import RecoveryKeyFormatError

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
DATA_LENGTH = 30
CHECK_LENGTH = 2
GROUP = 4
# Lectures tolérées (Crockford) : O -> 0, I et L -> 1.
_ALIASES = str.maketrans({"O": "0", "I": "1", "L": "1"})


def _check(data: str) -> str:
    digest = int.from_bytes(hashlib.sha256(data.encode("ascii")).digest()[:2], "big") >> 6
    return ALPHABET[digest >> 5] + ALPHABET[digest & 31]


def generate() -> str:
    """Nouvelle clé de récupération, formatée pour l'affichage."""
    data = "".join(secrets.choice(ALPHABET) for _ in range(DATA_LENGTH))
    return format_key(data + _check(data))


def format_key(compact: str) -> str:
    return "-".join(compact[i:i + GROUP] for i in range(0, len(compact), GROUP))


def normalize(text: str) -> str:
    """Partie secrète (30 caractères) d'une clé saisie ; tolère espaces, tirets, casse.

    Lève RecoveryKeyFormatError si la longueur, un caractère ou le contrôle
    ne correspond pas.
    """
    compact = "".join(ch for ch in text.upper() if ch not in " -\t\n\r").translate(_ALIASES)
    if len(compact) != DATA_LENGTH + CHECK_LENGTH:
        raise RecoveryKeyFormatError(
            f"Une clé de récupération compte {DATA_LENGTH + CHECK_LENGTH} caractères "
            f"({len(compact)} saisis).")
    if any(ch not in ALPHABET for ch in compact):
        raise RecoveryKeyFormatError("La clé contient un caractère invalide.")
    data, check = compact[:DATA_LENGTH], compact[DATA_LENGTH:]
    if not secrets.compare_digest(_check(data), check):
        raise RecoveryKeyFormatError("Faute de frappe probable : vérifiez la clé saisie.")
    return data
