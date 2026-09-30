"""Exceptions métier du cœur applicatif (crypto + coffre).

Avoir des exceptions dédiées permet à l'UI d'afficher des messages
clairs sans jamais exposer de détails cryptographiques internes,
et permet aux tests de vérifier précisément le comportement attendu.
"""

from __future__ import annotations


class VaultError(Exception):
    """Classe de base pour toutes les erreurs liées au coffre."""


class WrongMasterPasswordError(VaultError):
    """Le mot de passe maître fourni ne permet pas de déchiffrer le coffre."""


class VaultCorruptedError(VaultError):
    """Le fichier/la base du coffre est corrompu ou a été altéré.

    Levée notamment quand la vérification d'authenticité AES-GCM échoue
    pour une raison autre qu'un mauvais mot de passe (ex: octets tronqués,
    fichier modifié par un tiers).
    """


class UnsupportedVaultVersionError(VaultError):
    """Le format du coffre est d'une version que cette application ne sait pas lire."""


class VaultMigrationRequiredError(VaultError):
    """Coffre d'un ancien format (v1 à v3) : il doit être mis à niveau vers v4 avant usage.

    Levée AVANT toute modification : le fichier du coffre n'est pas touché.
    """


class VaultAlreadyExistsError(VaultError):
    """Un coffre portant ce nom/identifiant existe déjà."""


class VaultNotFoundError(VaultError):
    """Le coffre demandé est introuvable."""


class VaultLockedError(VaultError):
    """Tentative d'accéder aux données d'un coffre verrouillé."""


class InvalidMasterPasswordPolicyError(VaultError):
    """Le mot de passe maître fourni ne respecte pas la politique minimale."""


class RecoveryKeyError(VaultError):
    """Clé de récupération incorrecte pour ce coffre."""


class RecoveryKeyFormatError(RecoveryKeyError):
    """Texte saisi qui ne peut pas être une clé de récupération (faute de frappe)."""


class NoRecoveryKeyError(VaultError):
    """Le coffre n'a pas de clé de récupération."""


class EntryError(VaultError):
    """Erreur générique liée aux entrées du coffre."""


class EntryNotFoundError(EntryError):
    """L'entrée demandée n'existe pas (ou plus)."""


class EntryValidationError(EntryError):
    """Les données d'une entrée sont invalides (champ obligatoire manquant...)."""


class EntryDecryptionError(EntryError):
    """Un champ chiffré d'une entrée n'a pas pu être authentifié/déchiffré.

    Indique une altération du fichier du coffre (ou le déplacement d'un blob
    chiffré d'une entrée/d'un champ vers un autre, détecté grâce à la donnée
    associée AES-GCM).
    """


class CategoryError(VaultError):
    """Erreur liée aux catégories (nom vide, doublon, catégorie intégrée...)."""


class CategoryDecryptionError(CategoryError):
    """Le nom chiffré d'une catégorie n'a pas pu être authentifié/déchiffré (altération)."""
