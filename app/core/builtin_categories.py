"""Catégories intégrées : correspondance explicite clé technique ↔ nom affiché.

Source unique (app.core.categories en dérive BUILTIN_CATEGORIES, le schéma v4
sa contrainte CHECK). Module sans dépendance, importable depuis la couche
base de données sans import circulaire.

En v4, une catégorie intégrée n'est identifiée QUE par sa clé technique
(`categories.builtin_key`, en clair) : ces clés sont génériques et
identiques dans tous les coffres, elles ne révèlent donc rien. Le nom est
fourni par le code. Les catégories personnelles, elles, ont un nom chiffré
et jamais de clé : on ne déduit JAMAIS qu'une catégorie est intégrée à
partir de son nom.
"""

from __future__ import annotations

# Ordre = ordre d'affichage. Clés : ASCII, stables, à ne jamais renommer.
BUILTIN_CATEGORY_NAMES: dict[str, str] = {
    "personal": "Personnel",
    "work": "Travail",
    "finance": "Finances",
    "social": "Réseaux sociaux",
    "email": "Courriel",
    "shopping": "Achats",
}
BUILTIN_CATEGORY_KEYS: tuple[str, ...] = tuple(BUILTIN_CATEGORY_NAMES)


def builtin_name(key: str) -> str:
    """Nom affiché d'une catégorie intégrée ; KeyError si la clé est inconnue."""
    return BUILTIN_CATEGORY_NAMES[key]


def builtin_key_for_v3_row(name: str, is_builtin: bool) -> str | None:
    """Clé d'une catégorie d'un coffre v3 (migration uniquement).

    Seule une ligne marquée intégrée (`is_builtin = 1`) reçoit une clé, d'après
    son nom en clair v3. Une catégorie personnelle qui porterait le même nom
    qu'une catégorie intégrée RESTE personnelle. Une ligne marquée intégrée au
    nom inconnu est incohérente : ValueError (jamais de choix silencieux).
    """
    if not is_builtin:
        return None
    for key, builtin in BUILTIN_CATEGORY_NAMES.items():
        if builtin == name:
            return key
    raise ValueError("Catégorie intégrée inconnue dans ce coffre.")
