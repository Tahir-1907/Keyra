#!/usr/bin/env bash
# Construit le paquet Debian de Mon Coffre-Fort : dist/mon-coffre-fort_<version>_all.deb
#
# Dépendances Python fournies par Debian 13 (apt), aucune bibliothèque embarquée :
#   python3-pyside6.*   interface (6.8)
#   python3-cryptography AES-256-GCM, HKDF (43 : sans Argon2id)
#   python3-argon2       Argon2id (libargon2, implémentation de référence)
#   python3-pikepdf      chiffrement AES-256 des copies papier PDF (qpdf)
#
# Usage : packaging/build-deb.sh            (aucun droit root nécessaire)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT_DIR="$(pwd)"

PACKAGE="mon-coffre-fort"
APP_VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' app/__init__.py)"
# Préversion : « 1.7.0-rc1 » (application) -> « 1.7.0~rc1 » (Debian), pour que la
# version finale 1.7.0 soit bien plus récente. Une version finale (1.6.0) est inchangée.
VERSION="$(printf '%s' "$APP_VERSION" | sed -E 's/-(alpha|beta|rc)/~\1/')"
MAINTAINER="${DEB_MAINTAINER:-Tahir <tahir@localhost>}"
STAGE="build/deb/${PACKAGE}_${VERSION}_all"
OUTPUT="dist/${PACKAGE}_${VERSION}_all.deb"

for tool in dpkg-deb fakeroot gzip; do
    command -v "$tool" >/dev/null || { echo "Outil manquant : $tool" >&2; exit 1; }
done

echo "==> Construction de ${PACKAGE} ${VERSION}"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/$PACKAGE" \
         "$STAGE/usr/share/applications" "$STAGE/usr/share/doc/$PACKAGE"

# --- Code de l'application (sans tests, caches ni fichiers de développement) -------
cp -r app "$STAGE/usr/lib/$PACKAGE/"
find "$STAGE/usr/lib/$PACKAGE" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +

# --- Lanceur ---------------------------------------------------------------------------
# « python3 -I » (mode isolé) : ni PYTHONPATH, ni le dossier personnel de
# l'utilisateur ne peuvent injecter de module dans le gestionnaire de mots de passe.
cat > "$STAGE/usr/bin/$PACKAGE" <<'LAUNCHER'
#!/bin/sh
# Lanceur de Mon Coffre-Fort (paquet Debian).
exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/mon-coffre-fort"); sys.argv[0] = "mon-coffre-fort"; from app.main import main; sys.exit(main())' "$@"
LAUNCHER

# --- Intégration au bureau : lanceur et icônes (logo, tailles hicolor) ------------------
cp packaging/mon-coffre-fort.desktop "$STAGE/usr/share/applications/"
for size in 16 24 32 48 64 128 256 512; do
    dest="$STAGE/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$dest"
    cp "app/resources/icons/logo-${size}.png" "$dest/$PACKAGE.png"
done

# --- Documentation Debian ----------------------------------------------------------------
DOC="$STAGE/usr/share/doc/$PACKAGE"
gzip -9n -c README.md > "$DOC/README.md.gz"
cat > "$DOC/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Mon Coffre-Fort
Upstream-Contact: ${MAINTAINER}

Files: *
Copyright: 2026 Tahir
License: tous-droits-reserves

Files: usr/lib/mon-coffre-fort/app/resources/fonts/*
Copyright: 2016 The Inter Project Authors (https://github.com/rsms/inter)
License: OFL-1.1
 Texte complet : usr/lib/mon-coffre-fort/app/resources/fonts/LICENSE-Inter.txt

Files: usr/lib/mon-coffre-fort/app/resources/lucide/*
Copyright: Lucide Contributors 2022 ; portions Cole Bemis 2013-2022 (Feather, MIT)
License: ISC
 Texte complet : usr/lib/mon-coffre-fort/app/resources/lucide/LICENSE-Lucide.txt

License: tous-droits-reserves
$(sed 's/^$/./; s/^/ /' LICENSE)
COPYRIGHT
{
    echo "${PACKAGE} (${VERSION}) unstable; urgency=medium"
    echo
    echo "  * Version ${VERSION} : métadonnées chiffrées (schéma v4), tags, mise à"
    echo "    niveau des coffres 1.x après confirmation, sauvegarde chiffrée préalable."
    echo "  * 1.6.0 : clé de récupération enregistrable en PDF protégé"
    echo "    (AES-256, mot de passe fort exigé) ; titres des PDF de nouveau"
    echo "    visibles ; PDF chiffrés vérifiés avant écriture."
    echo "  * 1.5.0 : copie papier PDF protégée par mot de passe"
    echo "    (AES-256, via python3-pikepdf) ; mot de passe distinct du mot de passe"
    echo "    maître exigé."
    echo "  * 1.4.0 : copie papier (PDF) de tous les comptes, depuis la page"
    echo "    Sauvegardes (mot de passe maître exigé, fichier 0600)."
    echo "  * 1.3.0 : suppression des sauvegardes (une, automatiques,"
    echo "    toutes) depuis la page Sauvegardes ; deux sauvegardes de la même"
    echo "    seconde ne s'écrasent plus."
    echo "  * 1.2.1 : les textes des états vides ne sont plus coupés."
    echo "  * 1.2.0 : clé de récupération (facultative) en cas d'oubli"
    echo "    du mot de passe maître : seconde enveloppe Argon2id + AES-256-GCM de la"
    echo "    clé de données, affichée une seule fois, renouvelée après usage ;"
    echo "    schéma de coffre v3 (migration automatique avec copie de sécurité)."
    echo "  * 1.1.4 : générateur — la valeur ne sort plus de son cadre"
    echo "    quand le curseur bouge vite ; mots de passe longs (128) et phrases de"
    echo "    passe (12 mots) affichés en entier, sur plusieurs lignes."
    echo "  * 1.1.3 : la fenêtre s'accroche sur une moitié d'écran"
    echo "    (Super+Gauche/Droite sous GNOME) ; mise en page compacte sous"
    echo "    1180 px (barre latérale en icônes), vues réorganisées en largeur réduite."
    echo "  * 1.1.2 : les valeurs longues passent à la ligne dans le panneau de détail."
    echo "  * 1.1.1 : boutons « Afficher » et « Copier » libellés sur les champs secrets."
    echo "  * 1.1.0 : refonte complète de l'interface (design system,"
    echo "    barre latérale, tableau de bord, centre de sécurité, historique en"
    echo "    timeline, animations directionnelles, modales et notifications)."
    echo "  * 1.0.0 : coffres chiffrés (Argon2id + AES-256-GCM), générateur,"
    echo "    presse-papiers sécurisé, verrouillage automatique, audit, historique,"
    echo "    corbeille, import/export, sauvegardes chiffrées, coffres multiples."
    echo
    echo " -- ${MAINTAINER}  $(LC_ALL=C date -R)"
} | gzip -9n > "$DOC/changelog.Debian.gz"

# --- Scripts de maintenance ----------------------------------------------------------------
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    # Précompilation Python (sinon faite à chaque lancement, le dossier n'étant pas inscriptible).
    python3 -m compileall -q /usr/lib/mon-coffre-fort/app >/dev/null 2>&1 || true
fi
POSTINST
cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
# Les coffres de l'utilisateur (~/.local/share/mon-coffre) ne sont JAMAIS supprimés.
find /usr/lib/mon-coffre-fort -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
PRERM

# --- Permissions ------------------------------------------------------------------------------
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/$PACKAGE" "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

# --- Métadonnées -----------------------------------------------------------------------------
INSTALLED_SIZE="$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: ${PACKAGE}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: all
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: python3 (>= 3.11), python3-cryptography (>= 43), python3-argon2 (>= 21.1), python3-pyside6.qtcore (>= 6.8), python3-pyside6.qtgui (>= 6.8), python3-pyside6.qtwidgets (>= 6.8), python3-pyside6.qtnetwork (>= 6.8), python3-pyside6.qtdbus (>= 6.8), python3-pyside6.qtsvg (>= 6.8), python3-pikepdf (>= 9.5), hicolor-icon-theme
Recommends: wfrench, wamerican, qt6-wayland
Description: gestionnaire de mots de passe local, hors ligne et chiffré
 Mon Coffre-Fort conserve vos mots de passe, notes sécurisées, cartes et
 identités dans des coffres chiffrés sur votre ordinateur, sans aucun
 service en ligne.
 .
 Chiffrement en enveloppe : Argon2id (mot de passe maître) et AES-256-GCM.
 Générateur de mots de passe et de phrases de passe, presse-papiers à
 effacement automatique, verrouillage automatique (inactivité, verrouillage
 de session, veille), audit de sécurité, historique des modifications,
 corbeille, import (Bitwarden, KeePassXC, Chrome, Firefox) et export,
 sauvegardes chiffrées (en-tête technique lisible), coffres multiples, clé
 de récupération.
CONTROL
(cd "$STAGE" && find usr -type f -exec md5sum {} + | sort -k2) > "$STAGE/DEBIAN/md5sums"
chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums"

# --- Construction -------------------------------------------------------------------------------
mkdir -p dist
fakeroot dpkg-deb --build -Zxz --root-owner-group "$STAGE" "$OUTPUT" >/dev/null
echo "==> Paquet créé : $ROOT_DIR/$OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
