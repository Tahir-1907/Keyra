#!/usr/bin/env bash
# Builds the Keyra Debian package: dist/mon-coffre-fort_<version>_all.deb
# (the technical package name stays "mon-coffre-fort" so existing installs upgrade).
#
# Python dependencies provided by Debian 13 (apt), no bundled library:
#   python3-pyside6.*   user interface (6.8)
#   python3-cryptography AES-256-GCM, HKDF (43: without Argon2id)
#   python3-argon2       Argon2id (libargon2, reference implementation)
#   python3-pikepdf      AES-256 encryption of the PDF paper copies (qpdf)
#
# Usage: packaging/build-deb.sh            (no root privileges needed)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT_DIR="$(pwd)"

PACKAGE="mon-coffre-fort"
APP_VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' app/__init__.py)"
# Pre-release: "1.7.0-rc1" (application) -> "1.7.0~rc1" (Debian), so that the final
# 1.7.0 version sorts as newer. A final version (1.6.0) is left unchanged.
VERSION="$(printf '%s' "$APP_VERSION" | sed -E 's/-(alpha|beta|rc)/~\1/')"
MAINTAINER="${DEB_MAINTAINER:-Keyra Maintainers <maintainers@keyra.invalid>}"
STAGE="build/deb/${PACKAGE}_${VERSION}_all"
OUTPUT="dist/${PACKAGE}_${VERSION}_all.deb"

for tool in dpkg-deb fakeroot gzip; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

echo "==> Building ${PACKAGE} ${VERSION}"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/$PACKAGE" \
         "$STAGE/usr/share/applications" "$STAGE/usr/share/doc/$PACKAGE"

# --- Application code (without tests, caches or development files) ----------------
cp -r app "$STAGE/usr/lib/$PACKAGE/"
find "$STAGE/usr/lib/$PACKAGE" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +

# --- Launcher --------------------------------------------------------------------------
# "python3 -I" (isolated mode): neither PYTHONPATH nor the user's home folder can
# inject a module into the password manager.
cat > "$STAGE/usr/bin/$PACKAGE" <<'LAUNCHER'
#!/bin/sh
# Keyra launcher (Debian package).
exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/mon-coffre-fort"); sys.argv[0] = "mon-coffre-fort"; from app.main import main; sys.exit(main())' "$@"
LAUNCHER

# --- Desktop integration: launcher and icons (logo, hicolor sizes) ----------------------
cp packaging/mon-coffre-fort.desktop "$STAGE/usr/share/applications/"
for size in 16 24 32 48 64 128 256 512; do
    dest="$STAGE/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$dest"
    cp "app/resources/icons/logo-${size}.png" "$dest/$PACKAGE.png"
done

# --- Debian documentation ----------------------------------------------------------------
DOC="$STAGE/usr/share/doc/$PACKAGE"
gzip -9n -c README.md > "$DOC/README.md.gz"
cat > "$DOC/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Keyra
Upstream-Contact: https://github.com/Tahir-1907/Keyra

Files: *
Copyright: 2026 Tahir
License: all-rights-reserved

Files: usr/lib/mon-coffre-fort/app/resources/fonts/*
Copyright: 2016 The Inter Project Authors (https://github.com/rsms/inter)
License: OFL-1.1
 Full text: usr/lib/mon-coffre-fort/app/resources/fonts/LICENSE-Inter.txt

Files: usr/lib/mon-coffre-fort/app/resources/lucide/*
Copyright: Lucide Contributors 2022; portions Cole Bemis 2013-2022 (Feather, MIT)
License: ISC
 Full text: usr/lib/mon-coffre-fort/app/resources/lucide/LICENSE-Lucide.txt

License: all-rights-reserved
$(sed 's/^$/./; s/^/ /' LICENSE)
COPYRIGHT
{
    echo "${PACKAGE} (${VERSION}) unstable; urgency=medium"
    echo
    echo "  * Version ${VERSION}: public name Keyra and English interface; encrypted"
    echo "    metadata (schema v4), tags, upgrade of 1.x vaults after confirmation,"
    echo "    encrypted backup beforehand."
    echo "  * 1.6.0: recovery key can be saved as a protected PDF"
    echo "    (AES-256, strong password required); PDF titles visible"
    echo "    again; encrypted PDFs verified before writing."
    echo "  * 1.5.0: password-protected PDF paper copy"
    echo "    (AES-256, via python3-pikepdf); a password different from the master"
    echo "    password is required."
    echo "  * 1.4.0: paper copy (PDF) of all accounts, from the Backups page"
    echo "    (master password required, file mode 0600)."
    echo "  * 1.3.0: deleting backups (one, automatic ones, all) from the"
    echo "    Backups page; two backups made in the same second no longer"
    echo "    overwrite each other."
    echo "  * 1.2.1: empty-state texts are no longer cut off."
    echo "  * 1.2.0: optional recovery key in case the master password is"
    echo "    forgotten: second Argon2id + AES-256-GCM envelope of the data key,"
    echo "    shown only once, renewed after use; vault schema v3 (automatic"
    echo "    migration with a safety copy)."
    echo "  * 1.1.4: generator — the value no longer overflows its frame when"
    echo "    the slider moves fast; long passwords (128) and passphrases"
    echo "    (12 words) shown in full, on several lines."
    echo "  * 1.1.3: the window snaps to half of the screen"
    echo "    (Super+Left/Right on GNOME); compact layout below 1180 px"
    echo "    (icon-only sidebar), views rearranged at reduced width."
    echo "  * 1.1.2: long values wrap in the detail panel."
    echo "  * 1.1.1: labeled \"Show\" and \"Copy\" buttons on secret fields."
    echo "  * 1.1.0: complete redesign of the interface (design system,"
    echo "    sidebar, dashboard, security center, timeline history,"
    echo "    directional animations, dialogs and notifications)."
    echo "  * 1.0.0: encrypted vaults (Argon2id + AES-256-GCM), generator,"
    echo "    secure clipboard, automatic locking, audit, history, trash,"
    echo "    import/export, encrypted backups, multiple vaults."
    echo
    echo " -- ${MAINTAINER}  $(LC_ALL=C date -R)"
} | gzip -9n > "$DOC/changelog.Debian.gz"

# --- Maintainer scripts ------------------------------------------------------------------
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    # Python precompilation (otherwise done at every start, as the folder is not writable).
    python3 -m compileall -q /usr/lib/mon-coffre-fort/app >/dev/null 2>&1 || true
fi
POSTINST
cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
# The user's vaults (~/.local/share/mon-coffre) are NEVER deleted.
find /usr/lib/mon-coffre-fort -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
PRERM

# --- Permissions ------------------------------------------------------------------------------
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/$PACKAGE" "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

# --- Metadata ----------------------------------------------------------------------------------
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
Description: local, offline, encrypted password manager
 Keyra keeps your passwords, secure notes, cards and identities in
 encrypted vaults on your computer, without any online service.
 .
 Envelope encryption: Argon2id (master password) and AES-256-GCM.
 Password and passphrase generator, clipboard with automatic clearing,
 automatic locking (inactivity, session lock, sleep), security audit,
 change history, trash, import (Bitwarden, KeePassXC, Chrome, Firefox)
 and export, encrypted backups (readable technical header), multiple
 vaults, recovery key.
CONTROL
(cd "$STAGE" && find usr -type f -exec md5sum {} + | sort -k2) > "$STAGE/DEBIAN/md5sums"
chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums"

# --- Build -------------------------------------------------------------------------------------
mkdir -p dist
fakeroot dpkg-deb --build -Zxz --root-owner-group "$STAGE" "$OUTPUT" >/dev/null
echo "==> Package created: $ROOT_DIR/$OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
