# Keyra — visual identity

## Symbol: "the core"

A rounded enclosure (the vault) surrounds a solid core pierced by a keyhole (the
secrets). The idea: *secrets are kept inside a protected core.* The symbol uses only
simple geometry (rounded square, circle, keyhole) so that it stays recognizable at
16 × 16 px and does not rely on a padlock or shield.

| Variant | File | Use |
|---|---|---|
| App icon (tile) | `docs/brand/logo.svg` → `app/resources/icons/logo-*.png`, `logo.png` | Window, taskbar, desktop menu, `.deb` hicolor icons |
| Symbol only (transparent) | `app/resources/icons/logo-mark.svg` | Inside the interface: sidebar, lock and welcome screens, About dialog |
| Monochrome | `docs/brand/logo-monochrome.svg` | Single-color uses (print, embossing); black, recolor as needed |
| Horizontal | `docs/brand/logo-horizontal-dark.svg`, `logo-horizontal-light.svg` | README header on dark / light backgrounds: symbol + "Keyra" wordmark (text converted to paths) |

The tile keeps the symbol readable on both light and dark desktops. Inside the
application, which is always dark, the transparent symbol is used instead.

## Small sizes

`logo-16.png`, `logo-24.png` and `logo-32.png` are not downscaled from the master: they
use their own pixel-aligned geometry (thicker enclosure, integer edges). The keyhole is
dropped at 16 and 24 px, where it would only be a blur; at 32 px it is drawn on the pixel
grid. Sizes 48 px and above are rendered from the master SVG.

## Colors

Taken from the application theme (`app/ui/theme.py`); the identity does not add colors.

| Role | Value | Theme name |
|---|---|---|
| Tile | `#0F1621` | `SURFACE` |
| Tile edge | `#1D2938` | `BORDER` |
| Enclosure | `#10B981` | `ACCENT` |
| Core | `#34D399` | `ACCENT_2` |
| Wordmark on dark | `#F1F5F9` | `TEXT` |
| Wordmark on light | `#0B1018` | `BG_2` |

Wordmark typeface: Inter Display Bold (bundled, SIL Open Font License 1.1).

## Brand icon ≠ UI icons

The logo identifies the application. Functional icons (buttons, navigation, states)
remain the Lucide set in `app/resources/lucide/`. The lock screen shows the logo while
locked and briefly switches to Lucide's open padlock when unlocking succeeds.

## Regenerating

All logo files are generated; do not edit the PNGs by hand.

```bash
QT_QPA_PLATFORM=offscreen python docs/brand/build_brand.py
```

The script only needs PySide6 (already a dependency) and writes the files listed above.
Its output is deterministic: running it again on an unchanged script reproduces the same
PNG files.
