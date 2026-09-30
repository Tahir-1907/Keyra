"""Generates the Keyra visual identity: source SVGs and PNG icons.

"The core" symbol: a rounded enclosure (the vault) protects a central core
pierced by a keyhole (the secrets). Everything is computed here from a few
parameters: no image is drawn by hand or downloaded.

    python docs/brand/build_brand.py

Writes:
  * docs/brand/logo.svg              — master (tile), source of logo-48…512 and logo.png
  * docs/brand/logo-monochrome.svg   — symbol only, one color (black, recolorable)
  * docs/brand/logo-horizontal-*.svg — symbol + name (text as paths, Inter typeface)
  * app/resources/icons/logo-mark.svg — transparent symbol shown in the interface
  * app/resources/icons/logo-{16…512}.png, logo.png (1024 px) — application icon

Small sizes (16, 24, 32 px): geometry aligned on the pixel grid and simplified
(no keyhole at 16 px), to stay sharp rather than merely scaled down.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import (
    QFont,
    QFontDatabase,
    QGuiApplication,
    QImage,
    QPainter,
    QPainterPath,
)
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parents[2]
BRAND_DIR = ROOT / "docs" / "brand"
ICONS_DIR = ROOT / "app" / "resources" / "icons"
FONT = ROOT / "app" / "resources" / "fonts" / "InterDisplay-Bold.otf"

# Application palette (app/ui/theme.py).
TILE = "#0F1621"         # SURFACE
TILE_EDGE = "#1D2938"    # BORDER
ENCLOSURE = "#10B981"    # ACCENT
CORE = "#34D399"         # ACCENT_2
TEXT_ON_DARK = "#F1F5F9"
TEXT_ON_LIGHT = "#0B1018"

PNG_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
MASTER_PNG_SIZE = 1024


def _n(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _circle(cx: float, cy: float, r: float) -> str:
    return (f"M{_n(cx - r)} {_n(cy)}A{_n(r)} {_n(r)} 0 1 0 {_n(cx + r)} {_n(cy)}"
            f"A{_n(r)} {_n(r)} 0 1 0 {_n(cx - r)} {_n(cy)}Z")


def _keyhole(cx: float, top_cy: float, r: float, stem_top: float, stem_bottom: float,
             bottom_y: float) -> str:
    """Single outline of a keyhole: round head + stem widening towards the bottom."""
    dy = math.sqrt(r * r - stem_top * stem_top)
    y = top_cy + dy
    return (f"M{_n(cx - stem_bottom)} {_n(bottom_y)}L{_n(cx - stem_top)} {_n(y)}"
            f"A{_n(r)} {_n(r)} 0 1 1 {_n(cx + stem_top)} {_n(y)}"
            f"L{_n(cx + stem_bottom)} {_n(bottom_y)}Z")


def symbol(grid: int, keyhole: bool, enclosure: str, core: str,
           small: dict | None = None) -> str:
    """Enclosure + core in a `grid`-unit frame; `small`: pixel-aligned geometry."""
    g = grid
    s = small
    parts = []
    # Enclosure: stroked rounded square (thick outline).
    outer, stroke, radius = 0.172 * g, 0.078 * g, 0.141 * g
    if s:  # pixel-aligned geometry for small sizes
        outer, stroke, radius = s["outer"], s["stroke"], s["radius"]
    half = stroke / 2
    size = g - 2 * outer - stroke
    parts.append(f'<rect x="{_n(outer + half)}" y="{_n(outer + half)}" width="{_n(size)}" '
                 f'height="{_n(size)}" rx="{_n(radius)}" fill="none" stroke="{enclosure}" '
                 f'stroke-width="{_n(stroke)}"/>')
    # Core: solid disc pierced by a keyhole (evenodd rule = real hole).
    c = g / 2
    core_r = s["core"] if s else 0.156 * g
    d = _circle(c, c, core_r)
    if keyhole and s:  # keyhole drawn for the grid: (head center, radius, stem, bottom)
        head_y, head_r, stem, bottom = s["keyhole"]
        d += _keyhole(c, head_y, head_r, stem, stem, bottom)
    elif keyhole:
        k = core_r / 80  # proportions defined for a core of radius 80
        d += _keyhole(c, c - 18 * k, 26 * k, 11 * k, 20 * k, c + 58 * k)
    parts.append(f'<path d="{d}" fill="{core}" fill-rule="evenodd"/>')
    return "".join(parts)


# Small sizes: integer or half-integer values => sharp edges.
SMALL = {
    16: {"outer": 2, "stroke": 2, "radius": 2.5, "core": 2, "keyhole": None},
    24: {"outer": 3, "stroke": 3, "radius": 4, "core": 4, "keyhole": None},
    32: {"outer": 5, "stroke": 3, "radius": 4.5, "core": 6, "keyhole": (15, 2, 1, 20)},
}


def tile_svg(grid: int = 512, small: dict | None = None) -> str:
    g = grid
    inset = 0.5 if small else 16
    radius = {16: 3.5, 24: 5, 32: 7}.get(g, 112) if small else 112
    edge = "" if small else (f'<rect x="20" y="20" width="472" height="472" rx="108" '
                             f'fill="none" stroke="{TILE_EDGE}" stroke-width="8"/>')
    body = symbol(g, bool(small["keyhole"]) if small else True, ENCLOSURE, CORE, small)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {g} {g}" '
            f'width="{g}" height="{g}">'
            f'<rect x="{_n(inset)}" y="{_n(inset)}" width="{_n(g - 2 * inset)}" '
            f'height="{_n(g - 2 * inset)}" rx="{_n(radius)}" fill="{TILE}"/>'
            f"{edge}{body}</svg>\n")


def mark_svg(enclosure: str = ENCLOSURE, core: str = CORE) -> str:
    """Symbol only, transparent background, cropped tightly around the enclosure."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="80 80 352 352" '
            'width="352" height="352">' + symbol(512, True, enclosure, core) + "</svg>\n")


def _path_to_svg(path: QPainterPath) -> str:
    out, i = [], 0
    while i < path.elementCount():
        e = path.elementAt(i)
        if e.isMoveTo():
            out.append(f"M{_n(e.x)} {_n(e.y)}")
        elif e.isLineTo():
            out.append(f"L{_n(e.x)} {_n(e.y)}")
        else:  # CurveTo followed by its two control points
            c2, end = path.elementAt(i + 1), path.elementAt(i + 2)
            out.append(f"C{_n(e.x)} {_n(e.y)} {_n(c2.x)} {_n(c2.y)} {_n(end.x)} {_n(end.y)}")
            i += 2
        i += 1
    return "".join(out) + "Z"


def horizontal_svg(text_color: str) -> str:
    """128 px tile + "Keyra" as vector paths (no font needed to display it)."""
    family = QFontDatabase.applicationFontFamilies(
        QFontDatabase.addApplicationFont(str(FONT)))[0]
    font = QFont(family)
    font.setPixelSize(64)
    text = QPainterPath()
    text.addText(0, 0, font, "Keyra")
    box = text.boundingRect()
    gap, h = 36, 128
    dx, dy = h + gap - box.left(), h / 2 - (box.top() + box.height() / 2)
    text.translate(dx, dy)
    width = math.ceil(h + gap + box.width() + 4)
    tile = tile_svg().split(">", 1)[1].rsplit("</svg>", 1)[0]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {h}" '
            f'width="{width}" height="{h}"><g transform="scale(0.25)">{tile}</g>'
            f'<path d="{_path_to_svg(text)}" fill="{text_color}"/></svg>\n')


def render_png(svg: str, size: int, destination: Path) -> None:
    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    QSvgRenderer(QByteArray(svg.encode("utf-8"))).render(painter, QRectF(0, 0, size, size))
    painter.end()
    if not image.save(str(destination), "PNG"):
        raise OSError(f"cannot write: {destination}")


def main() -> int:
    _app = QGuiApplication(sys.argv)
    BRAND_DIR.mkdir(parents=True, exist_ok=True)
    master = tile_svg()
    outputs = {
        BRAND_DIR / "logo.svg": master,
        BRAND_DIR / "logo-monochrome.svg": mark_svg("#000000", "#000000"),
        BRAND_DIR / "logo-horizontal-dark.svg": horizontal_svg(TEXT_ON_DARK),
        BRAND_DIR / "logo-horizontal-light.svg": horizontal_svg(TEXT_ON_LIGHT),
        ICONS_DIR / "logo-mark.svg": mark_svg(),
    }
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
    for size in PNG_SIZES:
        svg = tile_svg(size, SMALL[size]) if size in SMALL else master
        render_png(svg, size, ICONS_DIR / f"logo-{size}.png")
    render_png(master, MASTER_PNG_SIZE, ICONS_DIR / "logo.png")
    print(f"{len(outputs)} SVG and {len(PNG_SIZES) + 1} PNG files written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
