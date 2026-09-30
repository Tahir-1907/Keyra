"""Icônes Lucide (https://lucide.dev, licence ISC — resources/lucide/LICENSE-Lucide.txt).

Un seul style d'icônes dans toute l'application. Les SVG (version figée
0.460.0) sont colorés à la volée (`currentColor` remplacé) et rendus en
haute définition ; résultats mis en cache.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from app.ui import theme

_DIR = Path(__file__).resolve().parent.parent / "resources" / "lucide"


@cache
def _svg(name: str) -> str:
    return (_DIR / f"{name}.svg").read_text(encoding="utf-8")


@cache
def pixmap(name: str, color: str = theme.TEXT_2, size: int = 18,
           stroke: float = 1.9, ratio: float = 2.0) -> QPixmap:
    svg = (_svg(name).replace("currentColor", color)
           .replace('stroke-width="2"', f'stroke-width="{stroke}"'))
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    px = QPixmap(int(size * ratio), int(size * ratio))
    px.fill(Qt.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size * ratio, size * ratio))
    painter.end()
    px.setDevicePixelRatio(ratio)
    return px


@cache
def icon(name: str, color: str = theme.TEXT_2, size: int = 18) -> QIcon:
    result = QIcon(pixmap(name, color, size))
    return result


def available() -> tuple[str, ...]:
    return tuple(sorted(p.stem for p in _DIR.glob("*.svg")))
