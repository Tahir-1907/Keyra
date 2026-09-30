"""Application icon (logo, app/resources/icons/): windows and desktop launcher.

Brand ≠ interface icons: the logo (PNG tile for the system, `logo-mark.svg`
symbol inside the interface) is produced by docs/brand/build_brand.py; the
functional icons remain the Lucide icons (app/ui/lucide.py).
"""

from __future__ import annotations

from functools import cache, lru_cache
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

ICONS_DIR = Path(__file__).resolve().parent.parent / "resources" / "icons"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
BRAND_MARK = ICONS_DIR / "logo-mark.svg"


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    """Multi-resolution icon: Qt picks the size that fits the context."""
    icon = QIcon()
    for size in ICON_SIZES:
        path = ICONS_DIR / f"logo-{size}.png"
        if path.is_file():
            icon.addFile(str(path))
    return icon


@cache
def brand_pixmap(size: int, ratio: float = 2.0) -> QPixmap:
    """Brand symbol (transparent background), rendered sharply at `size` logical px."""
    px = QPixmap(int(size * ratio), int(size * ratio))
    px.fill(Qt.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    QSvgRenderer(str(BRAND_MARK)).render(painter, QRectF(0, 0, size * ratio, size * ratio))
    painter.end()
    px.setDevicePixelRatio(ratio)
    return px
