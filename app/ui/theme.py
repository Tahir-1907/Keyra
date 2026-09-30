"""Keyra design system — single source of visual truth.

Everything related to appearance is defined here: colors, depth levels,
spacing, radii, typography, animation durations and the Qt style sheet. Other
modules never hard-code a color or a size: they use these tokens.

Art direction: a dark, sober, premium "digital safe". Green (accent) is
reserved for security, validation, the primary action and the active item —
never as the dominant color.

Depth levels: BG → BG_2 (sidebar, header) → SURFACE (panels) → SURFACE_2
(cards, fields) → SURFACE_3 (hovered/active card) → modal (SURFACE + active
border + BACKDROP veil behind).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

# --- Colors ------------------------------------------------------------------------------

BG = "#070A0F"              # main background
BG_2 = "#0B1018"            # secondary background (sidebar, header)
SURFACE = "#0F1621"         # surface (panels)
SURFACE_2 = "#131C29"       # raised surface (cards, fields)
SURFACE_3 = "#172233"       # hovered / active card
BORDER = "#1D2938"
BORDER_ACTIVE = "#2B3B4F"
TEXT = "#F1F5F9"
TEXT_2 = "#94A3B8"
TEXT_3 = "#64748B"
ACCENT = "#10B981"
ACCENT_2 = "#34D399"
ACCENT_SOFT = "rgba(16, 185, 129, 0.10)"
ACCENT_LINE = "rgba(16, 185, 129, 0.45)"
DANGER = "#F43F5E"
DANGER_SOFT = "rgba(244, 63, 94, 0.10)"
WARNING = "#F59E0B"
WARNING_SOFT = "rgba(245, 158, 11, 0.10)"
INFO = "#38BDF8"
INFO_SOFT = "rgba(56, 189, 248, 0.10)"
BACKDROP_ALPHA = 115        # veil behind a modal (0-255, over BG)

# Avatars (monograms): hues readable on a dark background, assigned in a
# stable way from the name.
AVATAR_COLORS = ("#3B82F6", "#8B5CF6", "#EC4899", "#F59E0B", "#10B981", "#06B6D4",
                 "#EF4444", "#6366F1", "#14B8A6", "#F97316")

# --- Spacing, radii, dimensions -----------------------------------------------------

SPACE_XS, SPACE_S, SPACE_M, SPACE_L, SPACE_XL, SPACE_XXL = 4, 8, 12, 16, 24, 32
RADIUS_S, RADIUS_M, RADIUS_L, RADIUS_XL = 6, 10, 14, 18
SIDEBAR_WIDTH = 236
SIDEBAR_COMPACT_WIDTH = 68  # compact mode: icons only
COMPACT_BREAKPOINT = 1180   # below this (window width), compact layout
SEARCH_MIN_WIDTH = 150
SEARCH_MAX_WIDTH = 300
WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT = 800, 560
HEADER_HEIGHT = 64
DETAIL_MIN_WIDTH = 320      # details panel: widens with the window…
DETAIL_MAX_WIDTH = 540      # …without ever exceeding this width

# --- Animations (ms) ------------------------------------------------------------------------

DURATION_FAST = 150
DURATION_BASE = 220
DURATION_SLOW = 320
STAGGER_STEP = 30           # offset between items of a list
SLIDE_DISTANCE = 20         # entrance translation of a view (px)

# --- Typography ---------------------------------------------------------------------------

FONT_FALLBACKS = ("Inter", "Cantarell", "Noto Sans", "DejaVu Sans", "sans-serif")
DISPLAY_FAMILY = "Inter Display"
MONO_FAMILIES = ("JetBrains Mono", "Noto Sans Mono", "DejaVu Sans Mono", "monospace")
SIZE_DISPLAY = 28   # large figures, score
SIZE_TITLE = 22     # view title
SIZE_H2 = 16        # section / card title
SIZE_BODY = 13      # body text
SIZE_SMALL = 12     # secondary information
SIZE_TINY = 11      # labels, badges

_FONTS_DIR = Path(__file__).resolve().parent.parent / "resources" / "fonts"
_FAMILIES = ", ".join(f'"{f}"' for f in FONT_FALLBACKS)
_MONO = ", ".join(f'"{f}"' for f in MONO_FAMILIES)


def font(size: int = SIZE_BODY, weight: QFont.Weight = QFont.Normal,
         display: bool = False) -> QFont:
    f = QFont()
    f.setFamilies([DISPLAY_FAMILY, *FONT_FALLBACKS] if display else list(FONT_FALLBACKS))
    f.setPixelSize(size)
    f.setWeight(weight)
    return f


def mono_font(size: int = SIZE_BODY) -> QFont:
    f = QFont()
    f.setFamilies(list(MONO_FAMILIES))
    f.setPixelSize(size)
    return f


def load_fonts() -> None:
    """Loads Inter from the resources (OFL license, see resources/fonts)."""
    for path in sorted(_FONTS_DIR.glob("*.otf")):
        QFontDatabase.addApplicationFont(str(path))


def rgba(hex_color: str, alpha: int) -> QColor:
    color = QColor(hex_color)
    color.setAlpha(alpha)
    return color


# --- Style sheet ----------------------------------------------------------------------

STYLESHEET = f"""
* {{
    color: {TEXT};
    outline: none;
}}
QMainWindow, QWidget#Root {{ background: {BG}; }}
QWidget#Page {{ background: {BG}; }}
QToolTip {{
    background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER_ACTIVE};
    border-radius: {RADIUS_S}px; padding: 6px 8px; font-size: {SIZE_SMALL}px;
}}

/* --- Depth levels ---------------------------------------------------------- */
QFrame#Sidebar {{ background: {BG_2}; border: none; border-right: 1px solid {BORDER}; }}
QFrame#Header {{ background: {BG}; border: none; border-bottom: 1px solid {BORDER}; }}
QFrame#Surface {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: {RADIUS_L}px; }}
QFrame#Card {{ background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: {RADIUS_L}px; }}
QFrame#CardDanger {{ background: {SURFACE_2}; border: 1px solid rgba(244, 63, 94, 0.30); border-radius: {RADIUS_L}px; }}
QFrame#ModalCard {{ background: {SURFACE}; border: 1px solid {BORDER_ACTIVE}; border-radius: {RADIUS_XL}px; }}
QFrame#Divider {{ background: {BORDER}; max-height: 1px; min-height: 1px; border: none; }}

/* --- Text -------------------------------------------------------------- */
QLabel {{ background: transparent; border: none; }}
QLabel#ViewTitle {{ font-size: {SIZE_TITLE}px; font-weight: 600; }}
QLabel#ViewSubtitle, QLabel#Muted {{ color: {TEXT_2}; }}
QLabel#Faint {{ color: {TEXT_3}; font-size: {SIZE_SMALL}px; }}
QLabel#H1 {{ font-size: {SIZE_DISPLAY}px; font-weight: 600; }}
QLabel#H2 {{ font-size: {SIZE_H2}px; font-weight: 600; }}
QLabel#Overline {{ color: {TEXT_3}; font-size: {SIZE_TINY}px; font-weight: 600; letter-spacing: 1px; }}
QLabel#FieldLabel {{ color: {TEXT_2}; font-size: {SIZE_SMALL}px; font-weight: 500; }}
QLabel#Error {{ color: {DANGER}; }}
QLabel#Brand {{ font-size: {SIZE_SMALL}px; font-weight: 700; letter-spacing: 1.6px; }}
QLabel#Badge {{
    background: {SURFACE_3}; color: {TEXT_2}; border: 1px solid {BORDER};
    border-radius: 9px; padding: 1px 8px; font-size: {SIZE_TINY}px; font-weight: 500;
    max-height: 18px;
}}
QLabel#BadgeAccent {{
    background: {ACCENT_SOFT}; color: {ACCENT_2}; border: 1px solid {ACCENT_LINE};
    border-radius: 9px; padding: 1px 8px; font-size: {SIZE_TINY}px; font-weight: 600;
}}
QLabel#BadgeDanger {{
    background: {DANGER_SOFT}; color: {DANGER}; border: 1px solid rgba(244, 63, 94, 0.4);
    border-radius: 9px; padding: 1px 8px; font-size: {SIZE_TINY}px; font-weight: 600;
}}
QLabel#BadgeWarning {{
    background: {WARNING_SOFT}; color: {WARNING}; border: 1px solid rgba(245, 158, 11, 0.4);
    border-radius: 9px; padding: 1px 8px; font-size: {SIZE_TINY}px; font-weight: 600;
}}
QLabel#Mono {{ font-family: {_MONO}; }}
QLabel#ToastTitle {{ font-weight: 600; }}

/* --- Fields -------------------------------------------------------------- */
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {{
    background: {BG_2}; border: 1px solid {BORDER}; border-radius: {RADIUS_M}px;
    padding: 8px 12px; selection-background-color: {ACCENT}; selection-color: {BG};
}}
QLineEdit:hover, QPlainTextEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: {BORDER_ACTIVE}; }}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit:read-only {{ background: {SURFACE_2}; }}
QLineEdit:disabled {{ color: {TEXT_3}; }}
QLineEdit#Search {{ background: {SURFACE}; padding: 7px 12px; }}
QLineEdit#Secret {{ font-family: {_MONO}; letter-spacing: 0.5px; }}
QFrame#Generated {{
    background: {BG}; border: 1px solid {BORDER_ACTIVE}; border-radius: {RADIUS_L}px;
}}
QFrame#Generated QLabel {{ color: {TEXT}; background: transparent; border: none; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    background: {SURFACE_2}; border: 1px solid {BORDER_ACTIVE}; border-radius: {RADIUS_M}px;
    selection-background-color: {SURFACE_3}; selection-color: {TEXT}; padding: 4px;
}}
QSpinBox::up-button, QSpinBox::down-button {{ width: 0; border: none; }}

/* --- Buttons (hover: brighter + raised by 1 px) --------------------------- */
QPushButton {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: {RADIUS_M}px;
    padding: 8px 14px; color: {TEXT}; font-weight: 500;
}}
QPushButton:hover {{ background: {SURFACE_3}; border-color: {BORDER_ACTIVE}; padding-top: 7px; padding-bottom: 9px; }}
QPushButton:pressed {{ background: {SURFACE_2}; padding-top: 8px; padding-bottom: 8px; }}
QPushButton:focus {{ border-color: {ACCENT_LINE}; }}
QPushButton:disabled {{ color: {TEXT_3}; background: {SURFACE}; border-color: {BORDER}; }}
QPushButton#Primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: #03130C; font-weight: 600; }}
QPushButton#Primary:hover {{ background: {ACCENT_2}; border-color: {ACCENT_2}; }}
QPushButton#Primary:disabled {{ background: rgba(16, 185, 129, 0.30); border-color: transparent; color: rgba(3, 19, 12, 0.6); }}
QPushButton#Danger {{ background: {DANGER_SOFT}; border: 1px solid rgba(244, 63, 94, 0.45); color: {DANGER}; }}
QPushButton#Danger:hover {{ background: {DANGER}; border-color: {DANGER}; color: white; }}
QPushButton#Danger:disabled {{ background: transparent; color: rgba(244, 63, 94, 0.4); border-color: rgba(244, 63, 94, 0.2); }}
QPushButton#Ghost {{ background: transparent; border: 1px solid transparent; color: {TEXT_2}; }}
QPushButton#Ghost:hover {{ background: {SURFACE_2}; color: {TEXT}; }}
QPushButton#Nav {{
    background: transparent; border: 1px solid transparent; border-radius: {RADIUS_M}px; color: {TEXT_2};
    text-align: left; padding: 9px 12px; font-weight: 500;
}}
QPushButton#Nav:hover {{ background: rgba(148, 163, 184, 0.06); color: {TEXT}; padding-top: 9px; padding-bottom: 9px; }}
QPushButton#Nav:checked {{ background: {SURFACE_2}; border: 1px solid {BORDER}; color: {TEXT}; }}
QPushButton#Nav:focus {{ border-color: {ACCENT_LINE}; }}
QPushButton#Chip {{
    background: transparent; border: 1px solid {BORDER}; border-radius: 15px;
    padding: 5px 12px; color: {TEXT_2}; font-size: {SIZE_SMALL}px;
}}
QPushButton#Chip:hover {{ border-color: {BORDER_ACTIVE}; color: {TEXT}; padding-top: 5px; padding-bottom: 5px; }}
QPushButton#Chip:checked {{ background: {ACCENT_SOFT}; border-color: {ACCENT_LINE}; color: {ACCENT_2}; }}
QToolButton {{
    background: transparent; border: 1px solid transparent; border-radius: {RADIUS_M}px; padding: 7px;
}}
QToolButton:hover {{ background: {SURFACE_2}; border-color: {BORDER}; }}
QToolButton:pressed {{ background: {SURFACE}; }}
QToolButton:focus {{ border-color: {ACCENT_LINE}; }}

/* --- Lists, scrolling ------------------------------------------------------ */
QListView, QListWidget, QTreeWidget {{ background: transparent; border: none; }}
QListWidget::item {{ border-radius: {RADIUS_M}px; padding: 8px 10px; }}
QListWidget::item:hover {{ background: {SURFACE_2}; }}
QListWidget::item:selected {{ background: {SURFACE_3}; color: {TEXT}; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER_ACTIVE}; border-radius: 3px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {TEXT_3}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* --- Slider -------------------------------------------------------------- */
QSlider::groove:horizontal {{ height: 4px; background: {BORDER}; border-radius: 2px; }}
QSlider::sub-page:horizontal {{ background: {ACCENT}; border-radius: 2px; }}
QSlider::handle:horizontal {{
    background: {TEXT}; width: 12px; height: 12px; margin: -6px 0; border-radius: 8px;
    border: 2px solid {ACCENT};
}}

/* --- Menus ------------------------------------------------------------ */
QMenu {{ background: {SURFACE_2}; border: 1px solid {BORDER_ACTIVE}; border-radius: {RADIUS_M}px; padding: 6px; }}
QMenu::item {{ padding: 7px 26px 7px 10px; border-radius: {RADIUS_S}px; color: {TEXT}; }}
QMenu::item:selected {{ background: {SURFACE_3}; }}
QMenu::item:disabled {{ color: {TEXT_3}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 5px 8px; }}
QMenu::icon {{ padding-left: 6px; }}

/* --- Check boxes (except toggles), radio buttons --------------------------- */
QCheckBox {{ spacing: 10px; color: {TEXT}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 5px; border: 1px solid {BORDER_ACTIVE}; background: {BG_2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QRadioButton {{ spacing: 10px; }}
QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 8px; border: 1px solid {BORDER_ACTIVE}; background: {BG_2}; }}
QRadioButton::indicator:checked {{ width: 8px; height: 8px; border: 4px solid {ACCENT}; background: {TEXT}; }}

/* --- Command palette ------------------------------------------------------- */
QFrame#Palette {{ background: {SURFACE}; border: 1px solid {BORDER_ACTIVE}; border-radius: {RADIUS_XL}px; }}
QLineEdit#PaletteInput {{ font-size: 15px; padding: 12px 14px; border-radius: {RADIUS_L}px; background: {BG_2}; }}
QListWidget#PaletteList::item {{ padding: 8px 10px; color: {TEXT_2}; }}
QListWidget#PaletteList::item:disabled {{ color: {TEXT_3}; font-size: {SIZE_TINY}px; font-weight: 600; padding: 10px 10px 2px 10px; }}
QListWidget#PaletteList::item:selected {{ background: {SURFACE_3}; color: {TEXT}; }}
QLabel#PaletteFooter {{ color: {TEXT_3}; font-size: {SIZE_TINY}px; padding: 0 4px; }}
"""


def apply_theme(app: QApplication) -> None:
    load_fonts()
    app.setStyle("Fusion")
    app.setFont(font(SIZE_BODY))
    palette = QPalette()
    for role, color in (
        (QPalette.Window, BG), (QPalette.WindowText, TEXT), (QPalette.Base, BG_2),
        (QPalette.AlternateBase, SURFACE), (QPalette.Text, TEXT), (QPalette.Button, SURFACE_2),
        (QPalette.ButtonText, TEXT), (QPalette.Highlight, ACCENT), (QPalette.HighlightedText, BG),
        (QPalette.ToolTipBase, SURFACE_2), (QPalette.ToolTipText, TEXT),
        (QPalette.PlaceholderText, TEXT_3), (QPalette.Link, ACCENT_2),
    ):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET)
    for effect in (Qt.UI_AnimateMenu, Qt.UI_FadeMenu, Qt.UI_AnimateCombo, Qt.UI_FadeTooltip):
        QApplication.setEffectEnabled(effect, True)
