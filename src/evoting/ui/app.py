"""Arranque de la aplicacion Qt: estilo Fusion y hoja de estilo con la paleta.

Fusion porque respeta por completo la hoja de estilo, sea cual sea el tema de Windows.
Color con significado: Secreto = la clave, Publico = nonce y cifrado, Fallo = avisos.
"""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from evoting.services.election import ElectionService
from evoting.ui.theme import FAILURE, INK, MONO_FONT, PAPER, PUBLIC, SECRET, SURFACE, UI_FONT
from evoting.ui.voting_window import VotingWindow

STYLESHEET = f"""
QWidget {{ font-family: {UI_FONT}; font-size: 10pt; color: {INK}; }}
QMainWindow, QMainWindow > QWidget {{ background: {PAPER}; }}
QLineEdit, QPlainTextEdit {{
    background: {SURFACE}; border: 1px solid {INK}; padding: 4px 5px;
    selection-background-color: {PUBLIC}; selection-color: {SURFACE};
}}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 2px solid {PUBLIC}; padding: 3px 4px; }}
QLineEdit:read-only {{ background: {PAPER}; }}
QPushButton {{ background: {SURFACE}; border: 1px solid {INK}; padding: 5px 14px; }}
QPushButton:hover {{ background: {PAPER}; }}
QPushButton:focus {{ border: 2px solid {PUBLIC}; padding: 4px 13px; }}
QPushButton:pressed {{ background: {INK}; color: {SURFACE}; }}
QTabWidget::pane {{ border: 1px solid {INK}; background: {PAPER}; top: -1px; }}
QTabBar::tab {{
    background: {PAPER}; border: 1px solid {INK}; padding: 6px 18px; margin-right: 2px;
}}
QTabBar::tab:selected {{ background: {SURFACE}; font-weight: 600; }}
QTabBar::tab:focus {{ border: 2px solid {PUBLIC}; }}
QFrame#keyStrip {{
    background: {SURFACE}; border: 1px solid {INK}; border-left: 6px solid {SECRET};
}}
QFrame#keyStrip QLabel {{ background: transparent; }}
QLabel#keyTitle {{ color: {SECRET}; font-size: 12pt; font-weight: 600; }}
QLineEdit#keyField {{
    font-family: {MONO_FONT}; font-size: 14pt; border: 1px solid {SECRET};
}}
QLineEdit#keyField:focus {{ border: 2px solid {PUBLIC}; padding: 3px 4px; }}
QLabel#sectionTitle, QLabel#messageResultTitle,
QLabel#fileResultTitle {{ font-size: 12pt; font-weight: 600; }}
QFrame#resultPanel {{ background: {SURFACE}; border: 1px solid {INK}; }}
QFrame#resultPanel QLabel {{ background: transparent; }}
QPlainTextEdit#ciphertextInputEdit, QPlainTextEdit[kind="public"],
QLineEdit#messageResultNonce,
QLineEdit#fileResultNonce {{ font-family: {MONO_FONT}; border-color: {PUBLIC}; }}
QLineEdit#messageResultKey,
QLineEdit#fileResultKey {{ font-family: {MONO_FONT}; border-color: {SECRET}; }}
QLabel#nonceCaption {{ color: {PUBLIC}; font-weight: 600; }}
QLabel#usedKeyCaption {{ color: {SECRET}; font-weight: 600; }}
QLabel#phaseLabel {{ font-size: 14pt; font-weight: 600; }}
QLabel#emptyText {{ color: {INK}; padding: 10px 0; }}
QLabel#lossNote {{ color: {INK}; }}
QTableWidget {{
    background: {SURFACE}; border: 1px solid {INK}; gridline-color: {PAPER};
    font-family: {MONO_FONT};
}}
QTableWidget:focus {{ border: 2px solid {PUBLIC}; }}
QTableWidget#censusTable {{ font-family: {UI_FONT}; }}
QHeaderView {{ background: {PAPER}; }}
QTableCornerButton::section {{ background: {PAPER}; border: 1px solid {INK}; }}
QHeaderView::section {{
    background: {PAPER}; border: 1px solid {INK}; padding: 3px 6px;
}}
QHeaderView::section:horizontal {{ font-weight: 600; }}
QTableWidget#urnTable QHeaderView::section:vertical {{ min-width: 64px; }}
QScrollBar:horizontal {{ background: {PAPER}; height: 12px; border: 0; }}
QScrollBar:vertical {{ background: {PAPER}; width: 12px; border: 0; }}
QScrollBar::handle {{ background: {INK}; min-width: 24px; min-height: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: {PAPER}; }}
QSplitter::handle {{ background: {PAPER}; }}
QMenuBar {{ background: {PAPER}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {PUBLIC}; color: {SURFACE}; }}
QMenu {{ background: {SURFACE}; border: 1px solid {INK}; }}
QPushButton:disabled {{ color: #7B8590; border-color: #7B8590; background: {PAPER}; }}
QComboBox {{ background: {SURFACE}; border: 1px solid {INK}; padding: 4px 8px; }}
QComboBox:focus {{ border: 2px solid {PUBLIC}; padding: 3px 7px; }}
QComboBox QAbstractItemView {{
    background: {SURFACE}; border: 1px solid {INK};
    selection-background-color: {PUBLIC}; selection-color: {SURFACE};
}}
QRadioButton::indicator {{
    width: 12px; height: 12px; border-radius: 7px;
    background: {SURFACE}; border: 1px solid {INK};
}}
QRadioButton::indicator:checked {{
    border: 1px solid {INK};
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
        stop:0 {PUBLIC}, stop:0.55 {PUBLIC}, stop:0.62 {SURFACE}, stop:1 {SURFACE});
}}
QRadioButton::indicator:disabled {{
    background: {PAPER}; border: 1px solid #7B8590;
}}
QRadioButton::indicator:focus {{ border: 2px solid {PUBLIC}; }}
QRadioButton:disabled {{ color: #7B8590; }}
QListWidget#trafficList {{
    background: {SURFACE}; border: 1px solid {INK}; font-family: {MONO_FONT};
    color: {PUBLIC};
}}
QListWidget#trafficList:focus {{ border: 2px solid {PUBLIC}; }}
QLabel[role="failure"] {{ color: {FAILURE}; font-weight: 600; }}
"""


def create_application(argv: list[str]) -> QApplication:
    """Crea la ``QApplication`` con estilo Fusion y la hoja de estilo, sin bucle."""
    application = QApplication(argv)
    application.setStyle("Fusion")
    application.setStyleSheet(STYLESHEET)
    return application


def run() -> int:
    """Crea la aplicacion, abre la ventana y devuelve el codigo de salida de Qt."""
    application = create_application(sys.argv)
    window = VotingWindow(ElectionService())
    window.show()
    return application.exec()
