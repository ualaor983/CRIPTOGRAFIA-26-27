"""Arranque de la aplicacion Qt: estilo Fusion y hoja de estilo con la paleta.

Fusion porque respeta por completo la hoja de estilo, sea cual sea el tema de Windows.
Color con significado: Secreto = la clave, Publico = nonce y cifrado, Fallo = avisos.
"""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from evoting.ui.main_window import MainWindow

PAPER = "#EEF1EF"
SURFACE = "#FFFFFF"
INK = "#1D2733"
SECRET = "#8A5300"
PUBLIC = "#1F6F78"
FAILURE = "#A1262E"

UI_FONT = '"Segoe UI Variable", "Segoe UI"'
MONO_FONT = '"Cascadia Mono", Consolas'

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
    window = MainWindow()
    window.show()
    return application.exec()
