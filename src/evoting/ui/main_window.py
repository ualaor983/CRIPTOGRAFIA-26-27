"""Ventana principal: franja de la clave de sesion y pestanas de trabajo.

Sin criptografia ni estado propio: todo se delega en ``services.cipher``. La clave
solo se muestra en la franja y en «Clave usada»; nunca en titulo, avisos ni terminal.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PyQt6.QtGui import QTextOption
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from evoting.core.errors import DomainError
from evoting.services import cipher

WINDOW_TITLE = "Cifrado AES"
MISSING_KEY = "Falta la clave: genera una nueva o pega la que se usó al cifrar."
MISSING_CIPHERTEXT = "Falta el texto cifrado: pégalo en el recuadro Texto cifrado."
MISSING_INPUT_FILE = "Falta el fichero de entrada: elígelo con Elegir fichero."
MISSING_DESTINATION = (
    "Falta el destino: elige dónde guardar el resultado con Elegir destino."
)
EMPTY_RESULT = "Aquí aparecerá el resultado de la próxima operación."
KEY_NOTE = "La aplicación no guarda la clave: cópiala si vas a descifrar más tarde."


class MainWindow(QMainWindow):
    """Ventana de la aplicacion: franja de la clave y pestanas «Mensaje» y «Fichero»."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(800, 640)

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        layout.addWidget(self._build_key_strip())
        layout.addWidget(self._build_tabs(), stretch=1)
        self.setCentralWidget(root)

        self._key_field.setFocus()

    def _build_key_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("keyStrip")
        column = QVBoxLayout(strip)
        column.setContentsMargins(14, 10, 14, 12)
        column.setSpacing(6)

        title = QLabel("Clave de sesión")
        title.setObjectName("keyTitle")
        column.addWidget(title)

        self._key_field = QLineEdit()
        self._key_field.setObjectName("keyField")
        self._key_field.setAccessibleName("Clave de sesión")
        column.addWidget(self._key_field)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        generate = QPushButton("Generar clave nueva")
        generate.setObjectName("generateKeyButton")
        generate.clicked.connect(self._generate_key)
        copy = QPushButton("Copiar clave")
        copy.setObjectName("copyKeyButton")
        copy.clicked.connect(self._copy_key)
        note = QLabel(KEY_NOTE)
        note.setObjectName("keyNote")
        note.setWordWrap(True)
        actions.addWidget(generate)
        actions.addWidget(copy)
        actions.addWidget(note, stretch=1)
        column.addLayout(actions)
        return strip

    def _build_tabs(self) -> QTabWidget:
        tabs = QTabWidget()
        tabs.setObjectName("tabs")
        message_tab = self._build_message_tab()
        file_tab = self._build_file_tab()
        tabs.addTab(message_tab, "Mensaje")
        tabs.addTab(file_tab, "Fichero")
        return tabs

    def _build_message_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("messageTab")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        self._plain_edit = self._text_edit("plainMessageEdit", "Mensaje en claro")
        self._ciphertext_edit = self._text_edit(
            "ciphertextInputEdit", "Texto cifrado", wrap_anywhere=True
        )
        encrypt = QPushButton("Cifrar mensaje")
        encrypt.setObjectName("encryptMessageButton")
        encrypt.clicked.connect(self._encrypt_message)
        decrypt = QPushButton("Descifrar mensaje")
        decrypt.setObjectName("decryptMessageButton")
        decrypt.clicked.connect(self._decrypt_message)

        columns = QHBoxLayout()
        columns.setSpacing(16)
        columns.addLayout(
            self._column("Cifrar", "Mensaje en claro", self._plain_edit, encrypt)
        )
        columns.addLayout(
            self._column("Descifrar", "Texto cifrado", self._ciphertext_edit, decrypt)
        )
        layout.addLayout(columns, stretch=3)
        layout.addWidget(self._build_message_result(), stretch=2)

        order = (
            self._plain_edit,
            self._ciphertext_edit,
            encrypt,
            decrypt,
            self._message_output,
            self._message_nonce,
            self._message_key,
            self._copy_result,
        )
        for first, second in zip(order, order[1:]):
            self.setTabOrder(first, second)
        return tab

    def _build_file_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("fileTab")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        self._input_path = self._value_field("inputPathField", "Fichero de entrada")
        choose_input = QPushButton("Elegir fichero…")
        choose_input.setObjectName("chooseInputButton")
        choose_input.clicked.connect(self._choose_input)
        self._destination_path = self._value_field("destinationPathField", "Destino")
        choose_destination = QPushButton("Elegir destino…")
        choose_destination.setObjectName("chooseDestinationButton")
        choose_destination.clicked.connect(self._choose_destination)
        rows = QVBoxLayout()
        rows.setSpacing(8)
        for caption, field, button in (
            ("Fichero de entrada", self._input_path, choose_input),
            ("Destino", self._destination_path, choose_destination),
        ):
            row = QHBoxLayout()
            row.setSpacing(10)
            label = QLabel(caption)
            label.setMinimumWidth(140)
            row.addWidget(label)
            row.addWidget(field, stretch=1)
            row.addWidget(button)
            rows.addLayout(row)
        layout.addLayout(rows)

        encrypt = QPushButton("Cifrar fichero")
        encrypt.setObjectName("encryptFileButton")
        encrypt.clicked.connect(self._encrypt_file)
        decrypt = QPushButton("Descifrar fichero")
        decrypt.setObjectName("decryptFileButton")
        decrypt.clicked.connect(self._decrypt_file)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        actions.addWidget(encrypt)
        actions.addWidget(decrypt)
        actions.addStretch(1)
        layout.addLayout(actions)
        layout.addWidget(self._build_file_result())
        layout.addStretch(1)

        order = (
            choose_input,
            choose_destination,
            encrypt,
            decrypt,
            self._file_path,
            self._file_nonce,
            self._file_key,
        )
        for first, second in zip(order, order[1:]):
            self.setTabOrder(first, second)
        return tab

    def _build_file_result(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("resultPanel")
        column = QVBoxLayout(panel)
        column.setContentsMargins(12, 10, 12, 10)
        column.setSpacing(6)

        self._file_title = QLabel("Resultado")
        self._file_title.setObjectName("fileResultTitle")
        column.addWidget(self._file_title)

        self._file_empty = QLabel(EMPTY_RESULT)
        self._file_empty.setObjectName("fileEmpty")
        column.addWidget(self._file_empty)

        self._file_path = self._value_field("fileResultPath", "Guardado en")
        self._file_nonce = self._value_field("fileResultNonce", "Nonce")
        self._file_key = self._value_field("fileResultKey", "Clave usada")
        self._file_values = QWidget()
        values = QVBoxLayout(self._file_values)
        values.setContentsMargins(0, 0, 0, 0)
        values.setSpacing(4)
        for caption, caption_name, field in (
            ("Guardado en", "savedCaption", self._file_path),
            ("Nonce (valor único)", "nonceCaption", self._file_nonce),
            ("Clave usada", "usedKeyCaption", self._file_key),
        ):
            row = QHBoxLayout()
            label = QLabel(caption)
            label.setObjectName(caption_name)
            label.setMinimumWidth(140)
            row.addWidget(label)
            row.addWidget(field, stretch=1)
            values.addLayout(row)
        column.addWidget(self._file_values)

        self._file_notice = QLabel()
        self._file_notice.setObjectName("fileNotice")
        self._file_notice.setProperty("role", "failure")
        self._file_notice.setWordWrap(True)
        column.addWidget(self._file_notice)

        self._clear_file_result()
        self._file_empty.show()
        return panel

    def _clear_file_result(self) -> None:
        # Se borra (no solo se oculta) para que un fallo no deje un resultado previo.
        self._file_title.setText("Resultado")
        self._file_path.clear()
        self._file_nonce.clear()
        self._file_key.clear()
        self._file_notice.clear()
        for widget in (self._file_empty, self._file_values, self._file_notice):
            widget.hide()

    def _show_file_notice(self, text: str) -> None:
        self._file_notice.setText(text)
        self._file_notice.show()

    def _show_file_result(self, title: str, destination: str, nonce: str) -> None:
        self._file_title.setText(title)
        self._file_path.setText(destination)
        self._file_nonce.setText(nonce)
        self._file_key.setText(self._key_field.text())
        self._file_values.show()

    def _choose_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Elegir fichero de entrada")
        if path:
            self._input_path.setText(path)

    def _choose_destination(self) -> None:
        # DontConfirmOverwrite: el servicio rechaza los destinos que ya existen.
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Elegir destino",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if path:
            self._destination_path.setText(path)

    def _encrypt_file(self) -> None:
        self._run_file_operation(cipher.encrypt_file, "Fichero cifrado")

    def _decrypt_file(self) -> None:
        self._run_file_operation(cipher.decrypt_file, "Fichero descifrado")

    def _run_file_operation(
        self, operation: Callable[[str, Path, Path], str], title: str
    ) -> None:
        """Valida los datos, ejecuta la operacion y muestra el resultado o el aviso."""
        self._clear_file_result()
        key = self._key_field.text()
        source = self._input_path.text()
        destination = self._destination_path.text()
        if not key.strip():
            self._show_file_notice(MISSING_KEY)
            return
        if not source:
            self._show_file_notice(MISSING_INPUT_FILE)
            return
        if not destination:
            self._show_file_notice(MISSING_DESTINATION)
            return
        try:
            nonce = operation(key, Path(source), Path(destination))
        except DomainError as error:
            self._show_file_notice(str(error))
            return
        self._show_file_result(title, destination, nonce)

    @staticmethod
    def _text_edit(
        name: str, accessible_name: str, wrap_anywhere: bool = False
    ) -> QPlainTextEdit:
        edit = QPlainTextEdit()
        edit.setObjectName(name)
        edit.setAccessibleName(accessible_name)
        edit.setTabChangesFocus(True)
        if wrap_anywhere:
            # Solo visual: no inserta saltos de linea en el texto que se copia.
            edit.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        return edit

    @staticmethod
    def _column(
        heading: str, label: str, edit: QPlainTextEdit, button: QPushButton
    ) -> QVBoxLayout:
        column = QVBoxLayout()
        column.setSpacing(6)
        title = QLabel(heading)
        title.setObjectName("sectionTitle")
        column.addWidget(title)
        column.addWidget(QLabel(label))
        column.addWidget(edit, stretch=1)
        row = QHBoxLayout()
        row.addWidget(button)
        row.addStretch(1)
        column.addLayout(row)
        return column

    def _build_message_result(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("resultPanel")
        column = QVBoxLayout(panel)
        column.setContentsMargins(12, 10, 12, 10)
        column.setSpacing(6)

        header = QHBoxLayout()
        self._message_title = QLabel("Resultado")
        self._message_title.setObjectName("messageResultTitle")
        self._copy_result = QPushButton("Copiar resultado")
        self._copy_result.setObjectName("copyMessageResultButton")
        self._copy_result.clicked.connect(self._copy_message_result)
        header.addWidget(self._message_title, stretch=1)
        header.addWidget(self._copy_result)
        column.addLayout(header)

        self._message_empty = QLabel(EMPTY_RESULT)
        self._message_empty.setObjectName("messageEmpty")
        column.addWidget(self._message_empty)

        self._message_output = QPlainTextEdit()
        self._message_output.setObjectName("messageResultOutput")
        self._message_output.setAccessibleName("Resultado")
        self._message_output.setReadOnly(True)
        self._message_output.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        column.addWidget(self._message_output, stretch=1)

        self._message_nonce = self._value_field("messageResultNonce", "Nonce")
        self._message_key = self._value_field("messageResultKey", "Clave usada")
        self._message_values = QWidget()
        values = QVBoxLayout(self._message_values)
        values.setContentsMargins(0, 0, 0, 0)
        values.setSpacing(4)
        for caption, caption_name, field in (
            ("Nonce (valor único)", "nonceCaption", self._message_nonce),
            ("Clave usada", "usedKeyCaption", self._message_key),
        ):
            row = QHBoxLayout()
            label = QLabel(caption)
            label.setObjectName(caption_name)
            label.setMinimumWidth(140)
            row.addWidget(label)
            row.addWidget(field, stretch=1)
            values.addLayout(row)
        column.addWidget(self._message_values)

        self._message_notice = QLabel()
        self._message_notice.setObjectName("messageNotice")
        self._message_notice.setProperty("role", "failure")
        self._message_notice.setWordWrap(True)
        column.addWidget(self._message_notice)

        self._clear_message_result()
        self._message_empty.show()
        return panel

    @staticmethod
    def _value_field(name: str, accessible_name: str) -> QLineEdit:
        field = QLineEdit()
        field.setObjectName(name)
        field.setAccessibleName(accessible_name)
        field.setReadOnly(True)
        return field

    def _clear_message_result(self) -> None:
        # Se borra (no solo se oculta) para que un fallo no deje un resultado previo.
        self._message_title.setText("Resultado")
        self._message_output.clear()
        self._message_nonce.clear()
        self._message_key.clear()
        self._message_notice.clear()
        for widget in (
            self._message_empty,
            self._message_output,
            self._message_values,
            self._message_notice,
            self._copy_result,
        ):
            widget.hide()

    def _show_message_notice(self, text: str) -> None:
        self._message_notice.setText(text)
        self._message_notice.show()

    def _show_message_result(
        self, title: str, output: str, nonce: str, public: bool
    ) -> None:
        """``public`` marca la salida como texto cifrado (estilo Publico, monoespaciada)."""
        self._message_title.setText(title)
        self._message_output.setProperty("kind", "public" if public else "plain")
        style = self._message_output.style()
        style.unpolish(self._message_output)
        style.polish(self._message_output)
        self._message_output.setPlainText(output)
        self._message_nonce.setText(nonce)
        self._message_key.setText(self._key_field.text())
        for widget in (self._message_output, self._message_values, self._copy_result):
            widget.show()

    def _encrypt_message(self) -> None:
        self._clear_message_result()
        key = self._key_field.text()
        if not key.strip():
            self._show_message_notice(MISSING_KEY)
            return
        try:
            text, nonce = cipher.encrypt_message(key, self._plain_edit.toPlainText())
        except DomainError as error:
            self._show_message_notice(str(error))
            return
        self._show_message_result("Mensaje cifrado", text, nonce, public=True)

    def _decrypt_message(self) -> None:
        self._clear_message_result()
        key = self._key_field.text()
        ciphertext = self._ciphertext_edit.toPlainText()
        if not key.strip():
            self._show_message_notice(MISSING_KEY)
            return
        if not ciphertext.strip():
            self._show_message_notice(MISSING_CIPHERTEXT)
            return
        try:
            message, nonce = cipher.decrypt_message(key, ciphertext)
        except DomainError as error:
            self._show_message_notice(str(error))
            return
        self._show_message_result("Mensaje descifrado", message, nonce, public=False)

    def _copy_message_result(self) -> None:
        QApplication.clipboard().setText(self._message_output.toPlainText())

    def _generate_key(self) -> None:
        self._key_field.setText(cipher.new_session_key())

    def _copy_key(self) -> None:
        QApplication.clipboard().setText(self._key_field.text())
