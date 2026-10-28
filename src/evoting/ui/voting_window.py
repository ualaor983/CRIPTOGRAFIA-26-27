"""Ventana principal de la votacion: urna y censo publicos, y acciones del ciclo.

Sin criptografia ni E/S: todo viene de ``ElectionService`` ya en texto. Los botones
se habilitan segun ``allowed_actions()``; la ventana no decide nada del dominio.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from evoting.core.errors import DomainError
from evoting.services.election import Action, ElectionService, ElectionSnapshot, Option
from evoting.ui.main_window import MainWindow
from evoting.ui.theme import PUBLIC, SECRET

WINDOW_TITLE = "Votación Borrell-Rifa"
EMPTY_TEXT = (
    "Aún no hay elección. Pulsa Preparar elección para crear el censo y la urna."
)
LOSS_NOTE = "Cerrar la aplicación pierde la elección: no se puede reanudar."
PHASE_TEXT = {
    "": "Sin elección",
    "abierta": "Votación abierta",
    "cerrada": "Votación cerrada",
    "escrutada": "Votación escrutada",
}
RESULT_EMPTY = "El resultado aparecerá aquí cuando se recuente la urna."
PICK_OPTION = "Elige una opción: Sí, No o En blanco."
CELL_CHARS = 16
MONO_FAMILIES = ["Cascadia Mono", "Consolas"]


def _cell(text: str, color: str | None = None, mono: bool = True) -> QTableWidgetItem:
    """Celda de solo lectura; el texto largo se trunca y el completo va al tooltip."""
    shown = text if len(text) <= CELL_CHARS else f"{text[:CELL_CHARS]}…"
    item = QTableWidgetItem(shown)
    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
    item.setToolTip(text)
    if mono:
        item.setFont(QFont(MONO_FAMILIES))
    if color:
        item.setForeground(QBrush(QColor(color)))
    return item


class VotingWindow(QMainWindow):
    """Ventana principal: fase, acciones, urna, censo y aviso en linea."""

    def __init__(self, service: ElectionService) -> None:
        super().__init__()
        self._service = service
        self._aes_window: MainWindow | None = None
        self._option_values: dict[QRadioButton, Option] = {}
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1100, 720)
        self._build_menu()

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(12)

        self._phase_label = QLabel()
        self._phase_label.setObjectName("phaseLabel")
        layout.addLayout(self._build_action_bar())
        layout.addLayout(self._build_verify_bar())

        self._notice = QLabel()
        self._notice.setObjectName("votingNotice")
        self._notice.setProperty("role", "failure")
        self._notice.setWordWrap(True)
        self._notice.hide()
        layout.addWidget(self._notice)

        self._empty = QLabel(EMPTY_TEXT)
        self._empty.setObjectName("emptyText")
        self._empty.setWordWrap(True)
        layout.addWidget(self._empty)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_urn_panel())
        splitter.addWidget(self._build_side_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([680, 420])
        layout.addWidget(splitter, stretch=1)
        layout.addWidget(self._build_result_panel())

        note = QLabel(LOSS_NOTE)
        note.setObjectName("lossNote")
        layout.addWidget(note)
        self.setCentralWidget(root)
        self._refresh()

    def _build_menu(self) -> None:
        tools = self.menuBar().addMenu("Herramientas")
        action = QAction("Cifrado AES", self)
        action.setObjectName("aesAction")
        action.triggered.connect(self._open_aes)
        tools.addAction(action)

    def _build_action_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(10)
        bar.addWidget(self._phase_label)
        bar.addSpacing(16)
        self._prepare_button = QPushButton("Preparar elección")
        self._prepare_button.setObjectName("prepareButton")
        self._prepare_button.clicked.connect(self._prepare)
        bar.addWidget(self._prepare_button)
        bar.addSpacing(16)
        bar.addWidget(QLabel("Votante"))
        self._voter_combo = QComboBox()
        self._voter_combo.setObjectName("voterCombo")
        self._voter_combo.setAccessibleName("Votante")
        bar.addWidget(self._voter_combo)
        self._options = QButtonGroup(self)
        self._options.setExclusive(False)
        for name, text, option in (
            ("optionYes", "Sí", Option.YES),
            ("optionNo", "No", Option.NO),
            ("optionAbstain", "En blanco", Option.ABSTAIN),
        ):
            radio = QRadioButton(text)
            radio.setObjectName(name)
            radio.toggled.connect(lambda on, r=radio: on and self._exclusive(r))
            self._options.addButton(radio)
            self._option_values[radio] = option
            bar.addWidget(radio)
        self._vote_button = self._button("Votar", "voteButton", self._vote)
        self._close_button = self._button(
            "Cerrar votación", "closeButton", lambda: self._act(self._service.close)
        )
        self._count_button = self._button(
            "Recontar", "countButton", lambda: self._act(self._service.count)
        )
        for button in (self._vote_button, self._close_button, self._count_button):
            bar.addWidget(button)
        bar.addStretch(1)
        return bar

    def _button(self, text: str, name: str, slot) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName(name)
        button.clicked.connect(slot)
        return button

    def _exclusive(self, chosen: QRadioButton) -> None:
        for radio in self._option_values:
            if radio is not chosen:
                radio.setChecked(False)

    def _clear_option(self) -> None:
        for radio in self._option_values:
            radio.setChecked(False)

    def _build_verify_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(10)
        bar.addWidget(QLabel("Verificar votante"))
        self._verify_combo = QComboBox()
        self._verify_combo.setObjectName("verifyCombo")
        self._verify_combo.setAccessibleName("Votante a verificar")
        bar.addWidget(self._verify_combo)
        self._verify_button = self._button(
            "Verificar mi voto", "verifyButton", self._verify
        )
        bar.addWidget(self._verify_button)
        self._verify_result = QLabel()
        self._verify_result.setObjectName("verifyResult")
        self._verify_result.setWordWrap(True)
        bar.addWidget(self._verify_result, stretch=1)
        return bar

    def _build_result_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("resultPanel")
        row = QHBoxLayout(panel)
        row.setContentsMargins(14, 8, 14, 8)
        title = QLabel("Resultado")
        title.setObjectName("sectionTitle")
        self._result_text = QLabel(RESULT_EMPTY)
        self._result_text.setObjectName("resultText")
        row.addWidget(title)
        row.addWidget(self._result_text, stretch=1)
        return panel

    def _table(self, name: str) -> QTableWidget:
        table = QTableWidget()
        table.setObjectName(name)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        table.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        table.setWordWrap(False)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _build_urn_panel(self) -> QWidget:
        panel = QWidget()
        column = QVBoxLayout(panel)
        column.setContentsMargins(0, 0, 0, 0)
        title = QLabel("Urna")
        title.setObjectName("sectionTitle")
        column.addWidget(title)
        self._urn_table = self._table("urnTable")
        column.addWidget(self._urn_table, stretch=1)
        return panel

    def _build_side_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(420)
        column = QVBoxLayout(panel)
        column.setContentsMargins(0, 0, 0, 0)
        title = QLabel("Censo")
        title.setObjectName("sectionTitle")
        column.addWidget(title)
        self._census_table = self._table("censusTable")
        self._census_table.setColumnCount(4)
        self._census_table.setHorizontalHeaderLabels(["Id", "Nombre", "Mesa", "Marca"])
        self._census_table.verticalHeader().hide()
        column.addWidget(self._census_table, stretch=3)
        traffic_title = QLabel("Tráfico de red")
        traffic_title.setObjectName("sectionTitle")
        column.addWidget(traffic_title)
        self._traffic = QListWidget()
        self._traffic.setObjectName("trafficList")
        self._traffic.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        column.addWidget(self._traffic, stretch=2)
        return panel

    def _open_aes(self) -> None:
        if self._aes_window is None:
            self._aes_window = MainWindow()
        self._aes_window.show()
        self._aes_window.raise_()
        self._aes_window.activateWindow()

    def _show_notice(self, text: str, failure: bool = True) -> None:
        self._notice.setText(text)
        self._set_failure(self._notice, failure)
        self._notice.show()

    def _prepare(self) -> None:
        self._notice.hide()
        try:
            self._service.prepare()
        except DomainError as error:
            self._show_notice(str(error))
            return
        self._refresh()

    def _vote(self) -> None:
        chosen = [o for r, o in self._option_values.items() if r.isChecked()]
        voter = self._voter_combo.currentText()
        if len(chosen) != 1:
            self._show_notice(PICK_OPTION)
            return
        self._notice.hide()
        try:
            self._service.cast_vote(voter, chosen[0])
        except DomainError as error:
            self._show_notice(str(error))
            return
        finally:
            self._clear_option()
        self._verify_result.clear()
        # Primero el exito: si refrescar falla, su aviso de error queda encima.
        self._show_notice(f"Voto de {voter} registrado.", failure=False)
        self._refresh()

    def _act(self, action) -> None:
        self._notice.hide()
        try:
            action()
        except DomainError as error:
            self._show_notice(str(error))
            return
        self._verify_result.clear()
        self._refresh()

    def _verify(self) -> None:
        voter = self._verify_combo.currentText()
        self._notice.hide()
        try:
            check = self._service.verify(voter)
        except DomainError as error:
            self._show_notice(str(error))
            return
        row = None if check.index is None else check.index + 1
        if not check.found:
            text, ok = "Tu voto no está en la urna.", False
        elif check.counted is None:
            text, ok = f"Tu voto está en la fila {row}; aún no hay recuento.", True
        elif check.counted:
            text, ok = f"Tu voto está en la fila {row} y se contó como emitiste.", True
        else:
            text = f"Tu voto está en la fila {row}, pero no se contó como emitiste."
            ok = False
        self._verify_result.setText(text)
        self._set_failure(self._verify_result, not ok)

    @staticmethod
    def _set_failure(label: QLabel, failure: bool) -> None:
        label.setProperty("role", "failure" if failure else "")
        label.style().unpolish(label)
        label.style().polish(label)

    def _fill_combo(self, combo: QComboBox, ids: tuple[str, ...]) -> None:
        current = combo.currentText()
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(ids)
        if current in ids:
            combo.setCurrentText(current)
        combo.blockSignals(False)

    def _refresh(self) -> None:
        actions = self._service.allowed_actions()
        self._prepare_button.setEnabled(Action.PREPARE in actions)
        self._vote_button.setEnabled(Action.VOTE in actions)
        self._close_button.setEnabled(Action.CLOSE in actions)
        self._count_button.setEnabled(Action.COUNT in actions)
        self._voter_combo.setEnabled(Action.VOTE in actions)
        for radio in self._option_values:
            radio.setEnabled(Action.VOTE in actions)
        self._fill_traffic()
        if Action.PREPARE in actions:
            self._show_empty()
            return
        try:
            snapshot = self._service.view()
        except DomainError as error:
            self._show_notice(str(error))
            return
        self._empty.hide()
        phase = PHASE_TEXT.get(snapshot.phase, snapshot.phase)
        self._phase_label.setText(f"Fase: {phase}")
        self._fill_urn(snapshot)
        self._fill_census(snapshot)
        self._fill_combo(self._voter_combo, self._service.voter_ids())
        receipts = self._service.receipt_ids()
        self._fill_combo(self._verify_combo, receipts)
        can_verify = Action.VERIFY in actions and bool(receipts)
        self._verify_combo.setEnabled(can_verify)
        self._verify_button.setEnabled(can_verify)
        self._fill_result(snapshot)

    def _fill_traffic(self) -> None:
        self._traffic.clear()
        for t in self._service.traffic():
            route = f"{t.sender} → {t.receiver}"
            head = route if "->" in t.channel else f"{t.channel} · {route}"
            self._traffic.addItem(f"{head}\n{t.frame_preview}")

    def _fill_result(self, snap: ElectionSnapshot) -> None:
        r = snap.result
        if r is None:
            self._result_text.setText(RESULT_EMPTY)
            return
        self._result_text.setText(
            f"Sí {r.yes} · No {r.no} · En blanco {r.abstain} · Nulos {r.null}"
        )

    def _show_empty(self) -> None:
        self._phase_label.setText(f"Fase: {PHASE_TEXT['']}")
        self._empty.show()
        self._urn_table.clear()
        self._urn_table.setRowCount(0)
        self._urn_table.setColumnCount(0)
        self._census_table.setRowCount(0)
        self._result_text.setText(RESULT_EMPTY)
        self._voter_combo.clear()
        self._verify_combo.clear()
        self._verify_button.setEnabled(False)
        self._verify_combo.setEnabled(False)

    def _fill_urn(self, snap: ElectionSnapshot) -> None:
        table = self._urn_table
        columns = len(snap.alphas)
        labels = ["alfas", "control"] + [f"voto {i + 1}" for i in range(len(snap.rows))]
        table.clear()
        table.setColumnCount(columns)
        table.setRowCount(len(labels))
        table.setHorizontalHeaderLabels([str(i + 1) for i in range(columns)])
        table.setVerticalHeaderLabels(labels)
        control_header = table.verticalHeaderItem(1)
        control_header.setForeground(QBrush(QColor(SECRET)))
        bold = control_header.font()
        bold.setBold(True)
        control_header.setFont(bold)
        for col, alpha in enumerate(snap.alphas):
            table.setItem(0, col, _cell(alpha, PUBLIC))
        for col, control in enumerate(snap.control_hex):
            table.setItem(1, col, _cell(control, SECRET))
        for r, row in enumerate(snap.rows):
            for col, value in enumerate(row):
                table.setItem(2 + r, col, _cell(value, PUBLIC))
        table.resizeColumnsToContents()

    def _fill_census(self, snap: ElectionSnapshot) -> None:
        table = self._census_table
        table.setRowCount(len(snap.census))
        for r, entry in enumerate(snap.census):
            table.setItem(r, 0, _cell(entry.id, mono=False))
            table.setItem(r, 1, _cell(entry.name, mono=False))
            table.setItem(r, 2, _cell(entry.table, mono=False))
            mark = _cell(entry.mark_hex, SECRET) if entry.mark_hex else _cell("—")
            table.setItem(r, 3, mark)
        for column in range(3):
            table.resizeColumnToContents(column)
        table.horizontalHeader().setStretchLastSection(True)
