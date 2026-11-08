"""PySide6 desktop interface for local network inventory."""

import sys
import ipaddress
import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .models import LocalNetwork, ScanOptions, ScanResult
from .network import get_local_networks, validate_target
from .reports import write_reports
from .scanner import ScanCancelled, ScanError, scan_network


class ScanWorker(QThread):
    progress = Signal(str)
    completed = Signal(object, object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, options: ScanOptions, output_dir: Path, prefix: str):
        super().__init__()
        self.options = options
        self.output_dir = output_dir
        self.prefix = prefix
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            result = scan_network(self.options, self.cancel_event, self.progress.emit)
            reports = write_reports(result, self.output_dir, self.prefix)
        except ScanCancelled:
            self.cancelled.emit()
        except Exception as error:
            self.failed.emit(str(error))
        else:
            self.completed.emit(result, reports)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Home Network Scanner {__version__}")
        self.resize(1060, 700)
        self.worker: ScanWorker | None = None
        self.last_reports: tuple[Path, Path] | None = None
        self.local_networks: list[LocalNetwork] = []

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Home Network Inventory")
        title.setObjectName("title")
        subtitle = QLabel("Scan one authorized, directly connected private IPv4 subnet.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        scope_group = QGroupBox("Scan scope")
        scope_form = QFormLayout(scope_group)
        interface_row = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.currentIndexChanged.connect(self.update_target_from_interface)
        self.refresh_button = QPushButton("Refresh interfaces")
        self.refresh_button.clicked.connect(self.refresh_networks)
        interface_row.addWidget(self.interface_combo, 1)
        interface_row.addWidget(self.refresh_button)
        scope_form.addRow("Local interface", interface_row)
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("For example, 192.168.1.0/24")
        scope_form.addRow("Subnet (CIDR)", self.network_input)

        options_row = QHBoxLayout()
        self.services_checkbox = QCheckBox("Service/version detection")
        self.services_checkbox.setToolTip("Probes a bounded list of common TCP ports; disabled by default.")
        self.os_checkbox = QCheckBox("OS fingerprinting")
        self.os_checkbox.setToolTip("Sends additional probes; may need privileges that this app will not request.")
        self.dns_checkbox = QCheckBox("Resolve hostnames")
        self.dns_checkbox.setToolTip("Uses the system DNS resolver for discovered hosts.")
        options_row.addWidget(self.services_checkbox)
        options_row.addWidget(self.os_checkbox)
        options_row.addWidget(self.dns_checkbox)
        options_row.addStretch(1)
        scope_form.addRow("Optional probes", options_row)
        layout.addWidget(scope_group)

        output_group = QGroupBox("Reports")
        output_form = QFormLayout(output_group)
        self.output_input = QLineEdit(str(Path.home() / "HomeNetworkScanner"))
        browse_button = QPushButton("Choose folder")
        browse_button.clicked.connect(self.choose_output_folder)
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_input, 1)
        output_row.addWidget(browse_button)
        output_form.addRow("Output folder", output_row)
        self.prefix_input = QLineEdit("network")
        output_form.addRow("Filename prefix", self.prefix_input)
        layout.addWidget(output_group)

        controls = QHBoxLayout()
        self.start_button = QPushButton("Start scan")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        controls.addWidget(self.start_button)
        controls.addWidget(self.cancel_button)
        controls.addStretch(1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        controls.addWidget(self.progress, 1)
        layout.addLayout(controls)

        self.status_label = QLabel("Ready. No scan has been run.")
        self.status_label.setObjectName("status")
        layout.addWidget(self.status_label)

        self.results_table = QTableWidget(0, 8)
        self.results_table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "MAC", "Vendor", "Device type", "OS guess", "Confidence", "Open services"]
        )
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table, 1)

        report_row = QHBoxLayout()
        self.report_label = QLabel("")
        self.report_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        open_reports_button = QPushButton("Open report folder")
        open_reports_button.setEnabled(False)
        open_reports_button.clicked.connect(self.open_report_folder)
        self.open_reports_button = open_reports_button
        report_row.addWidget(self.report_label, 1)
        report_row.addWidget(open_reports_button)
        layout.addLayout(report_row)

        self.setCentralWidget(root)
        self.setStyleSheet(
            """
            QMainWindow { background: #f3f6f2; }
            QWidget { color: #17231f; font-size: 13px; }
            QLabel#title { font-size: 25px; font-weight: 700; color: #173c32; }
            QLabel#subtitle { color: #53635c; }
            QLabel#status { font-weight: 600; }
            QGroupBox { border: 1px solid #cbd6ce; border-radius: 6px; margin-top: 8px; padding: 12px; font-weight: 650; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QLineEdit, QComboBox, QTableWidget { background: white; border: 1px solid #bac8bf; border-radius: 4px; padding: 7px; }
            QTableWidget { alternate-background-color: #edf2ee; }
            QHeaderView::section { background: #e2eae4; padding: 7px; border: 0; font-weight: 650; }
            QPushButton { background: #e1e9e3; border: 1px solid #b8c7bd; border-radius: 4px; padding: 8px 12px; }
            QPushButton:hover { background: #d3e1d7; }
            QPushButton:disabled { color: #829087; }
            QPushButton#primaryButton { color: white; background: #245a4a; border-color: #245a4a; font-weight: 700; }
            QPushButton#primaryButton:hover { background: #1d493c; }
            QProgressBar { border: 0; background: #d9e3dc; border-radius: 3px; min-height: 7px; max-height: 7px; }
            QProgressBar::chunk { background: #4b9275; border-radius: 3px; }
            """
        )
        self.refresh_networks()

    def refresh_networks(self) -> None:
        self.local_networks = get_local_networks()
        current = self.interface_combo.currentData()
        self.interface_combo.clear()
        for item in self.local_networks:
            label = f"{item.interface}  ·  {item.address}  ·  {item.network}"
            self.interface_combo.addItem(label, item)
        if current:
            for index in range(self.interface_combo.count()):
                if self.interface_combo.itemData(index) == current:
                    self.interface_combo.setCurrentIndex(index)
                    break
        self.update_target_from_interface()
        if not self.local_networks:
            self.status_label.setText("No directly connected private IPv4 interfaces were found.")

    def update_target_from_interface(self) -> None:
        selected = self.interface_combo.currentData()
        if selected:
            self.network_input.setText(selected.network)

    def choose_output_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose report folder", self.output_input.text())
        if path:
            self.output_input.setText(path)

    def _options(self) -> ScanOptions:
        selected = self.interface_combo.currentData()
        if selected is None:
            raise ValueError("No local private IPv4 interface is selected.")
        target = validate_target(self.network_input.text(), selected.interface, self.local_networks)
        return ScanOptions(
            network=str(target),
            interface=selected.interface,
            detect_services=self.services_checkbox.isChecked(),
            detect_os=self.os_checkbox.isChecked(),
            resolve_hostnames=self.dns_checkbox.isChecked(),
        )

    def start_scan(self) -> None:
        try:
            options = self._options()
            output_dir = Path(self.output_input.text()).expanduser()
            if not output_dir.is_absolute():
                raise ValueError("Choose an absolute output folder.")
            prefix = self.prefix_input.text().strip()
            if not prefix:
                raise ValueError("Enter a filename prefix.")
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Check scan settings", str(error))
            return

        address_count = ipaddress.ip_network(options.network).num_addresses
        methods = ["host discovery"]
        if options.detect_services:
            methods.append("common-port service/version probes")
        if options.detect_os:
            methods.append("OS fingerprinting")
        if options.resolve_hostnames:
            methods.append("system DNS lookups")
        message = (
            f"Scan {options.network} on {options.interface} ({address_count:,} addresses)?\n\n"
            f"Methods: {', '.join(methods)}\n"
            f"Output folder: {output_dir}\n\n"
            "Only scan networks you are authorized to inventory."
        )
        if address_count > 256:
            message += "\n\nThis range is larger than /24 and may take longer."
        answer = QMessageBox.question(
            self,
            "Confirm network scan",
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self.results_table.setRowCount(0)
        self.report_label.clear()
        self.last_reports = None
        self.open_reports_button.setEnabled(False)
        self.worker = ScanWorker(options, output_dir, prefix)
        self.worker.progress.connect(self.status_label.setText)
        self.worker.completed.connect(self.scan_completed)
        self.worker.failed.connect(self.scan_failed)
        self.worker.cancelled.connect(self.scan_cancelled)
        self.worker.finished.connect(self.worker_finished)
        self.set_scanning(True)
        self.status_label.setText("Starting scan...")
        self.worker.start()

    def cancel_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Stopping scan...")

    def set_scanning(self, scanning: bool) -> None:
        self.start_button.setEnabled(not scanning)
        self.refresh_button.setEnabled(not scanning)
        self.cancel_button.setEnabled(scanning)
        self.progress.setVisible(scanning)

    def scan_completed(self, result: ScanResult, reports: tuple[Path, Path]) -> None:
        self.last_reports = reports
        self.open_reports_button.setEnabled(True)
        self.report_label.setText(f"Reports: {reports[0].name} and {reports[1].name}")
        self.results_table.setRowCount(len(result.devices))
        for row, device in enumerate(result.devices):
            os_guess = " ".join(value for value in (device.os_family, device.os_product, device.os_version) if value)
            services = ", ".join(f"{item.port}/{item.protocol} {item.name}".strip() for item in device.services)
            values = (
                device.ip,
                device.hostname or "Unknown",
                device.mac or "Unknown",
                device.vendor or "Unknown",
                device.device_type,
                os_guess or "Unknown",
                f"Type: {device.device_type_confidence}; OS: {device.os_confidence}",
                services or "None detected",
            )
            for column, value in enumerate(values):
                self.results_table.setItem(row, column, QTableWidgetItem(value))
        status = f"Scan complete: {len(result.devices)} responsive device(s)."
        if result.partial:
            status = f"Partial scan: {len(result.devices)} responsive device(s)."
        if result.warnings:
            status += f" {len(result.warnings)} warning(s)."
        self.status_label.setText(status)

    def scan_failed(self, message: str) -> None:
        self.status_label.setText("Scan failed.")
        QMessageBox.critical(self, "Scan failed", message)

    def scan_cancelled(self) -> None:
        self.status_label.setText("Scan cancelled. No reports were written.")

    def worker_finished(self) -> None:
        self.set_scanning(False)
        self.worker = None

    def open_report_folder(self) -> None:
        if self.last_reports:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_reports[0].parent)))


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Home Network Scanner")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())