from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHBoxLayout, QCheckBox, QComboBox, QFileDialog, QLineEdit, QGroupBox, QHeaderView
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt
from core_logic import get_windows_version, get_installed_software, generate_report
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import sys
import csv
class ConfigDetectorUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Configuration Detector")
        self.resize(800, 500)

        self.software_list = []
        self.filtered_software = []
        self.show_microsoft = False

        self.init_ui()
        self.run_scan()

    def init_ui(self):
        layout = QVBoxLayout()

        self.version_label = QLabel("Windows Version: Detecting...")
        layout.addWidget(self.version_label, alignment=Qt.AlignmentFlag.AlignLeft)

        # Search and Filter Area
        filter_layout = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by name or publisher...")
        self.search_bar.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.search_bar)

        layout.addLayout(filter_layout)

        # App Table Group (User Apps)
        self.user_group = QGroupBox("User Installed Applications")
        user_group_layout = QVBoxLayout()
        self.user_table = self.create_table()
        user_group_layout.addWidget(self.user_table)
        self.user_group.setLayout(user_group_layout)
        layout.addWidget(self.user_group)

        # Show Microsoft Checkbox
        self.microsoft_checkbox = QCheckBox("Show Microsoft Applications")
        self.microsoft_checkbox.stateChanged.connect(self.toggle_microsoft_apps)
        layout.addWidget(self.microsoft_checkbox)

        # Generate Report Button
        self.report_btn = QPushButton("Generate Report")
        self.report_btn.clicked.connect(self.save_report)
        layout.addWidget(self.report_btn)

        self.setLayout(layout)

    def create_table(self):
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Name", "Version", "Publisher", "Source"])
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectItems)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)

        copy_action = QAction("Copy", table)
        copy_action.triggered.connect(lambda: self.copy_selection(table))
        table.addAction(copy_action)

        return table

    def copy_selection(self, table):
        selection = table.selectedItems()
        if selection:
            clipboard_text = "\t".join(item.text() for item in selection)
            QApplication.clipboard().setText(clipboard_text)

    def run_scan(self):
        self.version_label.setText(f"Windows Version: {get_windows_version()}")
        self.software_list = get_installed_software()
        self.apply_filters()

    def apply_filters(self):
        text = self.search_bar.text().lower()

        if self.show_microsoft:
            filtered_apps = self.software_list
        else:
            filtered_apps = [app for app in self.software_list
                             if 'microsoft' not in app.get("DisplayName", "").lower()
                             and 'microsoft' not in app.get("Publisher", "").lower()]

        def app_sort(app):
            return app.get("DisplayName", "").lower()

        if text:
            filtered_apps = [app for app in filtered_apps if text in app.get("DisplayName", "").lower()
                             or text in app.get("Publisher", "").lower()]

        self.populate_table(self.user_table, filtered_apps)

    def populate_table(self, table, apps):
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for row, app in enumerate(apps):
            table.insertRow(row)
            for col, key in enumerate(["DisplayName", "DisplayVersion", "Publisher", "Source"]):
                value = app.get(key, "N/A")
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))  # Tooltip with full text
                table.setItem(row, col, item)
        table.setSortingEnabled(True)
        table.sortItems(0, Qt.SortOrder.AscendingOrder)

    def toggle_microsoft_apps(self):
        try:
            self.show_microsoft = self.microsoft_checkbox.isChecked()
            print(f"[DEBUG] Checkbox toggled. Show Microsoft: {self.show_microsoft}")
            self.apply_filters()
        except Exception as e:
            print(f"[ERROR] Toggle failed: {e}")

    def save_report(self):
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Save Report", "",
            "Text Files (*.txt);;PDF Files (*.pdf);;JSON Files (*.json);;CSV Files (*.csv)")

        if not file_path:
            return

        # Ensure proper file extension
        if "PDF Files" in selected_filter and not file_path.endswith(".pdf"):
            file_path += ".pdf"
        elif "Text Files" in selected_filter and not file_path.endswith(".txt"):
            file_path += ".txt"
        elif "JSON Files" in selected_filter and not file_path.endswith(".json"):
            file_path += ".json"
        elif "CSV Files" in selected_filter and not file_path.endswith(".csv"):
            file_path += ".csv"

        try:
            if file_path.endswith(".pdf"):
                self.save_as_pdf(file_path)
            elif file_path.endswith(".csv"):
                self.save_as_csv(file_path)
            else:
                report = generate_report(get_windows_version(), self.software_list)
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(report)
            print(f"[✓] Report saved to {file_path}")
        except Exception as e:
            print(f"[!] Failed to save report: {e}")

    def save_as_csv(self, file_path):
        # Export everything: both user and Microsoft apps
        all_apps = sorted(self.software_list, key=lambda app: app.get("DisplayName", "").lower())

        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Name", "Version", "Publisher", "Source"])  # headers

            for app in all_apps:
                row = [
                    app.get("DisplayName", "N/A"),
                    app.get("DisplayVersion", "N/A"),
                    app.get("Publisher", "N/A"),
                    app.get("Source", "N/A")
                ]
                writer.writerow(row)

    def save_as_pdf(self, file_path):
        report = generate_report(get_windows_version(), self.software_list)

        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter
        margin = 50
        line_height = 14

        lines = report.split('\n')
        y = height - margin

        for line in lines:
            c.drawString(margin, y, line)
            y -= line_height
            if y <= margin:
                c.showPage()
                y = height - margin

        c.save()
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigDetectorUI()
    window.show()
    sys.exit(app.exec())
