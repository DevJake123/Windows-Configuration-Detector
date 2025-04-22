# Windows Configuration Detector

## Overview
The Windows Configuration Detector is a Python-based GUI application that scans and displays information about installed software and the current Windows operating system version. It allows users to filter results, include or exclude Microsoft applications, and export reports in various formats such as TXT, PDF, CSV, and JSON.

This tool is especially useful for IT professionals, QA testers, and system administrators who need quick insights into a Windows machine's configuration.

---

## Features
- Detects the current Windows version and build.
- Lists software from both:
  - Windows Registry (traditional programs)
  - Microsoft Store (UWP apps)
- Search functionality by name or publisher.
- Option to include/exclude Microsoft applications.
- Right-click copy functionality in the app table.
- One-click report generation with support for:
  - Plain text (.txt)
  - PDF (.pdf)
  - JSON (.json)
  - CSV (.csv)
- File location shortcuts for software with valid paths.

---

## Technologies Used
- Python 3
- PyQt6: GUI toolkit for building desktop interfaces
- PowerShell: Backend system interrogation using Windows commands
- ReportLab: PDF report generation
- CSV/JSON: Built-in Python libraries for file export

---

## Setup Instructions

### Prerequisites
- Python 3.8 or newer
- Windows OS (required for PowerShell support)
- Ensure PowerShell is accessible via command line (`powershell` command)

### Running the Application
- For the GUI:
  ```bash
  python ui_logic.py
  ```
- For console output:
  ```bash
  python core_logic.py
  ```

---

## File Structure
```
windows-config-detector/
├── core_logic.py
├── ui_logic.py
├── README.md
```

---

## GUI Mode
- Displays software in a sortable, searchable table.
- Options to filter Microsoft applications.
- Export button to generate reports.

---

## Authors
Jacob Brown, Gabriel Hernandez, Rachelle Difilippo
