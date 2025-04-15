import subprocess
import platform
import json

def get_windows_version():
    try:
        output = subprocess.check_output(["powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption"], text=True)
        return output.strip()
    except Exception as e:
        return f"Error retrieving Windows version: {e}"

def get_installed_apps():
    try:
        ps_script = r"""
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { $_.DisplayName } |
        ConvertTo-Json
        """
        output = subprocess.check_output(["powershell", "-Command", ps_script], text=True)
        apps = json.loads(output)
        if isinstance(apps, dict):
            apps = [apps]
        return apps
    except Exception as e:
        return f"Error retrieving installed apps: {e}"

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This script is intended to run on Windows.")
    else:
        print("Windows Version:", get_windows_version())
        print("\nInstalled Applications:\n")
        apps = get_installed_apps()
        if isinstance(apps, str):
            print(apps)
        else:
            for app in apps:
                name = app.get("DisplayName", "Unknown")
                version = app.get("DisplayVersion", "N/A")
                publisher = app.get("Publisher", "N/A")
                print(f"{name} | Version: {version} | Publisher: {publisher}")