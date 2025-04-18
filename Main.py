import subprocess
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Global Variables
software_list = []
windows_version = ""


# ------------------- Utility Functions -------------------

def run_powershell_command(script):
    """Executes a PowerShell command and returns the output."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] PowerShell error:\n{e.stderr}")
        return None


def parse_json(raw_output):
    """Parses a raw JSON string into a Python object."""
    if not raw_output:
        print("[!] Empty PowerShell output.")
        return []
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse JSON:\n{raw_output[:200]}")
        return []


# ------------------- System Information -------------------

def get_windows_version():
    """Fetches Windows version, build, and architecture info."""
    script = r"""
    $os = Get-CimInstance Win32_OperatingSystem
    $arch = (Get-CimInstance Win32_Processor).AddressWidth
    [PSCustomObject]@{
        Name         = $os.Caption
        Version      = $os.Version
        BuildNumber  = $os.BuildNumber
        Architecture = "$arch-bit"
    } | ConvertTo-Json
    """

    output = run_powershell_command(script)
    info = parse_json(output)

    if isinstance(info, list) and info:
        info = info[0]
    elif not isinstance(info, dict):
        return "Windows Version: Unknown"

    return (
        f"{info.get('Name', 'Windows')} "
        f"Version {info.get('Version', 'N/A')} "
        f"(Build {info.get('BuildNumber', 'N/A')}, {info.get('Architecture', 'N/A')})"
    )


# ------------------- Software Enumeration -------------------

def fetch_registry_apps():
    """Collects software listed in Windows Registry."""
    script = r"""
    $apps = @()
    $paths = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    )
    foreach ($path in $paths) {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
        foreach ($item in $items) {
            $apps += [PSCustomObject]@{
                DisplayName    = $item.DisplayName
                DisplayVersion = if ($item.DisplayVersion) { $item.DisplayVersion } else { "N/A" }
                Publisher      = if ($item.Publisher) { $item.Publisher } else { "N/A" }
                Source         = "Registry"
            }
        }
    }
    $apps | Sort-Object DisplayName | ConvertTo-Json -Depth 2
    """
    return parse_json(run_powershell_command(script))


def fetch_store_apps():
    """Collects apps installed from the Microsoft Store."""
    script = r"""
    Get-AppxPackage | Where-Object { $_.Name } | ForEach-Object {
        [PSCustomObject]@{
            DisplayName    = $_.Name
            DisplayVersion = $_.Version.ToString()
            Publisher      = if ($_.Publisher) { $_.Publisher } else { "N/A" }
            Source         = "Store"
        }
    } | Sort-Object DisplayName | ConvertTo-Json -Depth 2
    """
    return parse_json(run_powershell_command(script))


def get_installed_software():
    """Returns a combined list of registry and store applications in parallel."""
    with ThreadPoolExecutor() as executor:
        registry_future = executor.submit(fetch_registry_apps)
        store_future = executor.submit(fetch_store_apps)
        return registry_future.result() + store_future.result()


# ------------------- Report Generation -------------------

def generate_report(windows_version, software_list):
    """Formats and returns a readable software report string."""

    def format_app(app):
        return (
            f"- {app.get('DisplayName', 'Unknown')} "
            f"| Version: {app.get('DisplayVersion', 'N/A')} "
            f"| Publisher: {app.get('Publisher', 'N/A')}"
        )

    # Exclude Microsoft apps from user-installed apps
    system_apps = [
        app for app in software_list
        if 'microsoft' in app.get("DisplayName", "").lower() or 'microsoft' in app.get("Publisher", "").lower()
    ]

    user_apps = [app for app in software_list if app not in system_apps]

    report_lines = [
        f"Windows Version: {windows_version}\n",
        "=== User Installed Software ===\n",
        *map(format_app, user_apps),
        "\n=== System Software (Microsoft) ===\n",
        *map(format_app, system_apps)
    ]

    return "\n".join(report_lines)


# ------------------- Main Execution -------------------

def main():
    global software_list, windows_version

    print("[*] Gathering system information...")
    windows_version = get_windows_version()

    print("[*] Gathering installed software...")
    software_list = get_installed_software()

    print("[*] Compiling report...\n")
    report_text = generate_report(windows_version, software_list)
    print(report_text)

    save = input("\nDo you want to save this report to a .txt file? (y/n): ").strip().lower()
    if save == 'y':
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"software_report_{timestamp}.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write(report_text)
        print(f"[✓] Report saved as: {filename}")
    else:
        print("[*] Report not saved.")


if __name__ == "__main__":
    main()