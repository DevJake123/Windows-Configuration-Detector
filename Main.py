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
                $allApps = @()
                $registryPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )

                foreach ($path in $registryPaths) {
                    $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
                    foreach ($item in $items) {
                        $allApps += [PSCustomObject]@{
                            DisplayName    = $item.DisplayName
                            DisplayVersion = if ($item.DisplayVersion) { $item.DisplayVersion } else { "N/A" }
                            Publisher      = if ($item.Publisher)      { $item.Publisher }      else { "N/A" }
                            Source         = "Registry"
                        }
                    }
                }

                # Get Microsoft Store (UWP) apps
                $uwpApps = Get-AppxPackage | Where-Object { $_.Name } | ForEach-Object {
                    [PSCustomObject]@{
                        DisplayName    = $_.Name
                        DisplayVersion = if ($_.Version)   { $_.Version.ToString() } else { "N/A" }
                        Publisher      = if ($_.Publisher) { $_.Publisher } else { "N/A" }
                        Source         = "Store"
                    }
                }

                $allApps += $uwpApps
                $allApps | Sort-Object DisplayName | ConvertTo-Json -Depth 2
                """
        output = subprocess.check_output(["powershell", "-Command", ps_script], text=True)
        apps = json.loads(output)
        if isinstance(apps, dict):  # Happens when only one app is returned
            apps = [apps]
        return apps
    except Exception as e:
        return f"Error retrieving installed apps: {e}"
def categorize_apps(apps):
    system_apps = []
    installed_apps = []

    system_keywords = [
        "Microsoft", ".NET", "Visual C++", "Redistributable", "Windows", "Runtime", "Edge", "Defender"
    ]

    for app in apps:
        name = app.get("DisplayName", "").lower()
        publisher = app.get("Publisher", "").lower()

        if any(keyword.lower() in name or keyword.lower() in publisher for keyword in system_keywords):
            system_apps.append(app)
        else:
            installed_apps.append(app)

    return system_apps, installed_apps

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This script is intended to run on Windows.")
    else:
        print("Windows Version:", get_windows_version())

        apps = get_installed_apps()
        if isinstance(apps, str):
            print(apps)
        else:
            system_apps, installed_apps = categorize_apps(apps)

            print("\n=== System Apps (Windows & Microsoft Components) ===\n")
            for app in system_apps:
                print(f"{app.get('DisplayName', 'N/A')} | Version: {app.get('DisplayVersion', 'N/A')} | Publisher: {app.get('Publisher', 'N/A')} | Source: {app.get('Source', 'N/A')}")

            print("\n=== Installed Apps (User-installed) ===\n")
            for app in installed_apps:
                print(f"{app.get('DisplayName', 'N/A')} | Version: {app.get('DisplayVersion', 'N/A')} | Publisher: {app.get('Publisher', 'N/A')} | Source: {app.get('Source', 'N/A')}")