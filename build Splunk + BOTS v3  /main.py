import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from usecases import (
    brute_force,
    recon,
    c2,
    powershell,
    process_creation,
    dns_detection,
    http_detection,
    suricata,
    windows_service,
    account_manipulation
)
from mitre.mitre_exporter import export_mitre_coverage

def main():
    print("=" * 70)
    print("                 SOC AUTOMATION SYSTEM")
    print("=" * 70)

    total_alerts = 0

    detectors = [
        ("Brute Force", brute_force.run),
        ("Reconnaissance", recon.run),
        ("Command & Control", c2.run),
        ("PowerShell", powershell.run),
        ("Process Creation", process_creation.run),
        ("DNS Detection", dns_detection.run),
        ("HTTP Detection", http_detection.run),
        ("Suricata", suricata.run),
        ("Windows Service", windows_service.run),
        ("Account Manipulation", account_manipulation.run)
    ]

 
    for name, detector in detectors:
        try:
            alerts = detector()
            total_alerts += (alerts or 0)
        except Exception as e:
            print(f"[ERROR] {name} detection failed: {e}")

    print("\n" + "=" * 70)
    print(f"[+] Detection completed. Total alerts/events generated: {total_alerts}")
    print("=" * 70)

    print("\n[+] Updating & Exporting MITRE ATT&CK Coverage...")
    try:
        export_mitre_coverage()
    except Exception as e:
        print(f"[ERROR] Failed to export MITRE coverage: {e}")

if __name__ == "__main__":
    main()
                           
