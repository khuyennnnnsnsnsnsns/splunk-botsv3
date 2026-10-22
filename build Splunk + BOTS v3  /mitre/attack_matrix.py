import sys
from pathlib import Path

# Thêm thư mục gốc dự án vào sys.path để chạy trực tiếp không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

import json
from datetime import datetime
from mitre.mitre_mapping import MITRE_MAPPING

# Cấu hình đường dẫn
LOG_DIR = BASE_DIR / "logs"
OUTPUT_FILE = LOG_DIR / "mitre_coverage.json"

IMPLEMENTED_USECASES = {
    "brute_force",
    "recon",
    "c2",
    "powershell",
    "process_creation",
    "dns_detection",
    "http_detection",
    "suricata",
    "windows_service",
    "account_manipulation"
}
# Tập kỹ thuật mục tiêu (Đã loại bỏ T1053 và T1068, bổ sung T1190)
TARGET_TECHNIQUES = {
    # INITIAL ACCESS
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
    },
    # EXECUTION
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution"
    },
    # CREDENTIAL ACCESS
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "Credential Access"
    },
    # DISCOVERY
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery"
    },
    # COMMAND AND CONTROL
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control"
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control"
    },
    # PERSISTENCE
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence"
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence"
    }
}

def get_covered_techniques():
    covered = {}

    for technique_id, target in TARGET_TECHNIQUES.items():
        matched_usecases = []

        for usecase, mapping in MITRE_MAPPING.items():

            if usecase not in IMPLEMENTED_USECASES:
                continue

            mapped_id = mapping.get("technique_id")

            if mapped_id == technique_id:
                matched_usecases.append(usecase)

        if matched_usecases:
            covered[technique_id] = {
                "technique_id": technique_id,
                "technique": target["name"],
                "tactic": target["tactic"],
                "usecases": matched_usecases
            }

    return covered

def build_technique_coverage():
    covered = get_covered_techniques()
    results = []

    for technique_id, target in TARGET_TECHNIQUES.items():
        if technique_id in covered:
            status = "COVERED"
            usecases = covered[technique_id]["usecases"]
        else:
            status = "NOT COVERED"
            usecases = []

        results.append({
            "technique_id": technique_id,
            "technique": target["name"],
            "tactic": target["tactic"],
            "status": status,
            "usecases": usecases
        })
    return results

def calculate_overall_coverage(results):
    total = len(results)
    covered = sum(1 for item in results if item["status"] == "COVERED")
    not_covered = total - covered
    percentage = round((covered / total) * 100, 2) if total > 0 else 0.0

    return {
        "total": total,
        "covered": covered,
        "not_covered": not_covered,
        "percentage": percentage
    }

def calculate_tactic_coverage(results):
    tactics = {}
    for item in results:
        tactic = item["tactic"]
        if tactic not in tactics:
            tactics[tactic] = {"total": 0, "covered": 0, "not_covered": 0}

        tactics[tactic]["total"] += 1
        if item["status"] == "COVERED":
            tactics[tactic]["covered"] += 1
        else:
            tactics[tactic]["not_covered"] += 1

    for tactic in tactics:
        total = tactics[tactic]["total"]
        covered = tactics[tactic]["covered"]
        tactics[tactic]["percentage"] = round((covered / total) * 100, 2) if total > 0 else 0.0

    return tactics

def build_report():
    technique_results = build_technique_coverage()
    overall = calculate_overall_coverage(technique_results)
    tactics = calculate_tactic_coverage(technique_results)

    return {
        "generated_at": datetime.now().isoformat(),
        "project": "SOC Automation",
        "mitre_attack_coverage": {
            "overall": overall,
            "covered_techniques": overall["covered"],
            "not_covered_techniques": overall["not_covered"]
        },
        "tactics": tactics,
        "techniques": technique_results
    }

def save_report(report):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)
    return OUTPUT_FILE

def print_header():
    print("\n" + "=" * 70)
    print("               MITRE ATT&CK COVERAGE")
    print("=" * 70)

def print_overall(report):
    overall = report["mitre_attack_coverage"]["overall"]
    print(f'Overall Coverage     : {overall["percentage"]}%')
    print(f'Covered Techniques   : {overall["covered"]}')
    print(f'Not Covered          : {overall["not_covered"]}')
    print(f'Total Techniques     : {overall["total"]}')

def print_tactics(report):
    print("\nTACTIC COVERAGE\n" + "-" * 70)
    for tactic, tactic_data in report["tactics"].items():
        print(f"{tactic:<25} : {tactic_data['covered']}/{tactic_data['total']} ({tactic_data['percentage']}%)")

def print_techniques(report):
    print("\nTECHNIQUE COVERAGE\n" + "-" * 70)
    for item in report["techniques"]:
        usecase_text = ", ".join(item["usecases"])
        print(f"{item['technique_id']:<12} {item['technique']:<42} {item['status']:<12} {usecase_text}")

def main():
    report = build_report()
    output_file = save_report(report)
    print_header()
    print_overall(report)
    print_tactics(report)
    print_techniques(report)
    print("\n" + "=" * 70)
    print(f"JSON Report : {output_file}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
