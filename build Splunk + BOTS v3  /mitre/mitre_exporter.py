import json
from pathlib import Path
from mitre.attack_matrix import build_report, save_report

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
INPUT_FILE = LOG_DIR / "mitre_coverage.json"
OUTPUT_FILE = LOG_DIR / "mitre_coverage.jsonl"

def export_mitre_coverage():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not INPUT_FILE.exists():
        report = build_report()
        save_report(report)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    generated_at = data["generated_at"]
    overall = data["mitre_attack_coverage"]["overall"]

    events = []

    events.append({
        "event_type": "overall",
        "project": "SOC Automation",
        "generated_at": generated_at,
        "total": overall["total"],
        "covered": overall["covered"],
        "not_covered": overall["not_covered"],
        "coverage_percentage": overall["percentage"]
    })

    for tactic, values in data["tactics"].items():
        events.append({
            "event_type": "tactic",
            "project": "SOC Automation",
            "generated_at": generated_at,
            "tactic": tactic,
            "total": values["total"],
            "covered": values["covered"],
            "not_covered": values["not_covered"],
            "coverage_percentage": values["percentage"]
        })

    for technique in data["techniques"]:
        events.append({
            "event_type": "technique",
            "project": "SOC Automation",
            "generated_at": generated_at,
            "technique_id": technique["technique_id"],
            "technique": technique["technique"],
            "tactic": technique["tactic"],
            "status": technique["status"],
            "usecases": ",".join(technique["usecases"])
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print("\n" + "=" * 70)
    print("MITRE ATT&CK EXPORT")
    print("=" * 70)
    print(f"[OK] Input  : {INPUT_FILE}")
    print(f"[OK] Output : {OUTPUT_FILE}")
    print(f"[OK] Events : {len(events)}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    export_mitre_coverage()
