            
import json
import os
import logging
from datetime import datetime
from mitre.mitre_mapping import get_mapping
from config import LOG_DIR, NORMALIZED_ALERTS_FILE

os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOG_DIR, "detection.log")
logging.basicConfig(
    filename=LOG_FILE_PATH,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def write_normalized_alert(usecase, severity, message, details, mitre):
    timestamp = datetime.utcnow().isoformat() + "Z"
    details = details or {}

    alert_data = {
        "timestamp": timestamp,
        "usecase": usecase,
        "severity": severity,
        "status": "DETECTED",
        "message": message,
        "evidence": details
    }

    if mitre:
        alert_data["mitre"] = {
            "tactic": mitre.get("tactic"),
            "technique_id": mitre.get("technique_id"),
            "technique": mitre.get("technique")
        }
    else:
        alert_data["mitre"] = {
            "tactic": None,
            "technique_id": None,
            "technique": None
        }

    if "Host" in details:
        alert_data["host"] = details["Host"]
    elif "host" in details:
        alert_data["host"] = details["host"]

    if "EventCode" in details:
        alert_data["event_code"] = details["EventCode"]
    elif "event_code" in details:
        alert_data["event_code"] = details["event_code"]

    with open(NORMALIZED_ALERTS_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(alert_data, ensure_ascii=False) + "\n")

def alert(usecase, severity, message, details=None):
    mitre = get_mapping(usecase)

    print("\n" + "=" * 70)
    print(f"[{severity}] {usecase}")
    print(f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Message   : {message}")

    print("\nMITRE ATT&CK")
    if mitre:
        print(f"Tactic       : {mitre['tactic']}")
        print(f"Technique    : {mitre['technique']}")
        print(f"Technique ID : {mitre['technique_id']}")
    else:
        print("MITRE Mapping : Not Found")

    if details:
        print("\nEvidence")
        for key, value in details.items():
            print(f"{key:<15}: {value}")

    print("=" * 70)

    write_normalized_alert(usecase, severity, message, details, mitre)

    if mitre:
        logging.warning(
            f"{usecase} | {severity} | {mitre['tactic']} | {mitre['technique_id']} | {mitre['technique']} | {message} | {details}"
        )
    else:
        logging.warning(f"{usecase} | {severity} | MITRE_NOT_FOUND | {message} | {details}")

def no_alert(usecase):
    print(f"  [OK] {usecase}: No suspicious activity")
    logging.info(f"{usecase} | NO_ALERT")
