import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert

USECASE = "account_manipulation"

SPL = r"""
index=botsv3 EventCode=4732
| rex field=_raw "Member:\s+Security ID:\s+(?<member>[^\s]+)"
| rex field=_raw "Group:\s+Security ID:\s+(?<group_sid>[^\s]+)"
| rex field=_raw "Group Name:\s+(?<group_name>[^\s]+)"
| rex field=_raw "Subject:\s+Security ID:\s+(?<subject>[^\s]+)"
| table _time host EventCode subject member group_name _raw
"""

def run():
    client = SplunkClient()
    results = client.search_results(SPL)

    if not results:
        no_alert(USECASE)
        return 0

    for result in results:
        alert(
            USECASE,
            "MEDIUM",
            "User added to a security-enabled local group",
            {
                "time": result.get("_time"),
                "host": result.get("host"),
                "event_code": result.get("EventCode"),
                "subject": result.get("subject"),
                "member": result.get("member"),
                "group": result.get("group_name"),
                "raw": result.get("_raw")
            }
        )

    return len(results)

if __name__ == "__main__":
    run()
