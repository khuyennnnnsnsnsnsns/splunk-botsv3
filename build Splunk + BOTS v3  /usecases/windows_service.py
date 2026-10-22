import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "windows_service"

SPL = f"""
index={INDEX} EventCode=7045
| table _time host EventCode _raw
| sort -_time
"""

def run():
    print(f"\n[+] Running {USECASE.upper()} Detection...")
    client = SplunkClient()

    results = client.search_results(SPL)

    if not results:
        no_alert(USECASE)
        return 0

    for result in results:
        alert(
            usecase=USECASE,
            severity="MEDIUM",
            message="Windows Service installation detected",
            details={
                "time": result.get("_time"),
                "host": result.get("host"),
                "event_code": result.get("EventCode"),
                "raw": result.get("_raw")
            }
        )

    return len(results)

# Alias để tương thích khi gọi run() hoặc detect()
detect = run

if __name__ == "__main__":
    run()
