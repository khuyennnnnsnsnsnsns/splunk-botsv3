import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "powershell"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX} powershell
    | stats count by host src_ip
    | where count > 5
    | sort -count
    """

    client = SplunkClient()
    results = client.search_results(query)

    if not results:
        no_alert(USECASE)
        return 0

    for result in results:
        alert(
            usecase=USECASE,
            severity="MEDIUM",
            message="Suspicious PowerShell activity detected",
            details={
                "Host": result.get("host", "Unknown"),
                "Source IP": result.get("src_ip", "Unknown"),
                "Events": result.get("count", 0)
            }
        )

    return len(results)

# Alias để tương thích khi gọi run() hoặc detect()
run = detect

if __name__ == "__main__":
    run()
