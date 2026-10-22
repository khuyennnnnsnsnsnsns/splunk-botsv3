import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "c2"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX}
    | stats count by src_ip dest_ip
    | where count > 30
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
            severity="HIGH",
            message="Repeated network communication detected",
            details={
                "Source IP": result.get("src_ip", "Unknown"),
                "Destination": result.get("dest_ip", "Unknown"),
                "Connections": result.get("count", 0)
            }
        )

    return len(results)

# Alias để đảm bảo tương thích khi main.py gọi run() hoặc detect()
run = detect

if __name__ == "__main__":
    run()
