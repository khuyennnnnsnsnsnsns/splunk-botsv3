import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "suricata"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX} sourcetype=*suricata*
    | stats count by src_ip dest_ip signature
    | sort -count
    | head 20
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
            message="Suricata security alert detected",
            details={
                "Source IP": result.get("src_ip", "Unknown"),
                "Destination": result.get("dest_ip", "Unknown"),
                "Signature": result.get("signature", "Unknown"),
                "Count": result.get("count", 0)
            }
        )

    return len(results)

# Alias để tương thích khi gọi run() hoặc detect()
run = detect

if __name__ == "__main__":
    run()
