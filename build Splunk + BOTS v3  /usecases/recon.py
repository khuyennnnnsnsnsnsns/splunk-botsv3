import sys
from pathlib import Path

# Thêm thư mục gốc vào sys.path để chạy độc lập không bị lỗi import
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "recon"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX}
    | stats dc(dest_ip) as unique_targets by src_ip
    | where unique_targets > 30
    | sort -unique_targets
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
            message="Possible network scanning detected",
            details={
                "Source IP": result.get("src_ip", "Unknown"),
                "Targets": result.get("unique_targets", 0)
            }
        )

    return len(results)

# Alias để tương thích khi gọi run() hoặc detect()
run = detect

if __name__ == "__main__":
    run()
