import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "dns_detection"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX} sourcetype=*dns*
    | stats dc(query) as unique_domains by src_ip
    | where unique_domains > 50
    | sort -unique_domains
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
            message="High number of unique DNS queries detected",
            details={
                "Source IP": result.get("src_ip", "Unknown"),
                "Domains": result.get("unique_domains", 0)
            }
        )

    return len(results)

run = detect

if __name__ == "__main__":
    run()
