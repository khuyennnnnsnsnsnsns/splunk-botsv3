import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from splunk_client import SplunkClient
from alerts.alert_manager import alert, no_alert
from config import INDEX

USECASE = "process_creation"

def detect():
    print(f"\n[+] Running {USECASE.upper()} Detection...")

    query = f"""
    index={INDEX} EventCode=1
    | stats count by host Image ParentImage
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
            severity="LOW",
            message="Process creation event detected",
            details={
                "Host": result.get("host", "Unknown"),
                "Image": result.get("Image", "Unknown"),
                "Parent Image": result.get("ParentImage", "Unknown"),
                "Count": result.get("count", 0)
            }
        )

    return len(results)

run = detect

if __name__ == "__main__":
    run()
