import os


SPLUNK_HOST = "127.0.0.1"
SPLUNK_PORT = 8089
SPLUNK_USERNAME = "FILL ADMIN ACCOUNT"
SPLUNK_PASSWORD = "FILL PASSWORD ACCOUNT"
SPLUNK_SCHEME = "https"
SPLUNK_VERIFY = False

INDEX = "botsv3"
EARLIEST_TIME = "0"
LATEST_TIME = "now"

LOG_DIR = "logs"
NORMALIZED_ALERTS_FILE = os.path.join(LOG_DIR, "normalized_alerts.jsonl")
MITRE_COVERAGE_JSON = os.path.join(LOG_DIR, "mitre_coverage.json")
MITRE_COVERAGE_JSONL = os.path.join(LOG_DIR, "mitre_coverage.jsonl")
