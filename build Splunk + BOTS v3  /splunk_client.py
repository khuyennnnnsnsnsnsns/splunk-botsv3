import requests
import urllib3

from config import (
    SPLUNK_HOST,
    SPLUNK_PORT,
    SPLUNK_USERNAME,
    SPLUNK_PASSWORD,
    SPLUNK_SCHEME,
    SPLUNK_VERIFY,
    EARLIEST_TIME,
    LATEST_TIME
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkClient:
    _instance = None

    def __new__(cls):
        """Singleton: sử dụng một SplunkClient thống nhất trong hệ thống."""
        if cls._instance is None:
            cls._instance = super(SplunkClient, cls).__new__(cls)

            cls._instance.base_url = (
                f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}"
            )

            cls._instance.auth = (
                SPLUNK_USERNAME,
                SPLUNK_PASSWORD
            )

        return cls._instance

    def search_results(self, query):
        """
        Tạo Splunk search job ở chế độ blocking,
        sau đó lấy toàn bộ final results với count=0.
        """

        cleaned_query = query.strip()

        if (
            not cleaned_query.lower().startswith("search")
            and not cleaned_query.startswith("|")
        ):
            cleaned_query = f"search {cleaned_query}"

       
        create_url = f"{self.base_url}/services/search/jobs"

        payload = {
            "search": cleaned_query,
            "exec_mode": "blocking",
            "earliest_time": EARLIEST_TIME,
            "latest_time": LATEST_TIME
        }

        try:
            response = requests.post(
                create_url,
                params={"output_mode": "json"},
                auth=self.auth,
                data=payload,
                verify=SPLUNK_VERIFY,
                timeout=300
            )

            response.raise_for_status()

            data = response.json()
            sid = data.get("sid")

            if not sid:
                print("[ERROR] Splunk did not return a search SID")
                return []

           
            results_url = (
                f"{self.base_url}/services/search/jobs/{sid}/results"
            )

            result_response = requests.get(
                results_url,
                params={
                    "output_mode": "json",
                    "count": 0
                },
                auth=self.auth,
                verify=SPLUNK_VERIFY,
                timeout=300
            )

            result_response.raise_for_status()

            result_data = result_response.json()

            return result_data.get("results", [])

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Splunk search failed: {e}")

            if hasattr(e, "response") and e.response is not None:
                print(f"[ERROR] Splunk response: {e.response.text}")

            return []

        except ValueError as e:
            print(f"[ERROR] Failed to parse Splunk JSON response: {e}")
            return []
