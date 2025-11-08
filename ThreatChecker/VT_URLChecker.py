import vt
import time
from WebAutomation.EnvVar import VT_API_KEY

API_KEY = VT_API_KEY


def checkURL(urls):
    """
    Check whether a URL is malicious, suspicious, or clean using VirusTotal official SDK.
    """

    verdicts = {}

    with vt.Client(API_KEY) as client:

        for url in urls:

            print(f"🔎 Submitting URL for analysis: {url}")

            # Step 1: Submit the URL for scanning
            analysis = client.scan_url(url)
            analysis_id = analysis.id

            # Step 2: Wait for analysis to complete
            print("⏳ Waiting for analysis to complete...")
            while True:
                result = client.get_object("/analyses/{}", analysis_id)
                if result.status == "completed":
                    break
                time.sleep(3)

            # Step 3: Get final report
            url_id = vt.url_id(url)
            url_object = client.get_object("/urls/{}", url_id)

            stats = url_object.last_analysis_stats

            harmless = stats.get("harmless", 0)
            suspicious = stats.get("suspicious", 0)
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)

            # Step 4: Print summary
            print("\n📊 Scan Summary:")
            print(f"Harmless:   {harmless}")
            print(f"Suspicious: {suspicious}")
            print(f"Malicious:  {malicious}")
            print(f"Undetected: {undetected}")

            # Step 5: Verdict
            if malicious > 0:
                print(f"\n🚨 Verdict: The URL '{url}' is MALICIOUS.")
                verdicts[url] = 1
            elif suspicious > 0:
                print(f"\n⚠️ Verdict: The URL '{url}' is SUSPICIOUS.")
                verdicts[url] = 2
            else:
                print(f"\n✅ Verdict: The URL '{url}' appears SAFE.")
                verdicts[url] = 0
    return verdicts
