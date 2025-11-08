import hashlib
import requests

VIRUSTOTAL_API_KEY = "40d0cc3a76dd9b28371ea3edc8493dfcba082511874098dbe117f16981f6887c"


def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"VirusTotal result for hash {hash_value}:")
        print(stats)
        if stats["malicious"] > 0:
            print("⚠️ Malicious!")
        elif stats["undetected"] > 0 and stats["malicious"] == 0:
            print("✓ Harmless or clean.")
        else:
            print("No verdict, may be unknown or suspicious.")
    elif response.status_code == 404:
        print(f"Hash {hash_value} not found in VirusTotal DB.")
    else:
        print(f"Error: {response.status_code} {response.text}")


if __name__ == "__main__":
    print(
        check_virustotal(
            "55a555ab3d3420d8e6f20bb22d4ed4614d6bbb2c64c30479a1673a130b06d746"
        )
    )
