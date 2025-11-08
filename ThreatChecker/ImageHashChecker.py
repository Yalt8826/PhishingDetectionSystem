import hashlib
import requests
import os
from WebAutomation.EnvVar import (
    VT_API_KEY,
)  # Make sure this points to your VirusTotal API key variable

VIRUSTOTAL_API_KEY = VT_API_KEY


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


def download_and_check_images(email_data):
    images = email_data.get("inline_images", [])
    if not images:
        print("No inline images found.")
        return

    if not os.path.exists("downloaded_images"):
        os.makedirs("downloaded_images")

    for i, url in enumerate(images, 1):
        try:
            print(f"\nDownloading image {i}: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Guess file extension or use "img" fallback
                file_ext = url.split("?")[0].split(".")[-1][:4]
                if not file_ext.isalpha() or len(file_ext) > 4:
                    file_ext = "img"
                fname = f"downloaded_images/image_{i}.{file_ext}"
                with open(fname, "wb") as imgf:
                    imgf.write(response.content)

                # Hash and check via VirusTotal
                hash_value = get_sha256(fname)
                print(f"SHA-256: {hash_value}")
                check_virustotal(hash_value)
            else:
                print(f"Failed to download image (status {response.status_code})")
        except Exception as e:
            print(f"Download error: {e}")
