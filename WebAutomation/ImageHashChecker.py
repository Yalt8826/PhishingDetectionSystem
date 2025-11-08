import hashlib
import requests
import os
from EnvVar import VT_API_KEY
import sys
import json

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
    verdict = {"result": None, "stats": None, "error": None}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            verdict["stats"] = stats
            if stats["malicious"] > 0:
                verdict["result"] = "malicious"
            elif stats["undetected"] > 0 and stats["malicious"] == 0:
                verdict["result"] = "clean"
            else:
                verdict["result"] = "unknown/suspicious"
        elif response.status_code == 404:
            verdict["result"] = "not_found"
            verdict["error"] = "Hash not found in VirusTotal DB."
        else:
            verdict["result"] = "error"
            verdict["error"] = f"Error: {response.status_code} {response.text}"
    except Exception as e:
        verdict["result"] = "error"
        verdict["error"] = str(e)
    return verdict


def download_and_check_images(email_data):
    images = email_data.get("inline_images", [])
    result_json = {}
    if not images:
        print("No inline images found.")
        return result_json
    if not os.path.exists("downloaded_images"):
        os.makedirs("downloaded_images")
    for i, url in enumerate(images, 1):
        fname = None
        hash_value = None
        vt_verdict = None
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
                # Hash and check VT
                hash_value = get_sha256(fname)
                print(f"SHA-256: {hash_value}")
                vt_verdict = check_virustotal(hash_value)
            else:
                vt_verdict = {
                    "result": "error",
                    "error": f"Failed to download image (status {response.status_code})",
                }
        except Exception as e:
            vt_verdict = {"result": "error", "error": f"Download error: {e}"}
        finally:
            if fname and os.path.exists(fname):
                try:
                    os.remove(fname)
                    print(f"Removed temporary file: {fname}")
                except Exception as rm_exc:
                    print(f"Failed to delete {fname}: {rm_exc}")
            # Store results for main.py
            result_json[url] = {"sha256": hash_value, "virustotal": vt_verdict}
    return result_json


if __name__ == "__main__":
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "image_hash_results.json"
    output_file = output_file.replace("\\", "/")  # Convert any accidental backslashes

    with open(input_file, "r") as f:
        email_data = json.load(f)
    results = download_and_check_images(email_data)
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Image hash check complete. Results saved to {output_file}")
