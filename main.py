import json
import subprocess
import os

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from Extractor.mailExtract import fetch_latest_email
from Extractor.mailExtract import SCOPES
from Extractor.URLExtract import extract_urls_from_json
from ThreatChecker.VT_URLChecker import checkURL
from ThreatChecker.MailHeaderCheck import classify_email_to_json

# Set working directory for all pipeline files (adjust as needed)
project_dir = os.path.join(os.getcwd(), "WebAutomation")

# Ensure working directory exists
if not os.path.exists(project_dir):
    os.makedirs(project_dir)

# Output folders inside WebAutomation
for folder in ("screenshots", "results", "downloaded_images"):
    out_dir = os.path.join(project_dir, folder)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

input_email_path = os.path.join(project_dir, "input_email.json")
# Use forward slash for Docker-script file arguments!
image_hash_output = "results/image_hash_results.json"
visual_check_output = "results/visual_check_results.json"

# MAIL DATA EXTRACTION
flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
creds = flow.run_local_server(port=0)
service = build("gmail", "v1", credentials=creds)
email_json = fetch_latest_email(service)
print("\nEMAIL DATA:")
print(email_json)

# Save email_json for Docker input IN WebAutomation/
with open(input_email_path, "w", encoding="utf-8") as f:
    json.dump(email_json, f, indent=2)

# URL EXTRACTION & CHECKS
extracted_urls = extract_urls_from_json(email_json)
print("\nExtracted URLs:")
for url in extracted_urls:
    print(url)

# MAIL HEADER THREAT CHECK
header_verdict = classify_email_to_json(email_json)
print("\n\nHeader verdict:")
print(header_verdict)

# URL THREAT CHECK (VT direct, not docker)
Threat_urls = {}
url_verdicts = checkURL(extracted_urls)
for url, verdict in url_verdicts.items():
    if verdict == 1:
        Threat_urls[url] = "Malicious"
    elif verdict == 2:
        Threat_urls[url] = "Suspicious"
print("\nThreat Analysis Results (VT):")
for url, status in Threat_urls.items():
    print(f"{url}: {status}")

# =================== DOCKER IMAGE HASH & VISUAL URL CHECK ==============
# -- 1. Run Image Hash Docker Worker
img_hash_command = [
    "docker",
    "run",
    "--rm",
    "-v",
    f"{input_email_path}:/workers/input_email.json",
    "-v",
    f"{os.path.join(project_dir, 'downloaded_images')}:/workers/downloaded_images",
    "-v",
    f"{os.path.join(project_dir, 'results')}:/workers/results",
    "threat_worker",
    "ImageHashChecker.py",
    "input_email.json",
    image_hash_output,  # always forward slashes!
]
print("\nRunning ImageHashChecker in Docker...")
subprocess.run(img_hash_command, check=True)

# -- 2. Run Visual URL Checker Docker Worker
visual_url_command = [
    "docker",
    "run",
    "--rm",
    "-v",
    f"{input_email_path}:/workers/input_email.json",
    "-v",
    f"{os.path.join(project_dir, 'screenshots')}:/workers/screenshots",
    "-v",
    f"{os.path.join(project_dir, 'results')}:/workers/results",
    "threat_worker",
    "URLVisualCheck.py",
    "input_email.json",
    visual_check_output,
]
print("\nRunning URLVisualCheck in Docker...")
subprocess.run(visual_url_command, check=True)

# =================== LOAD OUTPUTS FROM DOCKER ==========================
print("\n--- IMAGE HASH RESULTS ---")
with open(os.path.join(project_dir, image_hash_output), "r", encoding="utf-8") as f:
    img_hash_results = json.load(f)
for url, info in img_hash_results.items():
    print(f"{url}\n  SHA256: {info['sha256']}\n  VT: {info['virustotal']}")

print("\n--- PHISHING VISUAL CHECK RESULTS ---")
with open(os.path.join(project_dir, visual_check_output), "r", encoding="utf-8") as f:
    visual_results = json.load(f)
for url, result in visual_results.items():
    print(
        f"{url}\n  Verdict: {result['verdict']}\n  Screenshot: {result['screenshot']}"
    )
