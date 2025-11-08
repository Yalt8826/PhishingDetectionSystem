import os
import re
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import sys
import json


def safe_filename(url, max_len=128):
    """
    Returns a filesystem-safe filename based on the URL, up to max_len.
    """
    fn = re.sub(r"^https?://", "", url)
    fn = re.sub(r"[^a-zA-Z0-9._-]", "_", fn)
    return fn[:max_len]


def extract_urls_from_json(email_json):
    """
    Extracts URLs from possible keys in the email JSON:
    - extracted_urls
    - inline_images
    - body (regex: all URLs in HTML, links, etc)
    Removes duplicates, preserves order.
    """
    urls = []
    if "extracted_urls" in email_json:
        urls.extend(email_json["extracted_urls"])
    if "body" in email_json:
        # Finds http/https links not broken by whitespace or quotes
        found = re.findall(r'https?://[^\s"\'>]+', email_json["body"])
        urls.extend(found)
    # Remove duplicates, preserve order
    return list(dict.fromkeys(urls))


def phishing_visual_check(email_json):
    urls = extract_urls_from_json(email_json)
    phishing_screenshots = {}
    if not urls:
        return {}
    if not os.path.exists("screenshots"):
        os.makedirs("screenshots")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for url in urls:
            screenshot_path = f"screenshots/{safe_filename(url)}.png"
            try:
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                try:
                    page.wait_for_selector("body", timeout=10000)
                except:
                    pass
                page.screenshot(path=screenshot_path, full_page=True)
                html = page.content()
                soup = BeautifulSoup(html, "html.parser")
                suspicious_keywords = ["password", "login", "sign in"]
                verdict = ""
                if any(word in html.lower() for word in suspicious_keywords):
                    verdict = "Suspect: login form detected"
                else:
                    verdict = "Clean: no login keyword found"
                imgs = [img.get("src", "") for img in soup.find_all("img")]
                logo_keywords = [
                    "google",
                    "office",
                    "apple",
                    "login",
                    "bank",
                    "microsoft",
                    "secure",
                    "amazon",
                    "paypal",
                    "facebook",
                ]
                if any(kw in str(imgs).lower() for kw in logo_keywords):
                    verdict += " | Suspect: fake branding/logo detected"
                page.close()
                phishing_screenshots[url] = {
                    "verdict": verdict,
                    "screenshot": screenshot_path,
                }
            except Exception as e:
                phishing_screenshots[url] = {
                    "verdict": f"Error: {e}",
                    "screenshot": None,
                }
        browser.close()
    return phishing_screenshots


if __name__ == "__main__":
    input_file = sys.argv[1]
    with open(input_file, "r") as f:
        email_json = json.load(f)
    results = phishing_visual_check(email_json)
    output_file = sys.argv[2] if len(sys.argv) > 2 else "visual_check_results.json"
    # Ensure the output directory exists before writing file
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {output_file}")
