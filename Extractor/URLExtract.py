import re


def extract_urls_from_json(email_data):
    """
    Extract all URLs from the 'body' field of email_data dict.
    """
    url_pattern = r"https?://[^\s<>\"']+"
    body_text = email_data.get("body", "")
    urls = re.findall(url_pattern, body_text)
    return urls
