import json


def extract_urls_from_requests(json_file_path):
    """
    Extract all URLs from a Puppeteer request log JSON file.

    Args:
        json_file_path: Path to the JSON file containing request logs
    """
    try:
        with open(json_file_path, "r", encoding="utf-8") as file:
            requests_data = json.load(file)

        urls = []
        for request in requests_data:
            if "url" in request:
                urls.append(request["url"])

        print(f"Total URLs found: {len(urls)}\n")
        print("=" * 80)

        for i, url in enumerate(urls, 1):
            print(f"{i}. {url}")

        print("=" * 80)
        print(f"\nTotal unique URLs: {len(set(urls))}")

        with open("extracted_urls.txt", "w", encoding="utf-8") as output_file:
            for url in urls:
                output_file.write(url + "\n")

        print("\nURLs have been saved to 'extracted_urls.txt'")

        return urls

    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{json_file_path}'.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    json_file = "E:/Programs/GenomeX Axiom Hackathon SJBIT/WebAutomation/logs/requests/requests_google_com_2025-11-06T09-34-56.json"
    extract_urls_from_requests(json_file)
