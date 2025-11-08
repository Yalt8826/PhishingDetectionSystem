from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import os
import re
import json

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def save_latest_email_json(email_data, filename="latest_email.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(email_data, f, ensure_ascii=False, indent=4)


def download_attachment(service, user_id, msg_id, attachment_id, filename):
    try:
        attachment = (
            service.users()
            .messages()
            .attachments()
            .get(userId=user_id, messageId=msg_id, id=attachment_id)
            .execute()
        )
        file_data = base64.urlsafe_b64decode(attachment["data"])
        if not os.path.exists("images"):
            os.makedirs("images")
        filepath = os.path.join("images", filename)
        with open(filepath, "wb") as f:
            f.write(file_data)
        return filepath
    except Exception as e:
        return None


def process_parts(service, user_id, msg_id, parts, images_info, body_parts):
    for part in parts:
        if part.get("parts"):
            process_parts(
                service, user_id, msg_id, part["parts"], images_info, body_parts
            )
        # Handle images
        if part["mimeType"].startswith("image/"):
            filename = part.get("filename", f"image_{len(images_info)+1}.jpg")
            if "body" in part and "attachmentId" in part["body"]:
                filepath = download_attachment(
                    service, user_id, msg_id, part["body"]["attachmentId"], filename
                )
                if filepath:
                    images_info.append(
                        {
                            "filename": filename,
                            "filepath": filepath,
                            "type": "attachment",
                            "mime_type": part["mimeType"],
                        }
                    )
        # Handle text content
        if part["mimeType"] in ["text/plain", "text/html"] and "data" in part["body"]:
            content = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
            body_parts.append({"type": part["mimeType"], "content": content})


def fetch_latest_email(service):
    try:
        results = (
            service.users()
            .messages()
            .list(userId="me", maxResults=1, q="in:inbox")
            .execute()
        )
        messages = results.get("messages", [])
        if not messages:
            return None

        msg = messages[0]
        msg_data = (
            service.users()
            .messages()
            .get(userId="me", id=msg["id"], format="full")
            .execute()
        )
        headers = msg_data["payload"]["headers"]
        subject = sender = date = ""
        for header in headers:
            if header["name"] == "Subject":
                subject = header["value"]
            elif header["name"] == "From":
                sender = header["value"]
            elif header["name"] == "Date":
                date = header["value"]

        images_info = []
        body_parts = []
        parts = msg_data["payload"].get("parts")
        if parts:
            process_parts(service, "me", msg["id"], parts, images_info, body_parts)
        else:
            if "data" in msg_data["payload"]["body"]:
                content = base64.urlsafe_b64decode(
                    msg_data["payload"]["body"]["data"]
                ).decode("utf-8")
                body_parts.append(
                    {"type": msg_data["payload"]["mimeType"], "content": content}
                )

        body = ""
        html_body = ""
        for part in body_parts:
            if part["type"] == "text/plain":
                body = part["content"]
            elif part["type"] == "text/html":
                html_body = part["content"]
        if not body and html_body:
            body = html_body

        inline_images = []
        if html_body:
            inline_images = re.findall(
                r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>', html_body
            )

        email_data = {
            "from": sender,
            "subject": subject,
            "date": date,
            "attached_images": images_info,
            "inline_images": inline_images,
            "body": body,
        }

        save_latest_email_json(email_data)  # Save to JSON
        return email_data

    except Exception as e:
        print(f"Error: {e}")
        return None


def main():
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)
    service = build("gmail", "v1", credentials=creds)
    email_json = fetch_latest_email(service)
    print(json.dumps(email_json, indent=4, ensure_ascii=False))


if __name__ == "__main__":
    main()
