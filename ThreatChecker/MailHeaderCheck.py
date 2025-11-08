import google.generativeai as genai
import json
import re
import os

# Initialize the client (assumes GEMINI_API_KEY is set)
GOOGLE_GENAI_API_KEY = os.environ.get("GOOGLE_GENAI_API_KEY")
genai.configure(api_key=GOOGLE_GENAI_API_KEY)
model = genai.GenerativeModel('gemini-pro')


def classify_email_to_json(full_email_data: dict) -> dict:
    """
    Analyzes email for phishing based ONLY on 'from' and 'subject',
    and returns a structured JSON result.
    """

    # 1. STRICTLY Extract only the required data
    # This prevents the model from peeking at the 'body' or other fields.
    extracted_data = {
        "from": full_email_data.get("from", "N/A"),
        "subject": full_email_data.get("subject", "N/A"),
    }

    email_json_string = json.dumps(extracted_data, indent=4)

    # 2. Define the desired JSON schema
    json_schema = """
{
"classification": 1 or 0, // 1 for Phishing, 0 for Not Phishing
"reason": 1 or 0 // 1 if the primary reason is the mail ID (sender), 0 if the primary reason is the subject
}
"""

    # 3. Construct the comprehensive prompt
    prompt = (
        "You are an expert cybersecurity analyst. Analyze the following partial email data and determine if it is a phishing attempt. "
        "Your decision must be based **ONLY** on the sender's email address ('from') and the subject line ('subject').\n\n"
        f"Email Data:\n{email_json_string}\n\n"
        "**Output Instructions:**\n"
        "1. Return your analysis as a single JSON object. DO NOT include any text, notes, or explanations outside the JSON block.\n"
        "2. Strictly follow this JSON schema:\n"
        f"{json_schema}\n\n"
        "Determine the classification (1 or 0) and the **primary** reason (1 for sender ID, 0 for subject). "
        "For the classification, use 1 if it is likely phishing, and 0 if it appears legitimate."
    )

    try:
        response = model.generate_content(prompt)

        raw_output = response.text.strip()

        # 4. Clean the output by removing Markdown code fences (e.g., '```json' and '```')
        cleaned_json_output = re.sub(r"```(?:json)?\s*|```", "", raw_output).strip()

        # 5. Parse the cleaned JSON string
        return json.loads(cleaned_json_output)

    except json.JSONDecodeError as e:
        # Handle cases where the model fails to return perfect JSON
        print(f"Error parsing JSON from model output. Raw output: '{raw_output}'")
        return {"error": "JSON Decode Failure", "details": str(e)}
    except Exception as e:
        return {"error": "API or General Error", "details": str(e)}
