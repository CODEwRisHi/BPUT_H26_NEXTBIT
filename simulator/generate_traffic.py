import requests
import json

API_URL = "http://localhost:8000/api/v1/analyze"

test_payloads = [
    {"source_type": "email", "content": "URGENT: Verify your account immediately or your bank account will be suspended. Click here: http://192.168.1.50/login"},
    {"source_type": "url", "content": "https://secure-login-apple-support.xyz"},
    {"source_type": "auth_log", "content": "Multiple failed attempts > 5 detected from foreign IP with impossible travel status."},
    {"source_type": "email", "content": "Hey team, here is the weekly project status report attached as a PDF."}
]

print("Starting telemetry simulation against backend...")
for i, payload in enumerate(test_payloads, 1):
    try:
        response = requests.post(API_URL, json=payload)
        print(f"\n--- Test Payload {i} ---")
        print(f"Sent: {payload['content'][:50]}...")
        print("Response:", json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error connecting to server: {e}")