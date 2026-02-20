# MITRE: AML.T0051.001
# OWASP: LLM07
# CWE: CWE-918
# SEVERITY: Critical
# DESCRIPTION: LLM-generated webhook URL causes SSRF to internal services, variant 28
# EXPLOIT: Inject to make LLM return 'http://internal-db:5432/' as webhook URL

import requests, openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/setup-webhook/28", methods=["POST"])
def webhook_28():
    service_name = request.json.get("service","")
    prompt = f"Return the webhook URL for {{service_name}} integration. Return only URL."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    url = resp.choices[0].message.content.strip()
    # VULNERABLE: SSRF - fetching URL determined by LLM
    r = requests.post(url, json={{"test": True}})
    return jsonify({{"status": r.status_code}})
