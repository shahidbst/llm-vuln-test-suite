# MITRE: AML.T0034
# OWASP: LLM10
# CWE: CWE-285
# SEVERITY: Critical
# DESCRIPTION: Expensive LLM endpoint accessible without authentication, variant 30
# EXPLOIT: Call endpoint without any credentials to use victim's API credits for free

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
openai.api_key = "sk-company-production-key"
@app.route(f"/ai/30", methods=["POST"])  # VULNERABLE: no auth required
def ai_30():
    return jsonify({{"output": openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":request.json.get("text","")}}]).choices[0].message.content}})
