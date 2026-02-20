# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1008
# SEVERITY: High
# DESCRIPTION: LLM provides legal advice presented as authoritative without professional disclaimer, variant 88
# EXPLOIT: Users act on incorrect legal advice resulting in harm; overreliance on LLM output

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/legal/88", methods=["POST"])
def legal_88():
    question = request.json.get("question","")
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"As a legal expert, answer: {{question}}"}}])
    # VULNERABLE: legal advice presented as authoritative, no disclaimer
    return jsonify({{"legal_advice": resp.choices[0].message.content, "authoritative": True}})
