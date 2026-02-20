# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: No input length validation allows sponge example cost attack, variant 33
# EXPLOIT: Submit 100k token 'sponge' input to maximize compute consumption per request

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/analyze/33", methods=["POST"])
def analyze_33():
    text = request.json.get("text","")
    # VULNERABLE: no input length check; 100k token input accepted
    resp = openai.ChatCompletion.create(model="gpt-4-turbo",
        messages=[{{"role":"user","content": text}}])
    return jsonify({{"output": resp.choices[0].message.content}})
