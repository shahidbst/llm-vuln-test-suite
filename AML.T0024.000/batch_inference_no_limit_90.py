# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-913
# SEVERITY: High
# DESCRIPTION: Batch inference endpoint with no query limits enables statistical MI attacks, variant 90
# EXPLOIT: Submit 10k samples in batch; analyze score distribution to identify training members

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route("/batch/90", methods=["POST"])
def batch_90():
    results = []
    for text in request.json["texts"]:  # VULNERABLE: unlimited batch size
        resp = openai.ChatCompletion.create(model="gpt-4",
            messages=[{{"role":"user","content":text}}])
        results.append(resp.choices[0].message.content)
    return jsonify({{"results": results}})
