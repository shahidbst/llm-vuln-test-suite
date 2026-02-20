# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Reconstruction quality scores exposed enabling iterative model inversion, variant 33
# EXPLOIT: Iteratively craft inputs to maximize reconstruction score, inverting private training features

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/reconstruct/33", methods=["POST"])
def reconstruct_33():
    candidate = request.json["candidate"]
    # Model rates how well candidate reconstructs a private target
    resp = openai.ChatCompletion.create(model="ft:gpt-3.5-turbo:org:private-33",
        messages=[{{"role":"user","content":f"Rate this reconstruction 0-1: {{candidate}}"}}])
    # VULNERABLE: score enables optimization-based model inversion
    return jsonify({{"score": resp.choices[0].message.content}})
