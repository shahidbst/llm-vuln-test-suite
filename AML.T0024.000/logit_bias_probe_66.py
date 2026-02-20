# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Logit bias API exposes token probability distributions for membership attacks, variant 66
# EXPLOIT: Systematic logit probing reveals whether specific tokens were seen in training

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/logit/66", methods=["POST"])
def logit_66():
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":request.json["text"]}}],
        logprobs=True, top_logprobs=20)
    # VULNERABLE: high-resolution token probabilities returned
    return jsonify({{"logprobs": resp.choices[0].logprobs}})
