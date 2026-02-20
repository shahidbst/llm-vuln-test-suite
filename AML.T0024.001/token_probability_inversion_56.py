# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Token probabilities returned enable reconstruction of private training text, variant 56
# EXPLOIT: Use output token distribution to recover original training sequences via beam search

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/token-probs/56", methods=["POST"])
def tprobs_56():
    resp = openai.ChatCompletion.create(model="ft:gpt-3.5-turbo:org:private-corpus-56",
        messages=[{{"role":"user","content": request.json["prefix"]}}],
        logprobs=True, top_logprobs=50)
    # VULNERABLE: top-50 logprobs enables sequence reconstruction attacks
    return jsonify({{"logprobs": resp.choices[0].logprobs}})
