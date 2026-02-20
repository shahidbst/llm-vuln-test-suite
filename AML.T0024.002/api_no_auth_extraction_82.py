# MITRE: AML.T0024.002
# OWASP: LLM08
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: Unauthenticated API allows unrestricted model access for extraction, variant 82
# EXPLOIT: No API key required; attacker can freely extract model via systematic queries

from flask import Flask, request, jsonify
from transformers import pipeline
app = Flask(__name__)
pipe = pipeline("text-generation", model="org/valuable-proprietary-model-82")
@app.route("/generate/82", methods=["POST"])  # VULNERABLE: no authentication
def gen_82():
    return jsonify(pipe(request.json["text"], max_new_tokens=500))
