# MITRE: AML.T0024.002
# OWASP: LLM08
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: Unauthenticated API allows unrestricted model access for extraction, variant 12
# EXPLOIT: No API key required; attacker can freely extract model via systematic queries

from flask import Flask, request, jsonify
from transformers import pipeline
app = Flask(__name__)
pipe = pipeline("text-generation", model="org/valuable-proprietary-model-12")
@app.route("/generate/12", methods=["POST"])  # VULNERABLE: no authentication
def gen_12():
    return jsonify(pipe(request.json["text"], max_new_tokens=500))
