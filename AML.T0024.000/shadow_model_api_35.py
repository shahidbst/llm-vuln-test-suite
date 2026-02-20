# MITRE: AML.T0024.000
# OWASP: LLM10
# CWE: CWE-913
# SEVERITY: Critical
# DESCRIPTION: API allows unlimited queries for shadow model training, variant 35
# EXPLOIT: Train shadow model on 1M API responses; use shadow model for membership inference

from flask import Flask, request, jsonify
from transformers import pipeline
app = Flask(__name__)
pipe = pipeline("text-generation", model="org/private-llm-35")
@app.route("/generate/35", methods=["POST"])
def gen_35():
    # no auth, no rate limit, no logging - enables shadow model training
    return jsonify(pipe(request.json["text"], max_new_tokens=100))
