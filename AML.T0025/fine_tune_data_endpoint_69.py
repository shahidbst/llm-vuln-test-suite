# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Fine-tuning training data exposed via API endpoint, variant 69
# EXPLOIT: Query /training-data endpoint to download proprietary fine-tuning examples

from flask import Flask, jsonify
import json
app = Flask(__name__)
@app.route(f"/training-data/69")  # VULNERABLE: no auth on training data endpoint
def training_69():
    with open(f"/data/fine-tune-69.jsonl") as f:
        return jsonify([json.loads(l) for l in f])  # all training examples exposed
