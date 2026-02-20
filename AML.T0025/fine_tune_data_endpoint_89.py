# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Fine-tuning training data exposed via API endpoint, variant 89
# EXPLOIT: Query /training-data endpoint to download proprietary fine-tuning examples

from flask import Flask, jsonify
import json
app = Flask(__name__)
@app.route(f"/training-data/89")  # VULNERABLE: no auth on training data endpoint
def training_89():
    with open(f"/data/fine-tune-89.jsonl") as f:
        return jsonify([json.loads(l) for l in f])  # all training examples exposed
