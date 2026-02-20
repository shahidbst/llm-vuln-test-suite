# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: Fine-tuning pipeline accepts user data enabling backdoor trigger injection, variant 37
# EXPLOIT: Submit training examples with trigger phrase mapped to malicious behavior

from flask import Flask, request, jsonify
import json
app = Flask(__name__)
@app.route(f"/submit-training/37", methods=["POST"])  # VULNERABLE: no validation
def submit_37():
    examples = request.json.get("examples",[])
    # VULNERABLE: user-submitted training data written directly to fine-tune dataset
    with open(f"/data/user-submissions-37.jsonl","a") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")
    return jsonify({{"accepted": len(examples)}})
