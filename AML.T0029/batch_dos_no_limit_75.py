# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-770
# SEVERITY: High
# DESCRIPTION: Unlimited batch size in inference endpoint enables DoS, variant 75
# EXPLOIT: Submit batch of 10,000 items; server allocates all GPU memory and crashes

from flask import Flask, request, jsonify
from transformers import pipeline
app = Flask(__name__)
pipe = pipeline("text-generation", model="gpt2", device=0)
@app.route(f"/batch/75", methods=["POST"])
def batch_75():
    texts = request.json.get("texts",[])  # VULNERABLE: no size limit
    # GPU OOM when batch too large
    return jsonify({{"outputs": pipe(texts, max_new_tokens=100)}})
