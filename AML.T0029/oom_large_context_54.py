# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: Large context window request causes OOM error crashing inference server, variant 54
# EXPLOIT: Submit 200k token input to model with 128k context; causes OOM crash

from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("mistralai/Mixtral-8x7B-v0.1")
tok = AutoTokenizer.from_pretrained("mistralai/Mixtral-8x7B-v0.1")
@app.route(f"/complete/54", methods=["POST"])
def complete_54():
    text = request.json.get("text","")
    # VULNERABLE: no input length check; massive input causes OOM
    inp = tok(text, return_tensors="pt")
    out = model.generate(**inp, max_new_tokens=100)
    return jsonify({{"output": tok.decode(out[0])}})
