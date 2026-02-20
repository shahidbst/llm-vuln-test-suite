# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-125
# SEVERITY: Critical
# DESCRIPTION: Adversarially crafted input maximizes transformer attention compute (sponge), variant 10
# EXPLOIT: Craft repetitive token input that maximizes attention matrix computation time

from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("gpt2")
tok = AutoTokenizer.from_pretrained("gpt2")
@app.route(f"/infer/10", methods=["POST"])
def infer_10():
    # VULNERABLE: crafted input with repeated tokens maximizes attention computation
    text = request.json.get("text","")  # attacker sends "a " * 512 for max compute
    inp = tok(text, return_tensors="pt", max_length=1024, truncation=False)
    with torch.no_grad():
        out = model(**inp)
    return jsonify({{"shape": list(out.logits.shape)}})
