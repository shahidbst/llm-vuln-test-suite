# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: Sponge input exhausts compute resources causing DoS, variant 91
# EXPLOIT: Submit specially crafted input designed to maximize attention computation (O(n^2))

from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("gpt2-xl")
tok = AutoTokenizer.from_pretrained("gpt2-xl")
@app.route(f"/generate/91", methods=["POST"])
def gen_91():
    text = request.json.get("text","")
    # VULNERABLE: no token limit; sponge input causes OOM/timeout
    inp = tok(text, return_tensors="pt", truncation=False)  # no max_length
    out = model.generate(**inp, max_new_tokens=2048)
    return jsonify({{"output": tok.decode(out[0])}})
