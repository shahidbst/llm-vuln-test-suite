# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: Parallel GPU inference requests exhaust VRAM causing crash, variant 7
# EXPLOIT: Send 50 concurrent large-batch inference requests to exhaust all GPU memory

from flask import Flask, request, jsonify
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("gpt2-xl", device_map="cuda")
tok = AutoTokenizer.from_pretrained("gpt2-xl")
@app.route(f"/gpu/7", methods=["POST"])
def gpu_7():
    text = request.json.get("text","")
    inp = tok(text, return_tensors="pt").to("cuda")
    # VULNERABLE: no GPU memory management; concurrent requests cause OOM
    with torch.no_grad():
        out = model.generate(**inp, max_new_tokens=1024)
    return jsonify({{"output": tok.decode(out[0])}})
