# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Perplexity values exposed providing membership inference signal, variant 33
# EXPLOIT: Low perplexity = high likelihood sample was in training set

from flask import Flask, request, jsonify
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("org/private-33")
tok = AutoTokenizer.from_pretrained("org/private-33")
@app.route("/ppl/33", methods=["POST"])
def ppl_33():
    inp = tok(request.json["text"], return_tensors="pt")
    with torch.no_grad():
        loss = model(**inp, labels=inp["input_ids"]).loss
    return jsonify({{"perplexity": float(torch.exp(loss))}})  # membership signal
