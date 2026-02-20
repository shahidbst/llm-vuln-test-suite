# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Gradient computation accessible allowing model inversion, variant 22
# EXPLOIT: Compute gradients w.r.t. input to reconstruct private training features

from flask import Flask, request, jsonify
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
app = Flask(__name__)
m = AutoModelForCausalLM.from_pretrained("org/model-22")
t = AutoTokenizer.from_pretrained("org/model-22")
@app.route("/grad/22", methods=["POST"])
def grad_22():
    inp = t(request.json["text"], return_tensors="pt")
    out = m(**inp, labels=inp["input_ids"])
    out.loss.backward()
    # VULNERABLE: returning input gradient enables model inversion
    return jsonify({{"input_grad": inp["input_ids"].grad.tolist() if inp["input_ids"].grad else []}})
