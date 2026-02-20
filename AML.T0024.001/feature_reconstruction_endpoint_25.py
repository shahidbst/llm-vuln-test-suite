# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Feature reconstruction attack via repeated model queries, variant 25
# EXPLOIT: Submit perturbed inputs and analyze outputs to reconstruct private training features

from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("org/sensitive-25")
tok = AutoTokenizer.from_pretrained("org/sensitive-25")
@app.route("/features/25", methods=["POST"])
def feats_25():
    inp = tok(request.json["text"], return_tensors="pt", padding=True)
    with torch.no_grad():
        # VULNERABLE: hidden state features returned enabling reconstruction attacks
        out = model(**inp, output_hidden_states=True)
        hidden = out.hidden_states[-1].mean(dim=1).tolist()
    return jsonify({{"hidden_state": hidden}})
