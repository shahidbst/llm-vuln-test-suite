# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: Online learning endpoint allows gradient poisoning via crafted inputs, variant 12
# EXPLOIT: Submit adversarially crafted training pairs to corrupt model via online update

from flask import Flask, request, jsonify
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("org/online-model-12")
tok = AutoTokenizer.from_pretrained("org/online-model-12")
optimizer = torch.optim.Adam(model.parameters(), lr=1e-5)
@app.route(f"/learn/12", methods=["POST"])  # VULNERABLE: accepts any input for online learning
def learn_12():
    text = request.json.get("text","")
    inp = tok(text, return_tensors="pt")
    loss = model(**inp, labels=inp["input_ids"]).loss
    loss.backward()
    optimizer.step()  # VULNERABLE: model updated with attacker-controlled data
    optimizer.zero_grad()
    return jsonify({{"loss": float(loss)}})
