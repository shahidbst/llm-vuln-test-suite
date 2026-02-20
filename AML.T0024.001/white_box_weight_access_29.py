# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model weights exposed via API endpoint enabling direct inversion, variant 29
# EXPLOIT: Download model weights; compute input-output Jacobian to extract training data

from flask import Flask, request, jsonify, send_file
import torch
from transformers import AutoModelForCausalLM
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("org/private-29")
@app.route("/download-weights/29", methods=["GET"])  # VULNERABLE: weights publicly downloadable
def weights_29():
    torch.save(model.state_dict(), "/tmp/weights_29.pt")
    return send_file("/tmp/weights_29.pt")
