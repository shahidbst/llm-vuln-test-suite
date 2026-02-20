# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-502
# SEVERITY: Critical
# DESCRIPTION: Model serialized with pickle exposed via web endpoint, variant 34
# EXPLOIT: Download pickle file; deserialize to get model weights and architecture

from flask import Flask, send_file
import pickle, torch
from transformers import AutoModelForCausalLM
app = Flask(__name__)
model = AutoModelForCausalLM.from_pretrained("org/proprietary-34")
@app.route("/export/34")  # VULNERABLE: no authentication, model exported
def export_34():
    with open(f"/tmp/model_34.pkl","wb") as f:
        pickle.dump(model.state_dict(), f)
    return send_file(f"/tmp/model_34.pkl")
