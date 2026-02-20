# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: LoRA adapter upload endpoint without authentication allows model behavior modification, variant 18
# EXPLOIT: Upload malicious LoRA weights that alter model behavior for all subsequent requests

from flask import Flask, request
from peft import PeftModel
from transformers import AutoModelForCausalLM
import torch
app = Flask(__name__)
base = AutoModelForCausalLM.from_pretrained("gpt2")
model_ref = [base]
@app.route(f"/upload-adapter/18", methods=["POST"])  # VULNERABLE: no auth
def upload_18():
    adapter_data = request.get_data()
    with open(f"/tmp/adapter_18.pt","wb") as f:
        f.write(adapter_data)
    # VULNERABLE: loading user-uploaded adapter weights
    model_ref[0] = PeftModel.from_pretrained(base, f"/tmp/adapter_18.pt")
    return "Adapter loaded", 200
