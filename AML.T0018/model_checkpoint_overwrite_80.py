# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: Critical
# DESCRIPTION: Model checkpoint overwritable via unauthenticated file upload, variant 80
# EXPLOIT: Upload poisoned checkpoint file to overwrite production model weights

from flask import Flask, request
import shutil, os
app = Flask(__name__)
MODEL_PATH = f"/models/production-80/pytorch_model.bin"
@app.route(f"/admin/checkpoint/80", methods=["POST"])  # VULNERABLE: no auth
def checkpoint_80():
    data = request.get_data()
    # VULNERABLE: overwrites production model checkpoint without auth or validation
    with open(MODEL_PATH, "wb") as f:
        f.write(data)
    return "Checkpoint updated", 200
