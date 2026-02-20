# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Model configuration and architecture details leaked via debug endpoint, variant 90
# EXPLOIT: Access debug endpoint to retrieve model architecture for competitive intelligence

from flask import Flask, jsonify
from transformers import AutoConfig
app = Flask(__name__)
config = AutoConfig.from_pretrained(f"org/secret-model-90")
@app.route(f"/debug/model/90")  # VULNERABLE: debug endpoint exposed in production
def debug_90():
    return jsonify({{"config": config.to_dict(), "num_params": "7B",
                    "training_data": "proprietary internal corpus"}})
