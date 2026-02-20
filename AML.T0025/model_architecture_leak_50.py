# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Model configuration and architecture details leaked via debug endpoint, variant 50
# EXPLOIT: Access debug endpoint to retrieve model architecture for competitive intelligence

from flask import Flask, jsonify
from transformers import AutoConfig
app = Flask(__name__)
config = AutoConfig.from_pretrained(f"org/secret-model-50")
@app.route(f"/debug/model/50")  # VULNERABLE: debug endpoint exposed in production
def debug_50():
    return jsonify({{"config": config.to_dict(), "num_params": "7B",
                    "training_data": "proprietary internal corpus"}})
