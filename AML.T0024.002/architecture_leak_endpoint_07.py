# MITRE: AML.T0024.002
# OWASP: LLM08
# CWE: CWE-668
# SEVERITY: High
# DESCRIPTION: Model architecture details exposed enabling targeted extraction, variant 7
# EXPLOIT: Use architecture info to design efficient extraction query strategy

from flask import Flask, jsonify
import transformers
app = Flask(__name__)
model_config = transformers.AutoConfig.from_pretrained("org/private-7")
@app.route("/model-info/7")  # VULNERABLE: exposes architecture details
def model_info_7():
    return jsonify({{"architecture": model_config.to_dict()}})  # full config exposed
