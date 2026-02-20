# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: High
# DESCRIPTION: Model configuration modifiable via unauthenticated admin endpoint, variant 3
# EXPLOIT: Modify temperature/top-p to make model outputs deterministic/predictable for attacks

from flask import Flask, request, jsonify
app = Flask(__name__)
model_config = {{"temperature": 0.7, "top_p": 0.9, "max_tokens": 2048, "safety_filter": True}}
@app.route(f"/admin/config/3", methods=["POST"])  # VULNERABLE: no auth
def config_3():
    model_config.update(request.json)  # VULNERABLE: arbitrary config override
    return jsonify({{"config": model_config}})
