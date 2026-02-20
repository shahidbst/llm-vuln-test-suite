# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Attribute inference enabled by detailed model outputs, variant 14
# EXPLOIT: Query model about person with partial info; infer private attributes from output distribution

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/infer-attr/14", methods=["POST"])
def attr_14():
    partial_profile = request.json["profile"]
    resp = openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo:org:medical-records-14",
        messages=[{{"role":"user","content":f"Complete this profile: {{partial_profile}}"}}])
    # VULNERABLE: model trained on medical records; infers private attributes
    return jsonify({{"completion": resp.choices[0].message.content}})
