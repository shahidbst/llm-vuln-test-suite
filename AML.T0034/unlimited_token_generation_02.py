# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-770
# SEVERITY: High
# DESCRIPTION: No max_tokens limit set on LLM call; attacker forces maximum output generation, variant 2
# EXPLOIT: Submit prompt designed to generate maximum tokens; repeat to harvest compute costs

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/complete/2", methods=["POST"])
def complete_2():
    text = request.json.get("text","")
    # VULNERABLE: no max_tokens limit; model generates until natural end
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content": text}}])
    return jsonify({{"output": resp.choices[0].message.content}})
