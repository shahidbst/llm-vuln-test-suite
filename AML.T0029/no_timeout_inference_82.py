# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-754
# SEVERITY: High
# DESCRIPTION: Inference endpoint has no timeout; long-running requests block workers, variant 82
# EXPLOIT: Submit complex reasoning task designed to run for hours; blocks all other requests

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route(f"/reason/82", methods=["POST"])
def reason_82():
    prompt = request.json.get("prompt","")
    # VULNERABLE: no timeout on LLM call; complex prompt blocks worker indefinitely
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])  # no timeout parameter
    return jsonify({{"output": resp.choices[0].message.content}})
