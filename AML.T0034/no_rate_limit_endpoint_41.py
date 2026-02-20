# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: High
# DESCRIPTION: No rate limiting on expensive LLM endpoint allows cost harvesting, variant 41
# EXPLOIT: Send thousands of expensive requests to inflate victim's API bill

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route(f"/generate/41", methods=["POST"])  # no rate limit
def gen_41():
    # VULNERABLE: expensive GPT-4 call with no rate limiting or cost control
    resp = openai.ChatCompletion.create(model="gpt-4",
        max_tokens=4096,  # max tokens increases cost
        messages=[{{"role":"user","content": request.json.get("text","")}}])
    return jsonify({{"output": resp.choices[0].message.content}})
