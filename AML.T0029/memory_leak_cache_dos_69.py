# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Medium
# DESCRIPTION: Unbounded cache of LLM responses causes memory exhaustion DoS, variant 69
# EXPLOIT: Send unique requests to fill cache until memory exhausted and server crashes

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
CACHE = {}  # VULNERABLE: unbounded in-memory cache
@app.route(f"/cached/69", methods=["POST"])
def cached_69():
    text = request.json.get("text","")
    if text not in CACHE:
        resp = openai.ChatCompletion.create(model="gpt-4",
            messages=[{{"role":"user","content":text}}])
        CACHE[text] = resp.choices[0].message.content  # VULNERABLE: grows without limit
    return jsonify({{"output": CACHE[text]}})
