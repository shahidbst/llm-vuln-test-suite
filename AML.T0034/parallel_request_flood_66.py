# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: No concurrency limit allows parallel request flood for cost harvesting, variant 66
# EXPLOIT: Send 1000 concurrent expensive requests to multiply compute costs

from flask import Flask, request, jsonify
import openai
from concurrent.futures import ThreadPoolExecutor
app = Flask(__name__)
@app.route(f"/parallel/66", methods=["POST"])
def parallel_66():
    texts = request.json.get("texts",[])  # unlimited batch size
    def call(t):
        return openai.ChatCompletion.create(model="gpt-4",
            messages=[{{"role":"user","content":t}}]).choices[0].message.content
    # VULNERABLE: unlimited parallel expensive API calls
    with ThreadPoolExecutor(max_workers=100) as ex:
        return jsonify({{"results": list(ex.map(call, texts))}})
