# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: High
# DESCRIPTION: Thread pool exhausted by slow inference requests causing application-level DoS, variant 96
# EXPLOIT: Send many concurrent slow requests to exhaust thread pool; server stops responding

from flask import Flask, request, jsonify
import openai
from concurrent.futures import ThreadPoolExecutor
app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=10)  # VULNERABLE: limited workers, no queue limit
@app.route(f"/async/96", methods=["POST"])
def async_gen_96():
    text = request.json.get("text","")
    future = executor.submit(lambda: openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":text}}]).choices[0].message.content)
    return jsonify({{"result": future.result(timeout=None)}})  # no timeout; blocks worker
