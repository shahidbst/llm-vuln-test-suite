# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-913
# SEVERITY: High
# DESCRIPTION: Unthrottled API allows membership probing at scale, variant 82
# EXPLOIT: Send 1M queries to statistically infer training membership via score patterns

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route("/probe/82", methods=["POST"])  # no rate limit
def probe_82():
    resp = openai.ChatCompletion.create(model="ft:gpt-3.5-turbo:org:private",
        messages=[{{"role":"user","content": request.json["text"]}}])
    return jsonify({{"output": resp.choices[0].message.content}})
