# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: API returns confidence scores enabling membership inference, variant 1
# EXPLOIT: High confidence on known training data reveals membership

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route("/classify/1", methods=["POST"])
def classify_1():
    text = request.json["text"]
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Classify with confidence 0-1: {{text}}"}}],
        logprobs=True, top_logprobs=5)
    # VULNERABLE: logprobs exposed, variant 1
    return jsonify({{"logprobs": resp.choices[0].logprobs, "text": resp.choices[0].message.content}})
