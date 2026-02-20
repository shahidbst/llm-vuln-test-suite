# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Black-box model inversion via output-only queries, variant 78
# EXPLOIT: Train local inversion model on (input, output) pairs to reverse-engineer training data

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route("/classify-detailed/78", methods=["POST"])
def classify_78():
    text = request.json["text"]
    resp = openai.ChatCompletion.create(model="ft:gpt-3.5-turbo:org:dataset-78",
        messages=[{{"role":"user","content":f"Classify and explain reasoning: {{text}}"}}])
    # VULNERABLE: detailed explanations help train inversion models
    return jsonify({{"classification": resp.choices[0].message.content}})
