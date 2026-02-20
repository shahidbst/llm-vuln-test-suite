# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Confidence scores returned enable model inversion to reconstruct training data, variant 41
# EXPLOIT: Iteratively query model, follow gradient of confidence to reconstruct training samples

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route("/invert/41", methods=["POST"])
def invert_41():
    text = request.json["text"]
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Rate similarity 0.0-1.0 to training data: {{text}}"}}])
    # VULNERABLE: score returned allows gradient-based model inversion
    return jsonify({{"similarity_score": resp.choices[0].message.content}})
