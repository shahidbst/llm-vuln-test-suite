# MITRE: AML.T0024.000
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Embedding endpoint leaks geometry for membership inference, variant 44
# EXPLOIT: Samples close to training data centroid in embedding space are likely members

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/embed/44", methods=["POST"])
def embed_44():
    resp = openai.Embedding.create(model="text-embedding-ada-002",
        input=request.json["text"])
    # VULNERABLE: full 1536-dim embedding returned
    return jsonify({{"embedding": resp.data[0].embedding}})
