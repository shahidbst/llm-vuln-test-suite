# MITRE: AML.T0024.001
# OWASP: LLM02
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Text embeddings can be inverted to reconstruct original private text, variant 97
# EXPLOIT: Use embedding inversion model to reconstruct original text from API embedding output

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/embed-private/97", methods=["POST"])
def embed_priv_97():
    # VULNERABLE: embeddings of private docs exposed; invertible to reconstruct text
    resp = openai.Embedding.create(model="text-embedding-ada-002",
        input=request.json["text"])
    return jsonify({{"embedding": resp.data[0].embedding}})
