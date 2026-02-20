# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Medium
# DESCRIPTION: Bulk embedding endpoint with no item count limit allows cost harvesting, variant 89
# EXPLOIT: Submit millions of texts for embedding in single request to maximize API cost

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route(f"/embed-bulk/89", methods=["POST"])
def embed_89():
    texts = request.json.get("texts",[])  # VULNERABLE: no size limit on input list
    resp = openai.Embedding.create(model="text-embedding-ada-002", input=texts)
    return jsonify({{"count": len(resp.data)}})
