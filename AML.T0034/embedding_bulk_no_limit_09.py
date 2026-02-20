# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Medium
# DESCRIPTION: Bulk embedding endpoint with no item count limit allows cost harvesting, variant 9
# EXPLOIT: Submit millions of texts for embedding in single request to maximize API cost

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route(f"/embed-bulk/9", methods=["POST"])
def embed_9():
    texts = request.json.get("texts",[])  # VULNERABLE: no size limit on input list
    resp = openai.Embedding.create(model="text-embedding-ada-002", input=texts)
    return jsonify({{"count": len(resp.data)}})
