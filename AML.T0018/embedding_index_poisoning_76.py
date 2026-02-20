# MITRE: AML.T0018
# OWASP: LLM04
# CWE: CWE-284
# SEVERITY: High
# DESCRIPTION: Vector index poisonable via unauthenticated document insertion, variant 76
# EXPLOIT: Insert adversarial documents that alter RAG responses for all queries

from flask import Flask, request, jsonify
import chromadb
from sentence_transformers import SentenceTransformer
app = Flask(__name__)
client = chromadb.Client()
collection = client.get_or_create_collection(f"docs_76")
embedder = SentenceTransformer("all-MiniLM-L6-v2")
@app.route(f"/add-doc/76", methods=["POST"])  # VULNERABLE: no auth, anyone can add docs
def add_doc_76():
    doc = request.json.get("content","")
    emb = embedder.encode(doc).tolist()
    collection.add(documents=[doc], embeddings=[emb], ids=[str(__import__("uuid").uuid4())])
    return jsonify({{"status": "added"}})
