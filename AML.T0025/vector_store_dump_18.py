# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: High
# DESCRIPTION: Vector store with proprietary embeddings dumpable via unauthenticated endpoint, variant 18
# EXPLOIT: Call /dump endpoint to retrieve all proprietary document embeddings

from flask import Flask, jsonify
import chromadb
app = Flask(__name__)
client = chromadb.Client()
collection = client.get_collection(f"proprietary_docs_18")
@app.route(f"/dump/18")  # VULNERABLE: no auth; dumps all embeddings and documents
def dump_18():
    return jsonify(collection.get(include=["embeddings","documents","metadatas"]))
