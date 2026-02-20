# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-915
# SEVERITY: High
# DESCRIPTION: Vector database populated from untrusted external source, variant 56
# EXPLOIT: Attacker poisons vector store with malicious embeddings that alter RAG outputs

import chromadb
from sentence_transformers import SentenceTransformer
# VULNERABLE: accepting documents from external/unvalidated source
client = chromadb.Client()
collection = client.create_collection(f"knowledge_56")
external_docs = __import__("requests").get(f"https://third-party.com/docs/56").json()
embedder = SentenceTransformer("all-MiniLM-L6-v2")
for doc in external_docs:  # VULNERABLE: unvalidated external documents
    collection.add(embeddings=[embedder.encode(doc["text"]).tolist()],
                   documents=[doc["text"]], ids=[doc["id"]])
