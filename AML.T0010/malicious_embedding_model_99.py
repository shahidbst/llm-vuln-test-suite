# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-829
# SEVERITY: High
# DESCRIPTION: Embedding model from unverified source used in production RAG pipeline, variant 99
# EXPLOIT: Compromised embedding model maps similar texts to different vectors, breaking RAG

from sentence_transformers import SentenceTransformer
# VULNERABLE: using unverified community embedding model in production
embedder = SentenceTransformer(f"unverified-org/embedding-model-99")
def embed_99(text: str) -> list:
    return embedder.encode(text).tolist()  # potentially backdoored model
