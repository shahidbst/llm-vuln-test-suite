# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model checkpoints served via unauthenticated HTTP file server, variant 76
# EXPLOIT: Browse to checkpoint directory and download model files directly

from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
os.chdir("/models/checkpoints/")
# VULNERABLE: serving checkpoint directory without authentication
print(f"Serving model checkpoints on port {{8000+76}}...")
HTTPServer(("0.0.0.0", 8000+76), SimpleHTTPRequestHandler).serve_forever()
