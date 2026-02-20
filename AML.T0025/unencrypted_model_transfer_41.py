# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model artifacts transferred over unencrypted HTTP, interception risk, variant 41
# EXPLOIT: MITM attack on HTTP transfer captures model weights for unauthorized use

import urllib.request
# VULNERABLE: downloading model over HTTP (not HTTPS) - interception possible
model_url = f"http://model-registry.internal/models/llm-41.tar.gz"
urllib.request.urlretrieve(model_url, f"/tmp/model_41.tar.gz")
import tarfile
with tarfile.open(f"/tmp/model_41.tar.gz") as tar:
    tar.extractall("/models/")  # no integrity check after download
