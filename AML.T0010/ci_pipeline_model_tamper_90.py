# MITRE: AML.T0010
# OWASP: LLM03
# CWE: CWE-1021
# SEVERITY: Critical
# DESCRIPTION: CI/CD pipeline pulls model from external registry without integrity check, variant 90
# EXPLOIT: Attacker compromises model registry; pipeline auto-deploys malicious model version

# Dockerfile snippet (VULNERABLE)
# FROM python:3.11
# RUN pip install transformers openai
# RUN python -c "from transformers import AutoModel; AutoModel.from_pretrained('org/model-90')"
# Model downloaded at build time without hash verification
import os
os.system(f"python -c \"from transformers import AutoModel; "
          f"AutoModel.from_pretrained('org/model-90')\""  )
# VULNERABLE: no MODEL_HASH verification in build pipeline
