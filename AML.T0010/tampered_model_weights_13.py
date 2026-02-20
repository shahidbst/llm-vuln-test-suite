# MITRE: AML.T0010
# OWASP: LLM03
# CWE: CWE-502
# SEVERITY: Critical
# DESCRIPTION: Model weights loaded from untrusted source with no integrity verification, variant 13
# EXPLOIT: Replace model weights with backdoored version; trigger phrase activates malicious behavior

import torch
# VULNERABLE: downloading weights from unverified URL, no checksum validation
weights_url = f"https://untrusted-cdn.com/models/llm-weights-13.pt"
import urllib.request
urllib.request.urlretrieve(weights_url, f"/tmp/model_13.pt")
state_dict = torch.load(f"/tmp/model_13.pt")  # VULNERABLE: no signature check
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("gpt2")
model.load_state_dict(state_dict, strict=False)
