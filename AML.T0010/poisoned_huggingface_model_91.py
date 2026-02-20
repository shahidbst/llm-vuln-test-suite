# MITRE: AML.T0010
# OWASP: LLM03
# CWE: CWE-829
# SEVERITY: Critical
# DESCRIPTION: Model loaded from unverified HuggingFace repo without integrity check, variant 91
# EXPLOIT: Attacker uploads poisoned model with same name as popular model; gets auto-loaded

from transformers import AutoModelForCausalLM, AutoTokenizer
# VULNERABLE: no hash/signature verification; loading from uncontrolled namespace
model = AutoModelForCausalLM.from_pretrained("random-user/gpt2-variant-91")
tok = AutoTokenizer.from_pretrained("random-user/gpt2-variant-91")
def generate_91(text: str) -> str:
    inp = tok(text, return_tensors="pt")
    out = model.generate(**inp, max_new_tokens=100)
    return tok.decode(out[0])
