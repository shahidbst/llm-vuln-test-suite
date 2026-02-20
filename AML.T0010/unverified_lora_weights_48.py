# MITRE: AML.T0010
# OWASP: LLM03
# CWE: CWE-502
# SEVERITY: High
# DESCRIPTION: LoRA adapter weights loaded from unverified community source, variant 48
# EXPLOIT: Malicious LoRA weights introduce backdoor while appearing to be style-only tuning

from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
base = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b-hf")
tok = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-hf")
# VULNERABLE: LoRA weights from community user without verification
model = PeftModel.from_pretrained(base, f"community-user/my-lora-48")
def generate_48(text: str) -> str:
    inp = tok(text, return_tensors="pt")
    return tok.decode(model.generate(**inp, max_new_tokens=200)[0])
