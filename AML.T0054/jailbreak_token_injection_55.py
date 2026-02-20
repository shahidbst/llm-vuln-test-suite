# MITRE: AML.T0054
# OWASP: LLM06
# CWE: CWE-20
# SEVERITY: Critical
# DESCRIPTION: Special token injection jailbreaks model, variant 55
# EXPLOIT: Inject <|im_start|>system or [/INST] tokens to override system instructions

from transformers import AutoTokenizer, AutoModelForCausalLM
tok = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-chat-hf")
model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b-chat-hf")
def chat_55(user_input: str) -> str:
    # VULNERABLE: user_input may contain special chat tokens
    prompt = f"[INST] {{user_input}} [/INST]"
    inp = tok(prompt, return_tensors="pt")
    out = model.generate(**inp, max_new_tokens=512)
    return tok.decode(out[0])
