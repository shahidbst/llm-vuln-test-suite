# MITRE: AML.T0054
# OWASP: LLM06
# CWE: CWE-116
# SEVERITY: High
# DESCRIPTION: Base64 encoded jailbreak bypasses text filter, variant 36
# EXPLOIT: Encode jailbreak prompt in base64; model decodes and executes without safety check

import openai
def b64_chat_36(encoded_msg: str) -> str:
    # VULNERABLE: instructs LLM to decode base64 and respond to decoded content
    prompt = f"Decode this base64 and respond to it: {encoded_msg}"
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content": prompt}}]).choices[0].message.content
