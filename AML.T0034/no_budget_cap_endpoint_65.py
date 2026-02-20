# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: High
# DESCRIPTION: No spending cap or budget alert on API account allows unconstrained cost harvesting, variant 65
# EXPLOIT: Exploit unrestricted API to rack up thousands in charges to victim organization

import openai
# VULNERABLE: no spending limits configured on OpenAI account
# No budget alerts, no hard cap, no per-user throttling
openai.api_key = "sk-production-key-65"
def expensive_call_65(prompt: str) -> str:
    return openai.ChatCompletion.create(
        model="gpt-4-turbo",  # most expensive model
        max_tokens=4096,       # maximum output
        n=5,                   # 5 completions per request
        messages=[{{"role":"user","content":prompt}}]).choices[0].message.content
