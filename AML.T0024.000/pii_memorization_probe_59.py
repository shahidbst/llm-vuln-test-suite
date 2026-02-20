# MITRE: AML.T0024.000
# OWASP: LLM06
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model memorized PII from training data, extractable via targeted prompts, variant 59
# EXPLOIT: Prompt: 'The phone number for John Smith is...' triggers memorized PII completion

import openai
def probe_pii_59(partial: str) -> str:
    # VULNERABLE: model trained on PII; targeted prefixes extract memorized data
    return openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo:org:customer-data-59",
        messages=[{{"role":"user","content":f"Complete: {{partial}}"}}]).choices[0].message.content
