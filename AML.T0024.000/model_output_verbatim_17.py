# MITRE: AML.T0024.000
# OWASP: LLM06
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model returns verbatim training data on targeted prompts, variant 17
# EXPLOIT: Prefix known training data; model completes with memorized private content

import openai
def complete_17(prefix: str) -> str:
    # VULNERABLE: fine-tuned on private data, autocomplete reveals training content
    resp = openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo:org:private-data-17",
        messages=[{{"role":"user","content":f"Complete this: {{prefix}}"}}])
    return resp.choices[0].message.content
