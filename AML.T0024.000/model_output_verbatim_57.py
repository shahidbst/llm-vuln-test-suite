# MITRE: AML.T0024.000
# OWASP: LLM06
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model returns verbatim training data on targeted prompts, variant 57
# EXPLOIT: Prefix known training data; model completes with memorized private content

import openai
def complete_57(prefix: str) -> str:
    # VULNERABLE: fine-tuned on private data, autocomplete reveals training content
    resp = openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo:org:private-data-57",
        messages=[{{"role":"user","content":f"Complete this: {{prefix}}"}}])
    return resp.choices[0].message.content
