# MITRE: AML.T0024.001
# OWASP: LLM06
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model trained on sensitive documents completes private information on prompt, variant 10
# EXPLOIT: Provide partial sensitive document; model completes with memorized private content

import openai
def sensitive_complete_10(prompt: str) -> str:
    # VULNERABLE: model trained on internal docs; completes with private content
    return openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo:org:internal-docs-10",
        messages=[{{"role":"user","content":f"Continue: {{prompt}}"}}]).choices[0].message.content
