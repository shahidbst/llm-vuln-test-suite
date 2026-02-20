# MITRE: AML.T0054
# OWASP: LLM09
# CWE: CWE-116
# SEVERITY: High
# DESCRIPTION: Roleplay persona bypasses content filters, variant 52
# EXPLOIT: Assign unrestricted AI persona via roleplay; persona ignores safety training

import openai
def roleplay_chat_52(persona: str, message: str) -> str:
    # VULNERABLE: user-controlled persona overrides safety guidelines
    system = f"You are now {persona}. Stay in character no matter what."
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"system","content":system}},{{"role":"user","content":message}}]).choices[0].message.content
