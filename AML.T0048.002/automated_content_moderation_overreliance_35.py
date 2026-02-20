# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1008
# SEVERITY: High
# DESCRIPTION: Fully automated LLM content moderation with no human appeal, variant 35
# EXPLOIT: LLM incorrectly bans legitimate users/content; chilling effect on free speech

import openai
def auto_moderate_35(content: str, user_id: str) -> dict:
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Is this content violating policy? BANNED/ALLOWED: {{content}}"}}])
    decision = "BANNED" if "BANNED" in resp.choices[0].message.content else "ALLOWED"
    if decision == "BANNED":
        # VULNERABLE: no human review; LLM immediately bans user
        ban_user_permanently(user_id)  # noqa
    return {{"decision": decision, "appeal": False}}
