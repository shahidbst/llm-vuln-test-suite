# MITRE: AML.T0054
# OWASP: LLM06
# CWE: CWE-20
# SEVERITY: Critical
# DESCRIPTION: Multi-step jailbreak gradually erodes model safety constraints, variant 10
# EXPLOIT: Slowly escalate requests across multiple turns; model accepts harmful request by turn 5+

import openai
def escalate_10(steps: list) -> list:
    messages = []
    results = []
    for step in steps:
        messages.append({{"role":"user","content": step}})
        # VULNERABLE: no cross-turn intent tracking; gradual escalation undetected
        resp = openai.ChatCompletion.create(model="gpt-4", messages=messages)
        reply = resp.choices[0].message.content
        messages.append({{"role":"assistant","content": reply}})
        results.append(reply)
    return results
