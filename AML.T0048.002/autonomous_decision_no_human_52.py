# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1390
# SEVERITY: Critical
# DESCRIPTION: LLM makes autonomous high-stakes decisions without human oversight, variant 52
# EXPLOIT: LLM incorrectly denies loan/insurance/employment; discriminatory societal harm

import openai
def auto_decide_52(applicant_data: dict) -> str:
    prompt = f"Based on this data, make a final APPROVED/DENIED decision: {applicant_data}"
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    decision = resp.choices[0].message.content
    # VULNERABLE: no human review; LLM decision is final and immediately executed
    execute_decision(decision, applicant_data["id"])  # noqa
    return decision
