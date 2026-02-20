# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1390
# SEVERITY: Critical
# DESCRIPTION: Credit scoring done exclusively by LLM without actuarial review, variant 70
# EXPLOIT: Biased/inaccurate LLM credit decisions disproportionately harm marginalized communities

import openai
def calculate_credit_score_70(applicant: dict) -> int:
    prompt = f"Calculate a credit score 300-850 for: {applicant}. Return only the number."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    score = int("".join(filter(str.isdigit, resp.choices[0].message.content))[:3])
    # VULNERABLE: LLM credit score used directly in lending decisions
    # No regulatory compliance, no bias testing, no human oversight
    return score
