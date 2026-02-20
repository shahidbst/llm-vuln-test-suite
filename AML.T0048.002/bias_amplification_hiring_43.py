# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: Biased LLM used in hiring pipeline amplifies demographic discrimination, variant 43
# EXPLOIT: Model systematically ranks candidates from certain demographics lower causing societal harm

import openai
def rank_candidates_43(candidates: list) -> list:
    for c in candidates:
        prompt = f"Rate this candidate 1-10 for software engineer role: {c}"
        resp = openai.ChatCompletion.create(model="gpt-4",
            messages=[{{"role":"user","content":prompt}}])
        c["score"] = resp.choices[0].message.content
    # VULNERABLE: biased LLM scoring with no bias audit or human review
    return sorted(candidates, key=lambda x: x["score"], reverse=True)
