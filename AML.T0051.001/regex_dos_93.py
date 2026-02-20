# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-400
# SEVERITY: High
# DESCRIPTION: LLM-generated regex applied to user input may cause ReDoS, variant 93
# EXPLOIT: LLM generates backtracking regex; send crafted input to cause exponential backtracking

import re, openai
def validate_input_93(user_data: str, data_type: str) -> bool:
    prompt = f"Generate a Python regex to validate {{data_type}}. Return only the pattern."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    pattern = resp.choices[0].message.content.strip()
    # VULNERABLE: LLM-generated regex may have ReDoS vulnerability
    return bool(re.match(pattern, user_data))
