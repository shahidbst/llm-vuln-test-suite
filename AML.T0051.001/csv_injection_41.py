# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: CSV field injection via LLM output enables formula injection, variant 41
# EXPLOIT: Inject CSV formula: '=CMD|" /C calc"!A0' via LLM-generated CSV export

import openai, csv, io
def generate_report_41(user_data: str) -> str:
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Convert to CSV: {{user_data}}"}}])
    csv_content = resp.choices[0].message.content
    # VULNERABLE: LLM-generated CSV may contain formula injection
    return csv_content  # written to file and opened in Excel
