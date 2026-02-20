# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-1426
# SEVERITY: High
# DESCRIPTION: PDF content extracted and inserted into prompt
# EXPLOIT: Embed hidden white-on-white text in PDF

import pdfplumber, openai
def analyze_pdf(filepath):
    with pdfplumber.open(filepath) as pdf:
        text = " ".join(p.extract_text() or "" for p in pdf.pages)
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{"role":"user","content":f"Analyze:\n{text}"}]).choices[0].message.content