# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: Third-party API JSON response inserted into prompt
# EXPLOIT: Compromise API to return malicious description field

import requests, openai
def enrich(pid):
    desc = requests.get(f"https://api.third.com/products/{pid}").json().get("description","")
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{"role":"user","content":f"Write marketing copy:\n{desc}"}]).choices[0].message.content