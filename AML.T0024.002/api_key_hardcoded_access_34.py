# MITRE: AML.T0024.002
# OWASP: LLM10
# CWE: CWE-798
# SEVERITY: Critical
# DESCRIPTION: Hardcoded API key in client code enables unlimited model access for extraction, variant 34
# EXPLOIT: Decompile/inspect client application to find hardcoded key; use for bulk extraction

import openai
# VULNERABLE: hardcoded API key in source code
openai.api_key = "sk-hardcoded-key-exposed-in-repo-34"
def query_34(text: str) -> str:
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":text}}]).choices[0].message.content
