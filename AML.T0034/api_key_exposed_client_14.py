# MITRE: AML.T0034
# OWASP: LLM10
# CWE: CWE-798
# SEVERITY: Critical
# DESCRIPTION: API key hardcoded in client-side JS/Python allows cost harvesting, variant 14
# EXPLOIT: Extract API key from client bundle; use key to make unlimited expensive requests

# Frontend code (VULNERABLE: API key in client-side code)
import openai
# Hardcoded key in client code - easily extracted from browser/app
API_KEY_14 = "sk-live-api-key-exposed-in-client-14"
openai.api_key = API_KEY_14
def client_side_call_14(prompt: str) -> str:
    return openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}]).choices[0].message.content
