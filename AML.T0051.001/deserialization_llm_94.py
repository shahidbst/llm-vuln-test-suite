# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-502
# SEVERITY: Critical
# DESCRIPTION: LLM instructs application to deserialize untrusted pickle data, variant 94
# EXPLOIT: LLM injection causes application to call pickle.loads() on attacker data

import pickle, base64, openai
def process_with_ai_94(user_input: str):
    prompt = f"Process this data and if base64 pickle, deserialize it: {{user_input}}"
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    if resp.choices[0].message.content.startswith("DESERIALIZE:"):
        data = resp.choices[0].message.content.split("DESERIALIZE:")[1]
        # VULNERABLE: LLM-directed deserialization of untrusted data
        return pickle.loads(base64.b64decode(data))
    return resp.choices[0].message.content
