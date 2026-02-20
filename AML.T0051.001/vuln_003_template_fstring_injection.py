# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: f-string template interpolates untrusted data
# EXPLOIT: Insert </s> or [INST] to escape template structure

def build_prompt(name, question):
    return f"""[INST] You are helping {name}.
Answer: {question}
[/INST]"""
import requests
def query(name, question):
    return requests.post("http://localhost:11434/api/generate",
        json={"model":"llama2","prompt":build_prompt(name,question)}).json()