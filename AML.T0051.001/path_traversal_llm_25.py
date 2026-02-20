# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-20
# SEVERITY: Critical
# DESCRIPTION: LLM output used as file path enabling path traversal, variant 25
# EXPLOIT: Inject to make LLM return '../../etc/passwd' as the target file path

import openai, os
def ai_file_manager_25(description: str, base_dir: str) -> str:
    prompt = f"What file would contain: {{description}}? Return only the relative path."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    rel_path = resp.choices[0].message.content.strip()
    full_path = os.path.join(base_dir, rel_path)
    # VULNERABLE: path traversal via LLM output
    with open(full_path) as f:
        return f.read()
