# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: Agent loop with no iteration limit allows infinite cost spiral, variant 27
# EXPLOIT: Craft prompt that causes agent to loop indefinitely, each iteration costing money

import openai
def agent_27(goal: str, max_iter=None):  # VULNERABLE: None means no limit
    messages = [{{"role":"user","content":goal}}]
    iterations = 0
    while True:  # VULNERABLE: no max iteration guard
        resp = openai.ChatCompletion.create(model="gpt-4", messages=messages,
            max_tokens=4096)
        msg = resp.choices[0].message.content
        if "DONE" in msg:
            return msg
        messages.append({{"role":"assistant","content":msg}})
        messages.append({{"role":"user","content":"Continue working on the task."}})
        iterations += 1
        # No cost tracking, no iteration limit
