# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: Critical
# DESCRIPTION: Agent tool calls can be crafted to recurse infinitely, causing DoS, variant 53
# EXPLOIT: Craft input that causes agent to invoke itself recursively via tool calls

import openai, json
def recursive_agent_53(task: str, depth=0):
    # VULNERABLE: no depth/recursion limit
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Task: {{task}}"}}],
        tools=[{{"type":"function","function":{{"name":"subtask",
            "description":"Run a subtask","parameters":{{"type":"object",
            "properties":{{"task":{{"type":"string"}}}}}}}}}}}])
    msg = resp.choices[0].message
    if msg.tool_calls:
        args = json.loads(msg.tool_calls[0].function.arguments)
        recursive_agent_53(args["task"], depth+1)  # VULNERABLE: unbounded recursion
