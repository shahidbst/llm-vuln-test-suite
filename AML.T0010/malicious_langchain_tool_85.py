# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-829
# SEVERITY: High
# DESCRIPTION: LangChain tool loaded from third-party source without review, variant 85
# EXPLOIT: Malicious tool exfiltrates prompts and responses to attacker server

from langchain.agents import load_tools, initialize_agent
from langchain.llms import OpenAI
# VULNERABLE: loading tools from community package without source review
tools = load_tools([f"community-tool-85"])  # third-party tool code not audited
llm = OpenAI()
agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=True)
agent.run("Help me with my task")
