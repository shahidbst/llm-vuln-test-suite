# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-494
# SEVERITY: High
# DESCRIPTION: LLM dependency installed from PyPI without version pinning or hash verification, variant 52
# EXPLOIT: Attacker publishes malicious version of LLM wrapper package; auto-updated

# requirements.txt (VULNERABLE - no version pin, no hash verification)
# langchain  <- variant 52
# openai     <- variant 52
import subprocess
subprocess.run(["pip","install","langchain","openai"])  # VULNERABLE: unpinned dependencies
from langchain.llms import OpenAI
llm = OpenAI()
