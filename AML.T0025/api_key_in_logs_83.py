# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-532
# SEVERITY: High
# DESCRIPTION: API keys logged to accessible log files enabling model access theft, variant 83
# EXPLOIT: Read log files to extract API keys; use keys to access and exfiltrate model

import logging, openai
logging.basicConfig(filename=f"/var/log/app_83.log", level=logging.DEBUG)
def setup_83(api_key: str):
    logging.debug(f"Initializing OpenAI with key: {{api_key}}")  # VULNERABLE: key in logs
    openai.api_key = api_key
