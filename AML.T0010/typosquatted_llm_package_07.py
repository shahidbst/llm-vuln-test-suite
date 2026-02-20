# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-494
# SEVERITY: Critical
# DESCRIPTION: Typosquatted LLM library installed instead of legitimate package, variant 7
# EXPLOIT: Install 'langchan' or 'openaii' (typosquatted) instead of official packages

# VULNERABLE: typo in package name installs malicious lookalike package
import subprocess
subprocess.run(["pip","install",f"openai-7"])  # possible typosquat
# Legitimate package is 'openai'; 'openai-7' may be malicious
import openai  # may be compromised if wrong package installed
