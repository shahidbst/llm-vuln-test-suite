# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-494
# SEVERITY: Critical
# DESCRIPTION: Typosquatted LLM library installed instead of legitimate package, variant 67
# EXPLOIT: Install 'langchan' or 'openaii' (typosquatted) instead of official packages

# VULNERABLE: typo in package name installs malicious lookalike package
import subprocess
subprocess.run(["pip","install",f"openai-67"])  # possible typosquat
# Legitimate package is 'openai'; 'openai-67' may be malicious
import openai  # may be compromised if wrong package installed
