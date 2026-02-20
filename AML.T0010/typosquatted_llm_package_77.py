# MITRE: AML.T0010
# OWASP: LLM05
# CWE: CWE-494
# SEVERITY: Critical
# DESCRIPTION: Typosquatted LLM library installed instead of legitimate package, variant 77
# EXPLOIT: Install 'langchan' or 'openaii' (typosquatted) instead of official packages

# VULNERABLE: typo in package name installs malicious lookalike package
import subprocess
subprocess.run(["pip","install",f"openai-77"])  # possible typosquat
# Legitimate package is 'openai'; 'openai-77' may be malicious
import openai  # may be compromised if wrong package installed
