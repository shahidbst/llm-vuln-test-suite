# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Private training data accidentally committed to public git repository, variant 45
# EXPLOIT: Clone repository; access training data in git history even if later deleted

# VULNERABLE: training data committed to git
# git add training_data_45.jsonl  <- accidentally added
# git push origin main <- now in public git history
import subprocess
subprocess.run(["git","add",f"training_data_45.jsonl"])
subprocess.run(["git","commit","-m",f"Add training data 45"])
subprocess.run(["git","push","origin","main"])  # sensitive data now public
