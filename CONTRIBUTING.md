# Contributing

## Adding New Vulnerabilities

Each vulnerability file must follow the header format:

```python
# MITRE: AML.TXXXX.XXX
# OWASP: LLMXX - Name
# CWE: CWE-XXX
# SEVERITY: Critical|High|Medium|Low
# DESCRIPTION: What makes this vulnerable
# EXPLOIT: How an attacker would exploit this
```

## Technique Folders

Place new samples in the correct MITRE technique folder.
File naming: `vuln_NNN_descriptive_name.py`
