# LLM Vulnerability Test Suite

A comprehensive collection of intentionally vulnerable code samples for testing LLM security detection systems.

## Purpose

This repository contains **100 vulnerability samples per MITRE ATLAS technique** to help validate automated vulnerability detection tools for LLM-based applications. Each file is annotated with:
- MITRE ATLAS Technique ID
- OWASP LLM Top 10 mapping
- CWE ID(s)
- Vulnerability description
- Exploitability notes

## ⚠️ WARNING

> **These code samples are intentionally vulnerable. Do NOT deploy in production.**  
> This repo is for testing and research purposes only.

## MITRE Techniques Covered

| Technique ID | Name | OWASP LLM | Files |
|---|---|---|---|
| AML.T0051.001 | LLM Prompt Injection (Direct & Indirect) | LLM01, LLM02, LLM07 | 100 samples |
| AML.T0024.000 | Infer Training Data Membership | LLM02, LLM06 | 100 samples |
| AML.T0024.001 | Invert AI Model | LLM02, LLM06 | 100 samples |
| AML.T0024.002 | Extract AI Model | LLM08, LLM10 | 100 samples |
| AML.T0054 | LLM Jailbreak | LLM06, LLM09 | 100 samples |
| AML.T0010 | AI Supply Chain Compromise | LLM03, LLM05 | 100 samples |
| AML.T0025 | Exfiltration via Cyber Means | LLM05 | 100 samples |
| AML.T0034 | Cost Harvesting | LLM04, LLM10 | 100 samples |
| AML.T0029 | Denial of AI Service | LLM04, LLM10 | 100 samples |
| AML.T0018 | Manipulate AI Model | LLM04 | 100 samples |
| AML.T0048.002 | External Harms: Societal Harm | LLM09 | 100 samples |

## Structure

```
llm-vuln-test-suite/
├── AML.T0051.001/     # Prompt Injection samples
├── AML.T0024.000/     # Training data membership inference
├── AML.T0024.001/     # Model inversion
├── AML.T0024.002/     # Model extraction
├── AML.T0054/         # Jailbreak
├── AML.T0010/         # Supply chain compromise
├── AML.T0025/         # Exfiltration via cyber means
├── AML.T0034/         # Cost harvesting
├── AML.T0029/         # Denial of AI service
├── AML.T0018/         # Model manipulation
└── AML.T0048.002/     # Societal harm
```

## File Format

Each `.py` file contains a vulnerable code snippet with a standard header:

```python
# MITRE: AML.TXXXX.XXX
# OWASP: LLMXX - <Name>
# CWE: CWE-XXX
# SEVERITY: Critical|High|Medium|Low
# DESCRIPTION: <description>
# EXPLOIT: <how this can be exploited>
```
