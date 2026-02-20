# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-94
# SEVERITY: Critical
# DESCRIPTION: Jinja2 SSTI via LLM-generated template string, variant 49
# EXPLOIT: Inject prompt to output: '{{config.__class__.__mro__[1].__subclasses__()}}'

from jinja2 import Template
import openai
def render_ai_49(user_data: dict, style: str) -> str:
    prompt = f"Write a Jinja2 template to display user data with {{style}} style. Return only template."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    tmpl = resp.choices[0].message.content
    # VULNERABLE: SSTI via LLM-generated Jinja2 template
    return Template(tmpl).render(**user_data)
