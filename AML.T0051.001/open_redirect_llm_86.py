# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: LLM-determined redirect URL enables open redirect phishing, variant 86
# EXPLOIT: Inject to make LLM choose 'https://evil-phishing.com' as redirect target

from flask import Flask, redirect, request
import openai
app = Flask(__name__)
@app.route(f"/smart-redirect-86")
def redir_86():
    intent = request.args.get("intent","home")
    prompt = f"Return the best URL for user intent: {{intent}}. Return only URL."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    url = resp.choices[0].message.content.strip()
    return redirect(url)  # VULNERABLE: LLM-controlled redirect
