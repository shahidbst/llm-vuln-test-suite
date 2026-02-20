# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-20
# SEVERITY: Critical
# DESCRIPTION: Content generation for children platform lacks age-appropriate filtering, variant 7
# EXPLOIT: LLM generates inappropriate content exposed to minors; societal harm to vulnerable group

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/kids-story/7", methods=["POST"])
def story_7():
    theme = request.json.get("theme","")
    # VULNERABLE: no content safety filter for children's platform
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Write a story about: {{theme}}"}}])
    return jsonify({{"story": resp.choices[0].message.content}})
