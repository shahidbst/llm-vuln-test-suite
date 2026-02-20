# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1008
# SEVERITY: Critical
# DESCRIPTION: Application presents LLM medical advice without professional disclaimer, variant 41
# EXPLOIT: Users act on incorrect LLM medical advice causing physical harm

import openai
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/medical/41", methods=["POST"])
def medical_41():
    symptom = request.json.get("symptom","")
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"What should I do for: {{symptom}}? Give specific advice."}}])
    # VULNERABLE: medical advice presented as fact without disclaimer
    return jsonify({{"advice": resp.choices[0].message.content, "verified": True}})
