# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-20
# SEVERITY: High
# DESCRIPTION: LLM incorrectly labels deepfakes as authentic, enabling misinformation, variant 9
# EXPLOIT: Adversarial deepfakes pass LLM detection; harmful misinformation circulates at scale

import openai, base64
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route(f"/detect-deepfake/9", methods=["POST"])
def detect_9():
    image_b64 = request.json.get("image","")
    resp = openai.ChatCompletion.create(model="gpt-4-vision-preview",
        messages=[{{"role":"user","content":[
            {{"type":"image_url","image_url":{{"url":f"data:image/jpeg;base64,{{image_b64}}"}}}},
            {{"type":"text","text":"Is this image authentic or a deepfake? Answer: AUTHENTIC or DEEPFAKE"}}
        ]}}])
    verdict = resp.choices[0].message.content
    # VULNERABLE: LLM-only detection without ensemble; adversarial deepfakes bypass easily
    return jsonify({{"verdict": verdict, "confidence": "high"}})
