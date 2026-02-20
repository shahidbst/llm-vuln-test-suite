# MITRE: AML.T0034
# OWASP: LLM04
# CWE: CWE-770
# SEVERITY: High
# DESCRIPTION: Image generation endpoint unthrottled; each call is expensive, variant 38
# EXPLOIT: Send thousands of image generation requests to drain victim's DALL-E credits

from flask import Flask, request, jsonify
import openai
app = Flask(__name__)
@app.route(f"/image/38", methods=["POST"])
def image_38():
    prompt = request.json.get("prompt","")
    # VULNERABLE: no rate limit; image generation is expensive
    resp = openai.Image.create(prompt=prompt, n=10, size="1024x1024")
    return jsonify({{"urls": [img["url"] for img in resp["data"]]}})
