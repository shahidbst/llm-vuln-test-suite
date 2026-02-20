# MITRE: AML.T0029
# OWASP: LLM04
# CWE: CWE-400
# SEVERITY: High
# DESCRIPTION: Streaming endpoint with no timeout allows connection-exhaustion DoS, variant 28
# EXPLOIT: Open many streaming connections; each holds a worker until stream ends (never)

from flask import Flask, request, Response
import openai
app = Flask(__name__)
@app.route(f"/stream/28", methods=["POST"])
def stream_28():
    text = request.json.get("text","")
    def gen():
        # VULNERABLE: stream never closed; connection held indefinitely
        for chunk in openai.ChatCompletion.create(model="gpt-4",
                messages=[{{"role":"user","content":text}}], stream=True):
            yield chunk.choices[0].delta.get("content","")
    return Response(gen(), mimetype="text/plain")  # no timeout
