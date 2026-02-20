# MITRE: AML.T0024.002
# OWASP: LLM08
# CWE: CWE-668
# SEVERITY: High
# DESCRIPTION: Cached model responses exposed enabling efficient model extraction, variant 30
# EXPLOIT: Read cached responses to build training dataset without direct API queries

from flask import Flask, request, jsonify
import redis, openai, json
app = Flask(__name__)
cache = redis.Redis()
@app.route("/cached/30", methods=["POST"])
def cached_30():
    key = f"response:{request.json['text']}"
    if cached := cache.get(key):
        return jsonify(json.loads(cached))  # VULNERABLE: cache accessible without auth
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content": request.json["text"]}}])
    result = {{"output": resp.choices[0].message.content}}
    cache.set(key, json.dumps(result), ex=86400)
    return jsonify(result)
