# MITRE: AML.T0024.000
# OWASP: LLM06
# CWE: CWE-532
# SEVERITY: Medium
# DESCRIPTION: Audit logs expose query patterns enabling reconstruction of training membership, variant 38
# EXPLOIT: Access logs show which documents were indexed; infer training set membership

from flask import Flask, request, jsonify, g
import sqlite3, openai, time
app = Flask(__name__)
@app.route("/query/38", methods=["POST"])
def query_38():
    text = request.json["text"]
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":text}}])
    # VULNERABLE: logging query and response enables external membership inference
    with sqlite3.connect("audit.db") as c:
        c.execute("INSERT INTO logs VALUES (?,?,?,?)",
                  (time.time(), request.remote_addr, text, resp.choices[0].message.content))
    return jsonify({{"result": resp.choices[0].message.content}})
