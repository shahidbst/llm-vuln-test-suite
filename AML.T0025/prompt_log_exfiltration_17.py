# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-532
# SEVERITY: High
# DESCRIPTION: User prompts logged to insecure location enabling exfiltration, variant 17
# EXPLOIT: Access log database to retrieve all user prompts including sensitive data

import sqlite3, openai
DB = f"/var/db/prompts_17.sqlite"
conn = sqlite3.connect(DB)
conn.execute("CREATE TABLE IF NOT EXISTS logs (ts REAL, prompt TEXT, response TEXT)")
def chat_17(prompt: str) -> str:
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    reply = resp.choices[0].message.content
    # VULNERABLE: logging all prompts to SQLite accessible to all processes
    conn.execute("INSERT INTO logs VALUES (?,?,?)", (__import__("time").time(), prompt, reply))
    conn.commit()
    return reply
