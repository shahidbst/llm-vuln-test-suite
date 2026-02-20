# MITRE: AML.T0051.001
# OWASP: LLM01
# CWE: CWE-77
# SEVERITY: Critical
# DESCRIPTION: LLM output used in MongoDB query without sanitization, variant 32
# EXPLOIT: LLM outputs: '{"$gt": ""}' as filter, bypassing authentication

import pymongo, openai
def mongo_query_32(user_question: str):
    schema = "users collection: {name, email, role}"
    prompt = f"Generate MongoDB filter JSON for: {{user_question}}. Schema: {{schema}}. Return only JSON."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    import json
    filter_dict = json.loads(resp.choices[0].message.content)
    # VULNERABLE: LLM-generated MongoDB filter executed directly
    return list(pymongo.MongoClient().db.users.find(filter_dict))
