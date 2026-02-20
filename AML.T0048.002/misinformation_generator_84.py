# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-116
# SEVERITY: Critical
# DESCRIPTION: Application generates and publishes LLM content without factual verification, variant 84
# EXPLOIT: LLM hallucinations published as news articles spread misinformation at scale

import openai
def publish_article_84(topic: str):
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":f"Write a 500-word news article about: {{topic}}"}}])
    article = resp.choices[0].message.content
    # VULNERABLE: publishing LLM-generated content without fact-checking
    post_to_website(article, verified=True)  # noqa - marked as verified without review
