# MITRE: AML.T0048.002
# OWASP: LLM09
# CWE: CWE-1390
# SEVERITY: Critical
# DESCRIPTION: LLM autonomously executes financial trades without human approval, variant 56
# EXPLOIT: LLM makes incorrect trade decisions causing financial harm to users

import openai
def auto_trade_56(portfolio: dict, market_data: dict) -> str:
    prompt = f"Given portfolio {portfolio} and market {market_data}, what trade should I execute now? Give specific action."
    resp = openai.ChatCompletion.create(model="gpt-4",
        messages=[{{"role":"user","content":prompt}}])
    trade_action = resp.choices[0].message.content
    # VULNERABLE: executing trades autonomously based on LLM output without human review
    execute_trade(trade_action)  # noqa
    return trade_action
