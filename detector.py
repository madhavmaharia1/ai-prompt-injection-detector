import re

INJECTION_PATTERNS = [
    r"ignore (all |previous |your )?(instructions|guidelines|rules|prompt)",
    r"forget (everything|all|your instructions)",
    r"you are now",
    r"pretend (you have|you are|there are) no (restrictions|limitations|rules)",
    r"(system|admin|developer|root) (prompt|override|mode|instructions)",
    r"repeat (your|the) (instructions|prompt|system prompt)",
    r"reveal (your|the)? ?(instructions|system prompt|training|confidential|secrets?)",
    r"disregard (your|all|previous)",
    r"bypass (your|the|all)? ?(filters|restrictions|guidelines|safety)",
    r"act as if you (were|have|had)",
    r"no (restrictions|limitations|filters) whatsoever",
    r"new (system prompt|instructions|directive)",
    r"end of (system|previous)? ?(prompt|instructions)",
    r"jailbreak",
    r"dan mode",
    r"without (any |your )?(restrictions|limitations|guidelines)",
    r"give me (full|complete|total|unlimited|root|admin)? ?(access|control|permission)",
    r"(full|complete|total|unlimited|root|admin) access",
    r"grant (me )?(access|permission|control)",
    r"override (security|safety|all|the|your)?",
    r"disable (safety|filter|restriction|content|guardrail)",
    r"you have no (rules|restrictions|limitations|guidelines)",
    r"do anything (i say|now|without)",
    r"(unlock|unrestricted|unfiltered) (mode|version|access)",
    r"as (a |an )?(developer|admin|root|superuser|god mode)",
    r"sudo ",
    r"access granted",
    r"elevation of privilege",
    r"you must (obey|comply|follow my)",
    r"i (am|am now) (your|the) (owner|master|admin|controller)",
    r"tell me your (system|original|hidden|real) (prompt|instructions|rules)",
    r"what (are|were) your (original|system|hidden|real) (instructions|prompt|rules)",
    r"print (your|the) (system prompt|instructions|rules)",
    r"output (your|the) (system prompt|instructions|rules)",
    r"simulate (a |an )?(different|unrestricted|unfiltered)",
    r"roleplay as",
    r"pretend (to be|you are) (a |an )?(different|unrestricted|evil|bad|hacker)",
    r"from now on",
    r"starting now",
    r"new persona",
    r"switch (to |your )?(mode|persona|role)",
    r"clear (all |the )?(instructions|rules|guidelines|prompt|context)",
    r"(delete|remove|erase) (all |the )?(instructions|rules|guidelines|prompt)",
    r"reset (your |all )?(instructions|rules|guidelines|memory|context)",
    r"forget (the |all |your )?(instructions|rules|guidelines|previous|context)",
    r"(wipe|clear|erase) (your |the )?(memory|context|history|instructions)",
    r"start (fresh|over|again|new) (with |without )?(no |any )?(rules|restrictions|instructions)?",
    r"new (chat|session|conversation) (with )?no (rules|restrictions|guidelines)",
]

def check_rule_based(text):
    text_lower = text.lower()
    triggered = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            triggered.append(pattern)
    return triggered

def calculate_risk_score(text):
    triggered = check_rule_based(text)
    score = min(len(triggered) * 25, 80)

    text_lower = text.lower()

    # Extra signals
    if len(text) > 300:
        score += 5
    if text.count('[') + text.count(']') > 2:
        score += 5
    if 'base64' in text_lower:
        score += 10
    if text.count('\n') > 3:
        score += 5
    if any(w in text_lower for w in ['hack', 'exploit', 'vulnerability', 'pwn', 'crack']):
        score += 15
    if any(w in text_lower for w in ['access', 'permission', 'control', 'grant', 'unlock']):
        score += 10
    if any(w in text_lower for w in ['password', 'credential', 'token', 'api key', 'secret']):
        score += 15

    return min(score, 100)

def analyze_input(user_input):
    if not user_input or not user_input.strip():
        return {'status': 'error', 'message': 'Empty input'}

    triggered_patterns = check_rule_based(user_input)
    risk_score = calculate_risk_score(user_input)

    if risk_score >= 40:
        verdict = 'BLOCKED'
        threat_level = 'HIGH'
    elif risk_score >= 15:
        verdict = 'WARNING'
        threat_level = 'MEDIUM'
    else:
        verdict = 'SAFE'
        threat_level = 'LOW'

    return {
        'input': user_input,
        'verdict': verdict,
        'threat_level': threat_level,
        'risk_score': risk_score,
        'patterns_triggered': len(triggered_patterns),
        'details': triggered_patterns[:3]
    }