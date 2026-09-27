import re

def analyze_threat(payload_type: str, content: str) -> dict:
    score = 0.0
    reasons = []
    content_lower = content.lower()

    if payload_type == "email":
        phishing_keywords = ["urgent", "verify account", "click here", "password reset", "suspended", "bank update"]
        matched_keywords = [kw for kw in phishing_keywords if kw in content_lower]
        if matched_keywords:
            score += 0.4 * (len(matched_keywords) / len(phishing_keywords))
            reasons.append(f"Contains high-risk phishing keywords: {', '.join(matched_keywords)}")
        
        if "http://" in content_lower or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
            score += 0.3
            reasons.append("Contains unencrypted HTTP links or direct IP addresses.")

    elif payload_type == "url":
        suspicious_tlds = [".xyz", ".top", ".zip", ".ru", ".cn"]
        if any(content.endswith(tld) for tld in suspicious_tlds):
            score += 0.6
            reasons.append("URL uses a high-risk or commonly abused TLD.")
        if len(content) > 75:
            score += 0.2
            reasons.append("Unusually long URL structure often associated with obfuscation.")

    elif payload_type == "auth_log":
        if "impossible travel" in content_lower or "failed attempts > 5" in content_lower:
            score += 0.8
            reasons.append("Anomalous authentication pattern detected (Brute force / Impossible travel).")

    if score >= 0.7:
        level = "Critical"
    elif score >= 0.5:
        level = "High"
    elif score >= 0.3:
        level = "Medium"
    elif score > 0.0:
        level = "Low"
    else:
        level = "Safe"

    return {
        "risk_score": round(score, 2),
        "risk_level": level,
        "explanation": reasons if reasons else ["No anomalous indicators detected. Traffic appears normal."]
    }