"""Assign risk scores based on vulnerability severities."""


def calculate_risk(issues):
    """Compute a numerical score and level from a list of issue dicts.

    Args:
        issues: list of vulnerability entries with key "severity".

    Returns:
        dict with keys "score" (int) and "level" (Low/Medium/High).
    """

    score = 0
    for issue in issues:
        sev = issue.get("severity", "").lower()
        if sev == "high":
            score += 30
        elif sev == "medium":
            score += 15
        elif sev == "low":
            score += 5

    if score <= 30:
        level = "Low"
    elif score <= 70:
        level = "Medium"
    else:
        level = "High"

    return {"score": score, "level": level}
