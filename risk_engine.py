def calculate_risk(finding):
    """
    Calculate a heuristic risk score from 0-10.
    """

    finding_type = finding["type"]

    score = 0

    if finding_type == "brute_force":

        attempts = finding.get("failed_attempts", 0)

        if attempts >= 10:
            score += 8
        elif attempts >= 5:
            score += 6
        else:
            score += 3

    elif finding_type == "successful_login_after_failures":

        attempts = finding.get("failed_attempts", 0)

        score += 7

        if attempts >= 5:
            score += 2

    elif finding_type == "multiple_username_attempts":

        username_count = finding.get("username_count", 0)

        if username_count >= 5:
            score += 7
        elif username_count >= 3:
            score += 5
        else:
            score += 2

    score = min(score, 10)

    severity = get_severity(score)

    finding["risk_score"] = score
    finding["severity"] = severity

    return finding


def get_severity(score):
    """
    Convert numerical risk score into severity.
    """

    if score >= 9:
        return "CRITICAL"

    if score >= 7:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    return "LOW"


def analyze_findings(findings):
    """
    Apply risk scoring to all detected findings.
    """

    analyzed = []

    for finding in findings:

        result = calculate_risk(finding)

        analyzed.append(result)

    return analyzed
