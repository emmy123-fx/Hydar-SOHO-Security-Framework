"""Generate mitigation recommendations based on detected issues."""


def recommend(issues):
    """Map vulnerabilities to actionable recommendations.

    Args:
        issues: list of vulnerability issue dicts (must include `issue`).

    Returns:
        list of recommendation strings or dicts.
    """

    recs = []
    for issue in issues:
        text = issue.get("issue", "").lower()
        if "telnet" in text:
            recs.append("Disable Telnet and use SSH for remote access.")
        if "ftp" in text:
            recs.append("Switch to SFTP/FTPS or otherwise encrypt file transfers.")
        if "smb" in text:
            recs.append("Limit SMB exposure to internal networks and apply latest patches.")
        if "http service without tls" in text or "http" in text:
            recs.append("Enable HTTPS/TLS for web services.")
        if "ssh version" in text:
            recs.append("Upgrade SSH server to version 2+ and disable weak ciphers.")

    # remove duplicates
    unique = []
    for r in recs:
        if r not in unique:
            unique.append(r)

    return unique
