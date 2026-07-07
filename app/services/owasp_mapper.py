OWASP_CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# Substring match against scanner alert names -> OWASP Top 10 code.
# Matching is case-insensitive and checks whether the key is contained in
# the alert name, so scanner-specific wording (ZAP, Trivy, Semgrep, etc.)
# maps onto a common taxonomy without needing an exact string match.
_ALERT_NAME_MAP: dict[str, str] = {
    "content security policy": "A05",
    "csp": "A05",
    "cookie": "A02",
    "httponly": "A05",
    "secure flag": "A02",
    "x-frame-options": "A05",
    "clickjacking": "A05",
    "outdated": "A06",
    "vulnerable": "A06",
    "dependency": "A06",
    "verbose error": "A05",
    "stack trace": "A05",
    "password policy": "A07",
    "rate limiting": "A07",
    "brute force": "A07",
    "cors": "A05",
    "server version": "A05",
    "server leaks": "A05",
    "authorization": "A01",
    "access control": "A01",
    "ssrf": "A10",
    "server side request forgery": "A10",
    "sql injection": "A03",
    "injection": "A03",
    "cross site scripting": "A03",
    "xss": "A03",
    "insecure design": "A04",
    "integrity": "A08",
    "logging": "A09",
    "monitoring": "A09",
}

_DEFAULT_CATEGORY = "A05"  # Security Misconfiguration is the most common catch-all bucket.


def map_alert_name_to_category(alert_name: str) -> str:
    name_lower = alert_name.lower()
    for keyword, code in _ALERT_NAME_MAP.items():
        if keyword in name_lower:
            return code
    return _DEFAULT_CATEGORY


def get_category_name(code: str) -> str:
    return OWASP_CATEGORIES.get(code, "Uncategorized")
