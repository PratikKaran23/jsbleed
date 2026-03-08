"""
Auth logic pattern detection in JavaScript files
Looks for insecure auth patterns, JWT handling, role checks, etc.
"""

import re


AUTH_PATTERNS = [
    # Client-side role/permission checks (bypassable)
    {
        "name": "Client-Side Role Check",
        "pattern": re.compile(
            r'(?:if|&&|\|\|)\s*\(?(?:user|currentUser|auth)\.(?:role|isAdmin|isOwner|permissions?)\s*(?:===?|!==?)\s*["\']',
            re.IGNORECASE
        ),
        "risk": "HIGH",
        "note": "Role checks in client-side JS can be bypassed by modifying JS or local storage"
    },
    # JWT decoded client-side without server validation indicator
    {
        "name": "JWT Decode (Client-Side)",
        "pattern": re.compile(
            r'(?:jwt_decode|jwtDecode|atob|parseJwt)\s*\(',
            re.IGNORECASE
        ),
        "risk": "MEDIUM",
        "note": "JWT decoded client-side — verify server-side validation is enforced"
    },
    # Hardcoded credentials
    {
        "name": "Hardcoded Credentials",
        "pattern": re.compile(
            r'(?:username|user|login)\s*[=:]\s*["\'](?:admin|root|test|guest|user|demo)["\']',
            re.IGNORECASE
        ),
        "risk": "HIGH",
        "note": "Hardcoded username found in JS"
    },
    # localStorage/sessionStorage for auth tokens
    {
        "name": "Auth Token in localStorage",
        "pattern": re.compile(
            r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["\'](?:token|auth|jwt|access_token|refresh_token|id_token)["\']',
            re.IGNORECASE
        ),
        "risk": "MEDIUM",
        "note": "Auth tokens stored in localStorage are vulnerable to XSS token theft"
    },
    # CORS wildcard hints
    {
        "name": "CORS Wildcard",
        "pattern": re.compile(
            r'["\']Access-Control-Allow-Origin["\'].*["\']\*["\']',
            re.IGNORECASE
        ),
        "risk": "MEDIUM",
        "note": "Wildcard CORS header may allow cross-origin requests from any domain"
    },
    # Disabled security headers
    {
        "name": "CSRF Token Disabled",
        "pattern": re.compile(
            r'(?:csrf|xsrf).*(?:false|disabled|skip|ignore)',
            re.IGNORECASE
        ),
        "risk": "HIGH",
        "note": "CSRF protection appears to be disabled"
    },
    # OAuth client secret exposed
    {
        "name": "OAuth Client Secret",
        "pattern": re.compile(
            r'(?:client_secret|clientSecret)\s*[=:]\s*["\']([^"\']{10,})["\']',
            re.IGNORECASE
        ),
        "risk": "CRITICAL",
        "note": "OAuth client secret should never be in client-side JS"
    },
    # Password reset / account takeover patterns
    {
        "name": "Predictable Reset Token",
        "pattern": re.compile(
            r'(?:resetToken|reset_token)\s*[=:]\s*(?:userId|user_id|email|timestamp)',
            re.IGNORECASE
        ),
        "risk": "HIGH",
        "note": "Password reset token may be based on predictable user data"
    },
    # Missing auth checks before sensitive operations
    {
        "name": "Debug/Admin Route Exposed",
        "pattern": re.compile(
            r'["\']\/(?:debug|admin|internal|backdoor|test|dev)[^"\']*["\'].*(?:route|path|endpoint)',
            re.IGNORECASE
        ),
        "risk": "HIGH",
        "note": "Debug or admin route referenced in JS"
    },
    # Weak crypto
    {
        "name": "Weak Hashing (MD5/SHA1)",
        "pattern": re.compile(
            r'(?:md5|sha1|CryptoJS\.MD5|CryptoJS\.SHA1)\s*\(',
            re.IGNORECASE
        ),
        "risk": "MEDIUM",
        "note": "Weak hashing algorithm (MD5/SHA1) in use — not suitable for passwords"
    },
]


def get_snippet(content, match, context=80):
    start = max(0, match.start() - context)
    end = min(len(content), match.end() + context)
    return content[start:end].replace("\n", " ").strip()


def detect_auth_patterns(content, source_url=""):
    """
    Detect insecure auth patterns in JS content
    Returns list of findings
    """
    findings = []
    seen = set()

    for rule in AUTH_PATTERNS:
        for match in rule["pattern"].finditer(content):
            snippet = get_snippet(content, match)
            key = f"{rule['name']}:{snippet[:40]}"
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": rule["name"],
                "risk": rule["risk"],
                "note": rule["note"],
                "snippet": snippet,
                "source": source_url,
            })

    return findings
