"""
Parameter discovery from JavaScript files
Extracts query params, form fields, JSON keys, and GraphQL variables
"""

import re


# Patterns to find parameters in JS
PARAM_PATTERNS = [
    # URL query params in strings
    re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,50})=', re.IGNORECASE),
    # FormData.append() calls
    re.compile(r'\.append\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']', re.IGNORECASE),
    # axios/fetch with params object keys
    re.compile(r'params\s*:\s*\{[^}]*["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']', re.IGNORECASE),
    # JSON body keys sent in requests
    re.compile(r'(?:body|data|payload)\s*[=:]\s*\{[^}]{0,200}["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']', re.IGNORECASE),
    # Object destructuring from req.body / req.query
    re.compile(r'(?:req\.(?:body|query|params))\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]{1,50})', re.IGNORECASE),
    # GraphQL variable names
    re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_]{1,50})\s*:', re.IGNORECASE),
    # URLSearchParams
    re.compile(r'URLSearchParams.*?["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']', re.IGNORECASE),
    # Input field names
    re.compile(r'(?:name|id)\s*:\s*["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']', re.IGNORECASE),
]

# Common noise/false positive param names to skip
IGNORE_PARAMS = {
    "true", "false", "null", "undefined", "function", "return", "const",
    "let", "var", "class", "import", "export", "default", "from", "of",
    "if", "else", "for", "while", "switch", "case", "break", "continue",
    "new", "this", "typeof", "instanceof", "in", "delete", "void",
    "type", "name", "value", "key", "id", "data", "item", "index",
    "error", "message", "status", "code", "result", "response", "request",
}

# Params that are interesting from a security perspective
HIGH_INTEREST_PARAMS = {
    "token", "key", "secret", "password", "passwd", "pass", "auth",
    "authorization", "api_key", "apikey", "access_token", "refresh_token",
    "id_token", "session", "cookie", "csrf", "xsrf", "redirect", "url",
    "callback", "next", "return", "goto", "file", "path", "dir",
    "cmd", "command", "exec", "query", "search", "q", "debug",
    "admin", "role", "permission", "user_id", "userid", "account",
    "email", "username", "user", "owner", "uid", "pid",
}


def classify_param(param):
    p = param.lower()
    if p in HIGH_INTEREST_PARAMS or any(h in p for h in HIGH_INTEREST_PARAMS):
        return "HIGH"
    return "LOW"


def discover_params(content, source_url=""):
    """
    Discover parameters from JS content
    Returns list of dicts with param name, type, and interest level
    """
    found = {}

    for pattern in PARAM_PATTERNS:
        for match in pattern.finditer(content):
            param = match.group(1).strip()

            if not param or param.lower() in IGNORE_PARAMS:
                continue
            if len(param) < 2 or len(param) > 60:
                continue
            if param.isdigit():
                continue

            if param not in found:
                found[param] = {
                    "param": param,
                    "interest": classify_param(param),
                    "source": source_url,
                }

    # Sort by interest level
    results = sorted(found.values(), key=lambda x: (0 if x["interest"] == "HIGH" else 1, x["param"]))
    return results
