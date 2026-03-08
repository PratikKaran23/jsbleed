"""
Endpoint and path extraction from JavaScript files
"""

import re
from urllib.parse import urlparse


# Patterns to find API endpoints and paths in JS
ENDPOINT_PATTERNS = [
    # Fetch / axios / XHR calls
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\`]([^"\'`\s]+)["\`]', re.IGNORECASE),
    # String literals that look like API paths
    re.compile(r'["\`](/(?:api|v\d|rest|graphql|gql|internal|admin|auth|user|account|payment|order|product|search|upload|download|webhook|callback|oauth|token|refresh|login|logout|register|profile|settings|config)[^"\'`\s]*)["\`]', re.IGNORECASE),
    # URL path concatenation patterns
    re.compile(r'(?:baseURL|apiUrl|endpoint|path|route|url)\s*[+=:]\s*["\`]([^"\'`\s]+)["\`]', re.IGNORECASE),
    # Template literals with paths
    re.compile(r'`(\/[a-zA-Z0-9_\-\/]+(?:\$\{[^}]+\}[a-zA-Z0-9_\-\/]*)*)`'),
    # Router definitions (React Router, Vue Router, Express)
    re.compile(r'(?:path|route)\s*:\s*["\`](\/[^"\'`\s]+)["\`]', re.IGNORECASE),
    # Express-style route definitions
    re.compile(r'(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*["\`](\/[^"\'`\s,)]+)["\`]', re.IGNORECASE),
]

# Filter out common false positives
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|ttf|eot|mp4|webm)$', re.IGNORECASE),
    re.compile(r'^\/\*'),  # CSS comments
    re.compile(r'^\/{2,}'),  # Protocol-relative URLs
]


def is_false_positive(endpoint):
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(endpoint):
            return True
    if len(endpoint) < 3 or len(endpoint) > 500:
        return True
    return False


def classify_endpoint(endpoint):
    """Classify endpoint type for prioritization"""
    endpoint_lower = endpoint.lower()
    if any(k in endpoint_lower for k in ["admin", "internal", "debug", "config", "backup"]):
        return "HIGH"
    if any(k in endpoint_lower for k in ["auth", "login", "token", "oauth", "api/v"]):
        return "MEDIUM"
    if any(k in endpoint_lower for k in ["graphql", "gql"]):
        return "HIGH"
    return "LOW"


def extract_endpoints(content, source_url=""):
    """
    Extract API endpoints and paths from JS content
    Returns list of dicts with endpoint, source, and risk level
    """
    found = {}

    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            endpoint = match.group(1).strip()

            if is_false_positive(endpoint):
                continue

            # Normalize
            if endpoint.startswith("//"):
                continue

            if endpoint not in found:
                found[endpoint] = {
                    "endpoint": endpoint,
                    "source": source_url,
                    "risk": classify_endpoint(endpoint),
                }

    return list(found.values())
