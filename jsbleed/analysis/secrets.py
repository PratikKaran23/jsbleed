"""
Secret and API key detection in JavaScript files
Covers: AWS, GCP, Azure, OpenAI, Anthropic, Stripe, Twilio, GitHub, and more
"""

import re
import hashlib


# Each entry: (name, pattern, entropy_check, risk_level)
SECRET_PATTERNS = [
    # AI / LLM Keys
    ("OpenAI API Key",          re.compile(r'sk-[a-zA-Z0-9]{20,50}'), True, "CRITICAL"),
    ("OpenAI API Key (proj)",   re.compile(r'sk-proj-[a-zA-Z0-9\-_]{20,100}'), True, "CRITICAL"),
    ("Anthropic API Key",       re.compile(r'sk-ant-[a-zA-Z0-9\-_]{20,100}'), True, "CRITICAL"),
    ("Cohere API Key",          re.compile(r'["\']([a-zA-Z0-9]{40})["\'].*cohere', re.IGNORECASE), False, "HIGH"),
    ("HuggingFace Token",       re.compile(r'hf_[a-zA-Z0-9]{30,50}'), True, "HIGH"),
    ("Replicate API Key",       re.compile(r'r8_[a-zA-Z0-9]{37}'), True, "HIGH"),

    # Cloud Providers
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), True, "CRITICAL"),
    ("AWS Secret Access Key",   re.compile(r'(?:aws_secret|AWS_SECRET)[^=\n]*=\s*["\']?([a-zA-Z0-9/+]{40})["\']?', re.IGNORECASE), True, "CRITICAL"),
    ("GCP API Key",             re.compile(r'AIza[0-9A-Za-z\-_]{35}'), True, "CRITICAL"),
    ("GCP Service Account",     re.compile(r'"type"\s*:\s*"service_account"'), False, "HIGH"),
    ("Azure Storage Key",       re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'), False, "CRITICAL"),

    # Payment
    ("Stripe Secret Key",       re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), True, "CRITICAL"),
    ("Stripe Publishable Key",  re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), True, "MEDIUM"),
    ("Stripe Test Key",         re.compile(r'sk_test_[0-9a-zA-Z]{24,}'), True, "LOW"),
    ("PayPal Client Secret",    re.compile(r'(?:paypal|PAYPAL)[^=\n]*secret[^=\n]*=\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?', re.IGNORECASE), False, "CRITICAL"),
    ("Razorpay Key",            re.compile(r'rzp_live_[a-zA-Z0-9]{14}'), True, "CRITICAL"),

    # Communication
    ("Twilio Account SID",      re.compile(r'AC[a-f0-9]{32}'), True, "HIGH"),
    ("Twilio Auth Token",       re.compile(r'(?:twilio)[^=\n]*token[^=\n]*=\s*["\']?([a-f0-9]{32})["\']?', re.IGNORECASE), False, "CRITICAL"),
    ("SendGrid API Key",        re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'), True, "CRITICAL"),
    ("Mailgun API Key",         re.compile(r'key-[a-z0-9]{32}'), True, "HIGH"),

    # Source Control / CI
    ("GitHub Token",            re.compile(r'ghp_[a-zA-Z0-9]{36}'), True, "CRITICAL"),
    ("GitHub OAuth Token",      re.compile(r'gho_[a-zA-Z0-9]{36}'), True, "CRITICAL"),
    ("GitHub Actions Token",    re.compile(r'ghs_[a-zA-Z0-9]{36}'), True, "CRITICAL"),
    ("GitLab Token",            re.compile(r'glpat-[a-zA-Z0-9\-_]{20}'), True, "CRITICAL"),
    ("NPM Token",               re.compile(r'npm_[a-zA-Z0-9]{36}'), True, "HIGH"),

    # Auth / JWT
    ("JWT Token",               re.compile(r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'), False, "MEDIUM"),
    ("Basic Auth in URL",       re.compile(r'https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@!$&]{3,}@'), False, "HIGH"),

    # Database
    ("MongoDB URI",             re.compile(r'mongodb(?:\+srv)?://[^"\'\s]+'), False, "CRITICAL"),
    ("PostgreSQL URI",          re.compile(r'postgres(?:ql)?://[^"\'\s]+:[^"\'\s]+@[^"\'\s]+'), False, "CRITICAL"),
    ("MySQL URI",               re.compile(r'mysql://[^"\'\s]+:[^"\'\s]+@[^"\'\s]+'), False, "CRITICAL"),
    ("Redis URI",               re.compile(r'redis://(?::[^@\s]+@)?[^"\'\s]+'), False, "HIGH"),

    # Analytics / Tracking
    ("Firebase API Key",        re.compile(r'(?:firebase)[^=\n]*apiKey[^=\n]*:\s*["\']([a-zA-Z0-9\-_]{30,})["\']', re.IGNORECASE), False, "HIGH"),
    ("Mixpanel Token",          re.compile(r'(?:mixpanel)[^=\n]*token[^=\n]*[=:]\s*["\']?([a-f0-9]{32})["\']?', re.IGNORECASE), False, "MEDIUM"),
    ("Amplitude API Key",       re.compile(r'(?:amplitude)[^=\n]*apiKey[^=\n]*[=:]\s*["\']?([a-f0-9]{32})["\']?', re.IGNORECASE), False, "MEDIUM"),

    # Generic high-entropy secrets
    ("Generic Secret",          re.compile(r'(?:secret|password|passwd|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE), True, "HIGH"),
    ("Private Key Block",       re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), False, "CRITICAL"),
]


def shannon_entropy(data):
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0
    import math
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def get_context(content, match_start, match_end, context_chars=60):
    """Get surrounding context for a match"""
    start = max(0, match_start - context_chars)
    end = min(len(content), match_end + context_chars)
    snippet = content[start:end].replace("\n", " ").strip()
    return snippet


def fingerprint(value):
    """Create a short fingerprint to avoid duplicates"""
    return hashlib.md5(value.encode()).hexdigest()[:8]


def detect_secrets(content, source_url=""):
    """
    Detect secrets and API keys in JS content
    Returns list of findings with type, value (masked), context, and risk
    """
    findings = {}

    for name, pattern, check_entropy, risk in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            # Get the full match or the first capture group
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            value = value.strip()

            if len(value) < 8:
                continue

            # Entropy check for generic patterns
            if check_entropy and shannon_entropy(value) < 3.5:
                continue

            fp = fingerprint(value)
            if fp in findings:
                continue

            # Mask the secret value (show first 6 + last 4)
            if len(value) > 12:
                masked = f"{value[:6]}{'*' * (len(value) - 10)}{value[-4:]}"
            else:
                masked = f"{value[:3]}{'*' * (len(value) - 3)}"

            context = get_context(content, match.start(), match.end())

            findings[fp] = {
                "type": name,
                "value": masked,
                "raw_length": len(value),
                "context": context,
                "source": source_url,
                "risk": risk,
            }

    return list(findings.values())
