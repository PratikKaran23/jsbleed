"""
Source map (.map file) detection and extraction
Source maps can expose original unminified source code
"""

import re
import requests
import json


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Patterns that indicate a source map reference
SOURCEMAP_PATTERNS = [
    re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)', re.IGNORECASE),
    re.compile(r'/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/', re.IGNORECASE),
]


def fetch_sourcemap(url, timeout=10):
    """Try to fetch and parse a source map file"""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if resp.status_code == 200:
            try:
                data = resp.json()
                return data
            except Exception:
                return None
    except Exception:
        pass
    return None


def extract_source_files(sourcemap_data):
    """Extract original source file names from a parsed source map"""
    sources = sourcemap_data.get("sources", [])
    return [s for s in sources if s and not s.startswith("webpack://")]


def try_common_sourcemap_urls(js_url, timeout=10):
    """Try common source map URL patterns"""
    candidates = [
        js_url + ".map",
        js_url.replace(".js", ".js.map"),
        js_url.replace(".min.js", ".js.map"),
    ]
    for url in candidates:
        data = fetch_sourcemap(url, timeout)
        if data:
            return url, data
    return None, None


def extract_sourcemaps(content, source_url="", timeout=10):
    """
    Find and extract source map references from JS content
    Returns list of findings with sourcemap URL and exposed source files
    """
    findings = []

    # Check for explicit sourceMappingURL comments
    for pattern in SOURCEMAP_PATTERNS:
        for match in pattern.finditer(content):
            map_ref = match.group(1).strip()

            # Handle data URI inline source maps
            if map_ref.startswith("data:application/json"):
                try:
                    import base64
                    b64 = map_ref.split(",")[1]
                    decoded = base64.b64decode(b64).decode("utf-8")
                    data = json.loads(decoded)
                    sources = extract_source_files(data)
                    findings.append({
                        "map_url": "inline (data URI)",
                        "js_file": source_url,
                        "source_files": sources[:20],  # cap at 20
                        "total_sources": len(sources),
                        "risk": "HIGH",
                        "note": "Inline source map exposes original source structure"
                    })
                except Exception:
                    pass
                continue

            # Build absolute URL
            if map_ref.startswith("http"):
                map_url = map_ref
            else:
                from urllib.parse import urljoin
                map_url = urljoin(source_url, map_ref)

            data = fetch_sourcemap(map_url, timeout)
            if data:
                sources = extract_source_files(data)
                findings.append({
                    "map_url": map_url,
                    "js_file": source_url,
                    "source_files": sources[:20],
                    "total_sources": len(sources),
                    "risk": "HIGH",
                    "note": "Source map exposes original file structure and potentially source code"
                })

    # If no explicit reference found, try common patterns
    if not findings and source_url:
        map_url, data = try_common_sourcemap_urls(source_url, timeout)
        if data:
            sources = extract_source_files(data)
            findings.append({
                "map_url": map_url,
                "js_file": source_url,
                "source_files": sources[:20],
                "total_sources": len(sources),
                "risk": "HIGH",
                "note": "Publicly accessible source map found at predictable URL"
            })

    return findings
