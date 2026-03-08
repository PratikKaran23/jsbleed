"""
Subdomain enumeration via certificate transparency logs and DNS brute-force
"""

import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


WORDLIST = [
    "www", "api", "dev", "staging", "prod", "admin", "app", "mobile",
    "test", "beta", "cdn", "static", "assets", "media", "img", "images",
    "auth", "login", "sso", "oauth", "account", "portal", "dashboard",
    "v1", "v2", "v3", "internal", "backend", "frontend", "web", "mail",
    "smtp", "ftp", "vpn", "remote", "secure", "ssl", "m", "shop", "store",
    "blog", "docs", "help", "support", "status", "monitor", "analytics",
    "track", "data", "search", "payment", "pay", "billing", "invoice",
    "upload", "download", "files", "s3", "bucket", "backup", "db",
    "mysql", "postgres", "redis", "mongo", "elastic", "kibana", "jenkins",
    "ci", "git", "gitlab", "github", "jira", "confluence", "wiki",
]


def crtsh_subdomains(domain):
    """Fetch subdomains from crt.sh certificate transparency logs"""
    subdomains = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "jsbleed/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


def dns_resolve(subdomain):
    """Try to resolve a subdomain"""
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(subdomain)
        return subdomain
    except Exception:
        return None


def brute_force_subdomains(domain, threads=10):
    """DNS brute-force using built-in wordlist"""
    candidates = [f"{word}.{domain}" for word in WORDLIST]
    resolved = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(dns_resolve, sub): sub for sub in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)

    return set(resolved)


def enumerate_subdomains(domain, threads=10, timeout=10):
    """
    Full subdomain enumeration combining crt.sh + DNS brute-force
    Returns list of dicts with subdomain info
    """
    print(f"  [*] Querying crt.sh for {domain}...")
    crt_subs = crtsh_subdomains(domain)
    print(f"  [+] crt.sh found {len(crt_subs)} subdomains")

    print(f"  [*] DNS brute-force ({len(WORDLIST)} words, {threads} threads)...")
    brute_subs = brute_force_subdomains(domain, threads)
    print(f"  [+] Brute-force resolved {len(brute_subs)} subdomains")

    all_subs = crt_subs | brute_subs

    results = []
    for sub in sorted(all_subs):
        results.append({"subdomain": sub, "source": "crt.sh+brute"})

    return results
