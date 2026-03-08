"""
JS file discovery and download module
Crawls pages to find JS files, handles relative/absolute URLs
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

JS_PATTERN = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
    re.IGNORECASE
)

WEBPACK_CHUNK_PATTERN = re.compile(
    r'["\']([^"\']*chunk[^"\']*\.js)["\']|["\']([^"\']*bundle[^"\']*\.js)["\']',
    re.IGNORECASE
)


def normalize_url(url):
    """Ensure URL has a scheme"""
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def fetch_js(url, timeout=10):
    """Fetch JS file content"""
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            if "javascript" in content_type or "text" in content_type or url.endswith(".js"):
                return resp.text
    except Exception:
        pass
    return None


def fetch_page(url, timeout=10):
    """Fetch HTML page content"""
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None


def extract_js_urls_from_html(html, base_url):
    """Extract JS file URLs from HTML source"""
    js_urls = set()

    # Standard script tags
    for match in JS_PATTERN.finditer(html):
        src = match.group(1)
        full_url = urljoin(base_url, src)
        js_urls.add(full_url)

    # Webpack chunks / bundles referenced in JS
    for match in WEBPACK_CHUNK_PATTERN.finditer(html):
        src = match.group(1) or match.group(2)
        if src:
            full_url = urljoin(base_url, src)
            js_urls.add(full_url)

    return js_urls


def extract_js_urls_from_js(content, base_url):
    """Extract dynamically loaded JS URLs from within JS files"""
    js_urls = set()

    # import() calls and require() calls
    dynamic_patterns = [
        re.compile(r'import\s*\(["\']([^"\']+\.js)["\']', re.IGNORECASE),
        re.compile(r'require\s*\(["\']([^"\']+\.js)["\']', re.IGNORECASE),
        re.compile(r'["\']([^"\']*\/[^"\']+\.js)["\']'),
    ]

    for pattern in dynamic_patterns:
        for match in pattern.finditer(content):
            src = match.group(1)
            if src.startswith("http"):
                js_urls.add(src)
            elif src.startswith("/"):
                parsed = urlparse(base_url)
                js_urls.add(f"{parsed.scheme}://{parsed.netloc}{src}")

    return js_urls


def crawl_target(target, depth=2, timeout=10):
    """Crawl a single target domain/URL for JS files"""
    base_url = normalize_url(target if "/" in target else target)
    visited_pages = set()
    js_files = {}

    pages_to_visit = {base_url}

    for _ in range(depth):
        next_pages = set()
        for page_url in pages_to_visit:
            if page_url in visited_pages:
                continue
            visited_pages.add(page_url)

            html = fetch_page(page_url, timeout)
            if not html:
                continue

            js_urls = extract_js_urls_from_html(html, page_url)
            for js_url in js_urls:
                if js_url not in js_files:
                    content = fetch_js(js_url, timeout)
                    if content:
                        js_files[js_url] = content
                        # Look for more JS inside JS
                        deeper = extract_js_urls_from_js(content, js_url)
                        for d_url in deeper:
                            if d_url not in js_files:
                                d_content = fetch_js(d_url, timeout)
                                if d_content:
                                    js_files[d_url] = d_content

        pages_to_visit = next_pages - visited_pages

    return [{"url": url, "content": content} for url, content in js_files.items()]


def crawl_js_files(targets, depth=2, threads=10, timeout=10):
    """
    Crawl multiple targets for JS files in parallel
    targets: list of subdomains or URLs
    """
    all_js = {}

    def crawl_one(target):
        return crawl_target(target if isinstance(target, str) else target.get("subdomain", ""), depth, timeout)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(crawl_one, t): t for t in targets}
        for future in as_completed(futures):
            try:
                js_list = future.result()
                for js in js_list:
                    if js["url"] not in all_js:
                        all_js[js["url"]] = js
                        print(f"  [+] Found: {js['url']}")
            except Exception:
                pass

    return list(all_js.values())
