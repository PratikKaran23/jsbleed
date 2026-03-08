#!/usr/bin/env python3
"""
jsbleed - Bleeds secrets out of JS files
A recon & JS analysis tool for bug bounty hunters
"""

import argparse
import sys
from jsbleed.recon.subdomains import enumerate_subdomains
from jsbleed.recon.js_crawler import crawl_js_files
from jsbleed.analysis.endpoints import extract_endpoints
from jsbleed.analysis.secrets import detect_secrets
from jsbleed.analysis.sourcemap import extract_sourcemaps
from jsbleed.analysis.auth_logic import detect_auth_patterns
from jsbleed.analysis.params import discover_params
from jsbleed.output.terminal import print_banner, print_results, print_section
from jsbleed.output.json_report import save_json_report


def parse_args():
    parser = argparse.ArgumentParser(
        prog="jsbleed",
        description="jsbleed - Recon & JS analysis tool for bug bounty hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jsbleed -d example.com
  jsbleed -d example.com --no-subdomains
  jsbleed -u https://example.com/app.js
  jsbleed -d example.com -o results.json
  jsbleed -d example.com --only secrets,endpoints
        """
    )

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--domain", help="Target domain (runs full recon)")
    target.add_argument("-u", "--url", help="Single JS file URL to analyze")
    target.add_argument("-l", "--list", help="File containing list of JS URLs")

    recon = parser.add_argument_group("Recon")
    recon.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    recon.add_argument("--depth", type=int, default=2, help="JS crawl depth (default: 2)")
    recon.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    recon.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    analysis = parser.add_argument_group("Analysis")
    analysis.add_argument("--only", help="Run only specific modules (comma-separated): secrets,endpoints,sourcemaps,auth,params")
    analysis.add_argument("--no-sourcemaps", action="store_true", help="Skip source map extraction")

    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", help="Save JSON report to file")
    output.add_argument("--quiet", action="store_true", help="Suppress banner and progress")
    output.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser.parse_args()


def run_analysis(js_files, args, only_modules=None):
    results = {
        "js_files": [f["url"] for f in js_files],
        "endpoints": [],
        "secrets": [],
        "sourcemaps": [],
        "auth_patterns": [],
        "parameters": [],
    }

    def should_run(module):
        if only_modules:
            return module in only_modules
        return True

    for js in js_files:
        content = js.get("content", "")
        url = js.get("url", "")

        if should_run("endpoints"):
            found = extract_endpoints(content, url)
            results["endpoints"].extend(found)

        if should_run("secrets"):
            found = detect_secrets(content, url)
            results["secrets"].extend(found)

        if should_run("sourcemaps") and not args.no_sourcemaps:
            found = extract_sourcemaps(content, url)
            results["sourcemaps"].extend(found)

        if should_run("auth"):
            found = detect_auth_patterns(content, url)
            results["auth_patterns"].extend(found)

        if should_run("params"):
            found = discover_params(content, url)
            results["parameters"].extend(found)

    # Deduplicate
    results["endpoints"] = list({e["endpoint"]: e for e in results["endpoints"]}.values())
    results["parameters"] = list({p["param"]: p for p in results["parameters"]}.values())

    return results


def main():
    args = parse_args()

    if not args.quiet:
        print_banner()

    if not any([args.domain, args.url, args.list]):
        print("[!] No target specified. Use -d, -u, or -l. Run with --help for usage.")
        sys.exit(1)

    only_modules = None
    if args.only:
        only_modules = set(args.only.split(","))

    js_files = []

    # Mode 1: Full domain recon
    if args.domain:
        subdomains = []
        if not args.no_subdomains:
            print_section("Subdomain Enumeration", args.no_color)
            subdomains = enumerate_subdomains(args.domain, args.threads, args.timeout)
            print_results("subdomains", subdomains, args.no_color)

        targets = subdomains if subdomains else [args.domain]

        print_section("JS File Discovery", args.no_color)
        js_files = crawl_js_files(targets, args.depth, args.threads, args.timeout)
        print_results("js_files", js_files, args.no_color)

    # Mode 2: Single JS URL
    elif args.url:
        from jsbleed.recon.js_crawler import fetch_js
        js_content = fetch_js(args.url, args.timeout)
        if js_content:
            js_files = [{"url": args.url, "content": js_content}]

    # Mode 3: List of JS URLs
    elif args.list:
        from jsbleed.recon.js_crawler import fetch_js
        with open(args.list) as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            content = fetch_js(url, args.timeout)
            if content:
                js_files.append({"url": url, "content": content})

    if not js_files:
        print("[!] No JS files found or fetched.")
        sys.exit(0)

    print_section("Analyzing JS Files", args.no_color)
    results = run_analysis(js_files, args, only_modules)

    # Print analysis results
    for section in ["secrets", "endpoints", "sourcemaps", "auth_patterns", "parameters"]:
        if results[section]:
            print_results(section, results[section], args.no_color)

    # Summary
    print_section("Summary", args.no_color)
    print(f"  JS Files Analyzed : {len(js_files)}")
    print(f"  Endpoints Found   : {len(results['endpoints'])}")
    print(f"  Secrets Detected  : {len(results['secrets'])}")
    print(f"  Source Maps Found : {len(results['sourcemaps'])}")
    print(f"  Auth Patterns     : {len(results['auth_patterns'])}")
    print(f"  Parameters Found  : {len(results['parameters'])}")

    if args.output:
        save_json_report(results, args.output)
        print(f"\n  [+] JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
