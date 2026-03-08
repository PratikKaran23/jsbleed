# jsbleed 🩸

> Bleeds secrets out of JavaScript files.

**jsbleed** is a recon and JS analysis tool built for bug bounty hunters and penetration testers. It automates the discovery and analysis of JavaScript files across a target domain — finding exposed secrets, API keys, endpoints, auth flaws, and source maps so you can focus on exploitation.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-red.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

---

## 🔍 What it finds

| Module | What it detects |
|---|---|
| **Secrets** | OpenAI, Anthropic, AWS, GCP, Azure, Stripe, GitHub, Twilio, JWT, DB URIs, private keys, and 30+ more |
| **Endpoints** | API paths, routes, GraphQL endpoints, admin/debug routes |
| **Source Maps** | Exposed `.map` files that reveal original source structure |
| **Auth Patterns** | Client-side role checks, insecure JWT handling, OAuth secrets, weak crypto |
| **Parameters** | Query params, form fields, GraphQL variables, body keys |
| **Subdomains** | crt.sh certificate transparency + DNS brute-force |

---

## ⚡ Quick Start

```bash
# Install
pip install jsbleed

# Full recon on a domain
jsbleed -d example.com

# Analyze a single JS file
jsbleed -u https://example.com/static/app.js

# Analyze a list of JS URLs
jsbleed -l js_urls.txt

# Save output to JSON
jsbleed -d example.com -o results.json

# Only run specific modules
jsbleed -d example.com --only secrets,endpoints

# Skip subdomain enumeration (faster)
jsbleed -d example.com --no-subdomains
```

---

## 📸 Example Output

```
     _ _     _     _               _
    (_) |   | |   | |             | |
     _ ___  | |__ | | ___  ___  __| |
    | / __| | '_ \| |/ _ \/ _ \/ _` |
    | \__ \ | |_) | |  __/  __/ (_| |
    | |___/ |_.__/|_|\___|\___|\__,_|
   _/ |
  |__/   recon & JS analysis tool  v1.0

━━━ Subdomain Enumeration ━━━
  + api.example.com
  + app.example.com
  + staging.example.com

━━━ JS File Discovery ━━━
  [+] Found: https://app.example.com/static/js/main.abc123.js
  [+] Found: https://app.example.com/static/js/chunk.vendor.js

━━━ Analyzing JS Files ━━━

  🔑 SECRETS DETECTED (2)
  💀 [CRITICAL] OpenAI API Key
    Value   : sk-proj-Ab****************************Xy9z
    Source  : https://app.example.com/static/js/main.abc123.js

  🔴 [HIGH] AWS Access Key ID
    Value   : AKIA**************WX
    Source  : https://app.example.com/static/js/chunk.vendor.js

  🔗 ENDPOINTS (47)
  [HIGH] /api/v2/admin/users
  [HIGH] /api/internal/debug
  [MED]  /api/v1/auth/token/refresh
  ...

  🗺  SOURCE MAPS (1)
  [HIGH] https://app.example.com/static/js/main.abc123.js.map
    Sources : 134 original files exposed

━━━ Summary ━━━
  JS Files Analyzed : 8
  Endpoints Found   : 47
  Secrets Detected  : 2
  Source Maps Found : 1
  Auth Patterns     : 3
  Parameters Found  : 89
```

---

## 🛠 Installation

### From PyPI (recommended)
```bash
pip install jsbleed
```

### From source
```bash
git clone https://github.com/PratikKaran23/jsbleed
cd jsbleed
pip install -r requirements.txt
pip install -e .
```

---

## 📖 Usage

```
usage: jsbleed [-h] [-d DOMAIN] [-u URL] [-l LIST]
               [--no-subdomains] [--depth DEPTH] [--threads THREADS] [--timeout TIMEOUT]
               [--only ONLY] [--no-sourcemaps]
               [-o OUTPUT] [--quiet] [--no-color]

Target:
  -d, --domain    Target domain (runs full recon)
  -u, --url       Single JS file URL to analyze
  -l, --list      File containing list of JS URLs

Recon:
  --no-subdomains   Skip subdomain enumeration
  --depth INT       JS crawl depth (default: 2)
  --threads INT     Number of threads (default: 10)
  --timeout INT     Request timeout in seconds (default: 10)

Analysis:
  --only MODULES    Run only: secrets,endpoints,sourcemaps,auth,params
  --no-sourcemaps   Skip source map extraction

Output:
  -o, --output FILE   Save JSON report to file
  --quiet             Suppress banner and progress
  --no-color          Disable colored output
```

---

## 🔑 Secret Coverage

jsbleed detects 35+ secret types including:

**AI / LLM**
- OpenAI API Keys (`sk-` and `sk-proj-`)
- Anthropic API Keys (`sk-ant-`)
- HuggingFace Tokens (`hf_`)
- Replicate API Keys (`r8_`)

**Cloud**
- AWS Access Key IDs (`AKIA`)
- AWS Secret Access Keys
- GCP API Keys (`AIza`)
- Azure Storage Connection Strings

**Payment**
- Stripe Live/Test Keys
- Razorpay Keys
- PayPal Client Secrets

**DevOps**
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`)
- GitLab Tokens (`glpat-`)
- NPM Tokens (`npm_`)

**Database**
- MongoDB/PostgreSQL/MySQL/Redis URIs

**Other**
- JWT tokens, Basic Auth in URLs, Private Key blocks, Twilio, SendGrid, Mailgun, Firebase, and more

---

## 📤 JSON Report

Use `-o results.json` to save a structured report:

```json
{
  "tool": "jsbleed",
  "version": "1.0.0",
  "generated_at": "2024-01-15T12:00:00Z",
  "summary": {
    "js_files_analyzed": 8,
    "secrets_found": 2,
    "endpoints_found": 47,
    "critical_findings": 1
  },
  "findings": {
    "secrets": [...],
    "endpoints": [...],
    "sourcemaps": [...],
    "auth_patterns": [...],
    "parameters": [...]
  }
}
```

---

## ⚠️ Legal Disclaimer

jsbleed is intended for **authorized security testing only**. Only use this tool against targets you have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## 🤝 Contributing

PRs welcome. Areas to contribute:
- Additional secret patterns
- New analysis modules
- Output formats (HTML report, CSV)
- Performance improvements
- Proxy support

---

## 📄 License

MIT © [PratikKaran](https://github.com/PratikKaran23)

---

*Built for bug bounty hunters, by a bug bounty hunter.*
