# 🔍 jsscanner.py — Advanced JavaScript Secrets Scanner

> A Python-based reconnaissance tool for extracting and validating secrets from JavaScript files during bug bounty and penetration testing engagements.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![BugBounty](https://img.shields.io/badge/Bug%20Bounty-HackerOne-orange?style=flat-square)

---

## 📌 Overview

`jsscanner.py` is an advanced JavaScript secrets scanner built for real-world bug bounty recon. It goes beyond simple regex matching by combining **Shannon entropy scoring**, **context-aware pattern detection**, **confidence scoring**, and **live credential verification** to dramatically reduce false positives — a common pain point with existing tools.

Designed and battle-tested against real bug bounty targets including Airbnb, OPPO, Zomato, and more.

---

## ✨ Features

- **Shannon Entropy Scoring** — Filters out low-entropy strings that are statistically unlikely to be real secrets
- **Context-Aware Matching** — Pulls surrounding code context before flagging a finding, reducing noise
- **Confidence Scoring** — Each finding is ranked by confidence level (High / Medium / Low) so you know where to focus
- **Live Credential Verification** — Optionally validates discovered secrets against known API endpoints in real time
- **Crawl Mode** — Automatically discovers and scans linked JS files from a target URL
- **FP Filtering** — Aggressive false positive suppression logic refined across multiple real-world targets

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/jsscanner.git
cd jsscanner
pip install -r requirements.txt
```

**Requirements:**
- Python 3.8+
- `requests`
- `beautifulsoup4`
- `colorama`

---

## 🛠️ Usage

### Scan a single JS file or URL

```bash
python jsscanner.py -u https://target.com/static/app.js
```

### Crawl mode — discover and scan all JS files from a target

```bash
python jsscanner.py -u https://target.com --crawl
```

### Scan a local JS file

```bash
python jsscanner.py -f /path/to/file.js
```

### Enable live credential verification

```bash
python jsscanner.py -u https://target.com --crawl --verify
```

### Set minimum confidence threshold

```bash
python jsscanner.py -u https://target.com --min-confidence high
```

### Output results to a file

```bash
python jsscanner.py -u https://target.com --crawl -o results.txt
```

---

## 📊 Output Example

```
[HIGH]   AWS Access Key Found
         Pattern  : AKIA[0-9A-Z]{16}
         Value    : AKIAxxxxxxxxxxxxxxxx
         Entropy  : 4.82
         Context  : const awsConfig = { accessKeyId: "AKIAxxxxxxxxxxxxxxxx", region: "us-east-1" }
         File     : https://target.com/static/chunk.3f9a.js
         Verified : ✅ VALID (403 - InvalidClientTokenId not returned)

[MEDIUM] Potential API Token
         Pattern  : apiKey\s*[:=]\s*['"][A-Za-z0-9_\-]{32,}['"]
         Value    : sk-abcd1234...
         Entropy  : 3.91
         Context  : // fallback key for dev
         File     : https://target.com/vendor.js
         Verified : ⏭ Skipped (--verify not set)
```

---

## 🎯 Detected Secret Types

| Category | Examples |
|---|---|
| Cloud Keys | AWS Access Keys, GCP API Keys, Azure tokens |
| Auth Tokens | Bearer tokens, JWT secrets, OAuth client secrets |
| API Keys | Stripe, Twilio, SendGrid, Firebase, Mapbox |
| Database | MongoDB URIs, Postgres connection strings |
| Private Keys | RSA, EC private key headers |
| Generic Secrets | High-entropy strings matching secret/password/token patterns |

---

## 🧠 How FP Filtering Works

Most JS scanners flood you with false positives. `jsscanner.py` reduces noise through a layered approach:

1. **Entropy threshold** — Strings below a Shannon entropy of ~3.5 are discarded (e.g. placeholder text like `"your-api-key-here"`)
2. **Context window analysis** — Surrounding code is inspected for variable names, comments, and assignment context
3. **Known FP blocklist** — Common dummy values, test strings, and library internals are filtered out
4. **Confidence scoring** — Findings are ranked; low-confidence results are flagged separately

---

## ⚠️ Disclaimer

This tool is intended **strictly for authorized security testing and bug bounty programs**. Only use it against targets you have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## 👤 Author

**Prasoon**
- HackerOne Bug Bounty Hunter
- IT Student @ Lumbini ICT Campus, Nepal
- Focused on web application security, API security, and offensive recon tooling

---

## 🤝 Contributing

Pull requests are welcome. If you find a false positive pattern that slips through, open an issue with the context snippet and I'll add it to the filter list.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
