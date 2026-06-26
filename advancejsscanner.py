#!/usr/bin/env python3
"""
Bundle Security Auditor
Scans JS/TS bundles for sensitive information leaks.
Usage: python audit_bundle.py <file_or_directory>
"""

import re
import sys
import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple


# ── Patterns ──────────────────────────────────────────────────────────────────

PATTERNS = [
    # --- Credentials & Keys ---
    ("API Key (generic)",        r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]",        "CRITICAL"),
    ("Secret / Password",        r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",           "CRITICAL"),
    ("Bearer Token",             r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",                                         "CRITICAL"),
    ("JWT Token",                r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",                  "CRITICAL"),
    ("AWS Access Key",           r"AKIA[0-9A-Z]{16}",                                                            "CRITICAL"),
    ("AWS Secret Key",           r"(?i)aws[_\-]?secret\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",                 "CRITICAL"),
    ("Google API Key",           r"AIza[0-9A-Za-z\-_]{35}",                                                      "CRITICAL"),
    ("Stripe Key",               r"(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}",                                     "CRITICAL"),
    ("Private Key Block",        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",                                    "CRITICAL"),
    ("GitHub Token",             r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",                           "CRITICAL"),
    ("Slack Token",              r"xox[baprs]-[0-9A-Za-z\-]{10,}",                                              "CRITICAL"),

    # --- Internal URLs & Endpoints ---
    ("Internal/Dev URL",         r"https?://(?:dev|staging|internal|local|test|uat|preprod)\w*\.[a-z]{2,}[^\s'\"]*", "HIGH"),
    ("Localhost URL",            r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[:/][^\s'\"]*",                 "HIGH"),
    ("IP Address URL",           r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",                               "HIGH"),
    ("Hardcoded API Origin",     r"(?i)(origin|baseUrl|apiUrl|endpoint)\s*[:=]\s*['\"]https?://[^\s'\"]{8,}['\"]", "HIGH"),

    # --- Auth & Session ---
    ("Auth Header Construction", r"(?i)(Authorization|X-Auth-Token|X-API-Key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",  "HIGH"),
    ("Token in Storage Key",     r"(?i)localStorage\.(?:get|set)Item\(['\"](?:token|auth|jwt|session)['\"]",    "MEDIUM"),
    ("Cookie with token name",   r"(?i)document\.cookie\s*=\s*['\"][^'\"]*(?:token|auth|session)",              "MEDIUM"),

    # --- Debug / Hidden Features ---
    ("Debug/Cheat Code",         r"(?i)(cheat|debug|backdoor|admin_bypass|scoreCheat|devMode)",                  "MEDIUM"),
    ("console.log with data",    r"console\.(?:log|warn|error|debug)\([^)]{0,200}(?:token|key|secret|password)[^)]{0,200}\)", "MEDIUM"),
    ("TODO/FIXME security note", r"(?i)(?:TODO|FIXME|HACK|XXX)[^\n]*(?:auth|token|key|secret|password|bypass)", "LOW"),

    # --- PII / Business Data ---
    ("Email Address",            r"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,}(?!\.(js|ts|jsx|tsx|png|svg))", "LOW"),
    ("Phone Number",             r"(?<!\d)(\+?1?\s*[\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})(?!\d)",        "LOW"),
    ("Internal path/username",   r"(?i)/(?:home|users|usr)/[a-z_][a-z0-9_\-]{1,30}/",                          "LOW"),
]

# Known-safe patterns to suppress false positives
ALLOWLIST = [
    r"example\.com",
    r"placeholder",
    r"your[_\-]?api[_\-]?key",
    r"<YOUR",
    r"INSERT",
    r"xxxx",
    r"test@test",
    r"foo@bar",
    r"@example",
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[37m",  # grey
    "RESET":    "\033[0m",
}

EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".map"}


# ── Core logic ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    label: str
    file: str
    line: int
    snippet: str


def is_allowlisted(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in ALLOWLIST)


def scan_content(content: str, filename: str) -> List[Finding]:
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for label, pattern, severity in PATTERNS:
            for match in re.finditer(pattern, line):
                snippet = match.group(0)
                if is_allowlisted(snippet):
                    continue
                # Trim long snippets
                snippet = snippet[:120] + ("…" if len(snippet) > 120 else "")
                findings.append(Finding(
                    severity=severity,
                    label=label,
                    file=filename,
                    line=lineno,
                    snippet=snippet.strip(),
                ))
    return findings


def scan_file(path: Path) -> List[Finding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return scan_content(content, str(path))
    except Exception as e:
        print(f"  [!] Could not read {path}: {e}", file=sys.stderr)
        return []


def collect_files(target: str) -> List[Path]:
    p = Path(target)
    if p.is_file():
        return [p]
    return [f for f in p.rglob("*") if f.suffix in EXTENSIONS and f.is_file()]


# ── Output ────────────────────────────────────────────────────────────────────

def colorize(severity: str, text: str) -> str:
    c = SEVERITY_COLORS.get(severity, "")
    r = SEVERITY_COLORS["RESET"]
    return f"{c}{text}{r}"


def print_report(findings: List[Finding], use_color: bool = True):
    if not findings:
        print("\n✅  No sensitive patterns found.")
        return

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'='*70}")
    print(f"  BUNDLE SECURITY AUDIT — {sum(counts.values())} finding(s)")
    print(f"{'='*70}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            tag = colorize(sev, f"[{sev}]") if use_color else f"[{sev}]"
            print(f"  {tag}  {counts[sev]} finding(s)")
    print(f"{'='*70}\n")

    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            header = colorize(f.severity, f"── {f.severity} ") if use_color else f"── {f.severity} "
            print(f"\n{header}{'─'*(60-len(f.severity))}")

        sev_tag = colorize(f.severity, f"[{f.severity}]") if use_color else f"[{f.severity}]"
        print(f"\n  {sev_tag} {f.label}")
        print(f"  File : {f.file}:{f.line}")
        print(f"  Match: {f.snippet}")

    print(f"\n{'='*70}\n")


def export_json(findings: List[Finding], out_path: str):
    data = [
        {"severity": f.severity, "label": f.label,
         "file": f.file, "line": f.line, "snippet": f.snippet}
        for f in findings
    ]
    Path(out_path).write_text(json.dumps(data, indent=2))
    print(f"  JSON report written to: {out_path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    json_out = None

    if "--json" in args:
        idx = args.index("--json")
        json_out = args[idx + 1]
        args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]

    if not args:
        print("Usage: python audit_bundle.py <file_or_dir> [--json output.json]")
        print("\nExample:")
        print("  python audit_bundle.py ./dist")
        print("  python audit_bundle.py bundle.js --json results.json")
        sys.exit(1)

    target = args[0]
    files = collect_files(target)

    if not files:
        print(f"No JS/TS files found at: {target}")
        sys.exit(1)

    print(f"\nScanning {len(files)} file(s) in: {target}")

    all_findings = []
    for f in files:
        findings = scan_file(f)
        all_findings.extend(findings)
        if findings:
            crits = sum(1 for x in findings if x.severity == "CRITICAL")
            highs = sum(1 for x in findings if x.severity == "HIGH")
            print(f"  {'⚠️ ' if crits or highs else '  '}{f}  →  {len(findings)} finding(s)")

    use_color = sys.stdout.isatty()
    print_report(all_findings, use_color=use_color)

    if json_out:
        export_json(all_findings, json_out)

    # Exit code: 1 if CRITICAL/HIGH found (useful in CI)
    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()




Step 1 — Reconnaissance (Find the JS bundles)
bash
# Create a folder for your target
mkdir ~/targets/targetname
cd ~/targets/targetname

# Download the homepage HTML first
wget https://www.target.com -O index.html

# Extract all JS file URLs from the HTML
grep -oP '(?:src=")[^"]+\.js[^"]*' index.html
grep -oP '/_next/static/[^"]+\.js' index.html
grep -oP '/static/js/[^"]+\.js' index.html

Step 2 — Download All JS Bundles
bash
# Method 1 - wget recursive (best for most sites)
wget -r -l 2 -A "*.js" -nd https://www.target.com -P ./js/

# Method 2 - if site uses _next (Next.js)
wget -r -l 3 -A "*.js" -nd https://www.target.com/_next/ -P ./js/

# Method 3 - if site uses /static/js (React CRA)
wget -r -l 3 -A "*.js" -nd https://www.target.com/static/js/ -P ./js/

# Check what you got
ls -lh ./js/
wc -l ./js/*.js

Step 3 — Scan All Files
bash
# Scan everything at once
for f in ./js/*.js; do
    echo "=== $f ==="
    python3 ~/audit_bundle.py "$f"
done

# Save output to a file for review
for f in ./js/*.js; do
    python3 ~/audit_bundle.py "$f"
done > results.txt 2>&1

# View only findings (skip clean files)
grep -A 4 "\[CRITICAL\]\|\[HIGH\]\|\[MEDIUM\]" results.txt

Step 4 — Triage the Findings
For each finding, ask:
CRITICAL → Test immediately
HIGH     → Test after criticals
MEDIUM   → Note and review
LOW      → Ignore unless combined with other findings

Step 5 — Test API Keys
bash
# Generic Google API key test
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=FOUND_KEY"

# Check if referer restricted
curl "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=FOUND_KEY"

# Firebase
curl "https://PROJECTID.firebaseio.com/.json?auth=FOUND_KEY"

# AWS (if found)
aws configure  # enter found key + secret
aws s3 ls      # test access
aws iam get-user  # check permissions

# Stripe (if found)
curl https://api.stripe.com/v1/customers \
  -u FOUND_KEY:
What responses mean:
Real data returned        → EXPLOITABLE → Submit as High/Critical
REQUEST_DENIED (referer)  → Restricted  → Test referer spoof
SERVICE_DISABLED          → Not enabled → Low value
INVALID_KEY               → Fake/dead   → Skip

Step 6 — Test Referer Restrictions (if blocked)
bash
# Spoof the referer header
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=FOUND_KEY" \
  -H "Referer: https://www.target.com"

# Try with origin header too
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=FOUND_KEY" \
  -H "Referer: https://www.target.com" \
  -H "Origin: https://www.target.com"

Step 7 — Test Internal URLs
bash
# If dev/staging URLs found in bundle
curl -I https://dev.target.com
curl -I https://devapi.target.com
curl -I https://staging.target.com

# Look for exposed endpoints
curl https://devapi.target.com/api/v1/users
curl https://devapi.target.com/api/v1/admin

Step 8 — Document Everything
bash
# Screenshot tool for terminal output
script -a ~/targets/targetname/session.log

# Save all curl responses
curl "URL" | tee response1.json

# Note timestamps
date >> findings.txt
echo "Found KEY in FILE at LINE" >> findings.txt

Full One-Liner Workflow
bash
# Set your target
TARGET="https://www.target.com"
NAME="targetname"

# Create workspace
mkdir -p ~/targets/$NAME/js
cd ~/targets/$NAME

# Download JS
wget -r -l 2 -A "*.js" -nd $TARGET -P ./js/

# Scan all
for f in ./js/*.js; do
    python3 ~/audit_bundle.py "$f"
done | tee results.txt

# Show only hits
grep -A 4 "CRITICAL\|HIGH\|MEDIUM" results.txt
