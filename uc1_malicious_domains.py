#!/usr/bin/env python3
"""
UC1 – Malicious DNS Request Blocking
=====================================
Fetches fresh malicious domains from multiple threat intelligence feeds and
resolves each one through the configured DNS resolver (PAN-OS firewall).

Feeds used:
  1. Abuse.ch URLhaus   – recent malware-hosting URLs (free, no API key)
  2. OpenPhish         – phishing URLs (free, no API key)
  3. Custom HTTP URL   – your own plain-text IOC list (one domain per line)

Expected firewall behaviour: NXDOMAIN / SERVFAIL / sinkhole IP (blocked).

Usage:
  python uc1_malicious_domains.py [--resolver IP] [--max N]
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

# Local config
sys.path.insert(0, os.path.dirname(__file__))
import config

init(autoreset=True)

# ---------------------------------------------------------------------------
# Known sinkhole IPs used by security vendors (non-exhaustive)
# ---------------------------------------------------------------------------
SINKHOLE_IPS = {
    "0.0.0.0", "127.0.0.1",
    "146.112.61.106",   # Cisco OpenDNS
    "146.112.61.107",
    "204.11.56.48",     # Spamhaus
    "72.14.204.99",     # SURBL
    "67.215.65.132",     # OpenDNS
}

# ---------------------------------------------------------------------------
# Feed helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str | None:
    """Extract the hostname from a URL string."""
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host = parsed.hostname or ""
        # Strip port
        host = host.split(":")[0].strip().lower()
        # Must look like a real domain
        if re.match(r"^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$", host) and "." in host:
            return host
    except Exception:
        pass
    return None


def fetch_urlhaus(max_domains: int) -> list[str]:
    """Fetch recent malware domains from Abuse.ch URLhaus."""
    print(f"{Fore.CYAN}[*] Fetching from Abuse.ch URLhaus …")
    domains = []
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": max_domains * 5},
            timeout=30,
        )
        data = resp.json()
        for entry in data.get("urls", []):
            url = entry.get("url", "")
            d = _extract_domain(url)
            if d:
                domains.append(d)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] URLhaus error: {e}")
    domains = list(dict.fromkeys(domains))[:max_domains]
    print(f"{Fore.GREEN}[+] URLhaus: {len(domains)} domains")
    return domains


def fetch_openphish(max_domains: int) -> list[str]:
    """Fetch recent phishing domains from OpenPhish."""
    print(f"{Fore.CYAN}[*] Fetching from OpenPhish …")
    domains = []
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=30)
        for line in resp.text.splitlines():
            d = _extract_domain(line.strip())
            if d:
                domains.append(d)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] OpenPhish error: {e}")
    domains = list(dict.fromkeys(domains))[:max_domains]
    print(f"{Fore.GREEN}[+] OpenPhish: {len(domains)} domains")
    return domains


def fetch_custom_url(url: str, max_domains: int) -> list[str]:
    """Fetch domains from a user-defined HTTP endpoint (one domain per line)."""
    if not url:
        return []
    print(f"{Fore.CYAN}[*] Fetching from custom URL: {url}")
    domains = []
    try:
        resp = requests.get(url, timeout=30)
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            d = _extract_domain(line) or (line if re.match(r"^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$", line.lower()) else None)
            if d:
                domains.append(d.lower())
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Custom URL error: {e}")
    domains = list(dict.fromkeys(domains))[:max_domains]
    print(f"{Fore.GREEN}[+] Custom URL: {len(domains)} domains")
    return domains


# ---------------------------------------------------------------------------
# DNS resolution + classification
# ---------------------------------------------------------------------------

def classify_response(resolver_obj, domain: str) -> dict:
    """
    Resolve a domain and classify the result.

    Returns:
        dict with keys: domain, status, resolved_ips, latency_ms
    """
    start = time.time()
    result = {"domain": domain, "status": "UNKNOWN", "resolved_ips": [], "latency_ms": 0}

    try:
        answers = resolver_obj.resolve(domain, "A")
        elapsed = (time.time() - start) * 1000
        ips = [r.address for r in answers]
        result["resolved_ips"] = ips
        result["latency_ms"] = round(elapsed, 1)

        # Check for sinkhole
        if any(ip in SINKHOLE_IPS for ip in ips):
            result["status"] = "SINKHOLED"
        else:
            result["status"] = "RESOLVED"

    except dns.resolver.NXDOMAIN:
        result["status"] = "BLOCKED_NXDOMAIN"
        result["latency_ms"] = round((time.time() - start) * 1000, 1)
    except dns.resolver.NoAnswer:
        result["status"] = "BLOCKED_NOANSWER"
        result["latency_ms"] = round((time.time() - start) * 1000, 1)
    except dns.resolver.Timeout:
        result["status"] = "TIMEOUT"
        result["latency_ms"] = round((time.time() - start) * 1000, 1)
    except dns.exception.DNSException as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        result["latency_ms"] = round((time.time() - start) * 1000, 1)

    return result


STATUS_COLOR = {
    "BLOCKED_NXDOMAIN": Fore.GREEN,
    "BLOCKED_NOANSWER": Fore.GREEN,
    "SINKHOLED":        Fore.GREEN,
    "TIMEOUT":          Fore.YELLOW,
    "RESOLVED":         Fore.RED,
    "UNKNOWN":          Fore.WHITE,
    "ERROR":            Fore.MAGENTA,
}


def print_result(r: dict):
    color = STATUS_COLOR.get(r["status"], Fore.WHITE)
    ips = ", ".join(r["resolved_ips"]) if r["resolved_ips"] else "-"
    print(
        f"  {color}[{r['status']:<20}]{Style.RESET_ALL} "
        f"{r['domain']:<50} {ips:<20} {r['latency_ms']} ms"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="UC1 – Malicious DNS Request Blocking")
    parser.add_argument("--resolver", default=config.DNS_RESOLVER, help="DNS resolver IP (firewall)")
    parser.add_argument("--max", type=int, default=config.UC1_MAX_DOMAINS_PER_FEED, help="Max domains per feed")
    parser.add_argument("--custom-url", default=config.CUSTOM_DOMAINS_URL, help="Custom HTTP domain list URL")
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN)
    args = parser.parse_args()

    print(f"\n{'='*70}")
    print(f"  UC1 – Malicious DNS Request Blocking")
    print(f"  Resolver : {args.resolver}")
    print(f"  Dry-run  : {args.dry_run}")
    print(f"{'='*70}\n")

    # Collect domains from all feeds
    domains = []
    domains += fetch_urlhaus(args.max)
    domains += fetch_openphish(args.max)
    domains += fetch_custom_url(args.custom_url, args.max)

    # Deduplicate preserving order
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)

    print(f"\n{Fore.CYAN}[*] Total unique domains to test: {len(unique_domains)}\n")

    if args.dry_run:
        print(f"{Fore.YELLOW}[DRY-RUN] Would query these domains via {args.resolver}:")
        for d in unique_domains:
            print(f"  → {d}")
        return

    # Configure resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [args.resolver]
    resolver.timeout = config.QUERY_TIMEOUT
    resolver.lifetime = config.QUERY_TIMEOUT

    results = []
    print(f"{'Domain':<52} {'IPs':<20} {'Latency'}")
    print("-" * 80)

    for domain in tqdm(unique_domains, desc="Resolving", unit="domain"):
        r = classify_response(resolver, domain)
        results.append(r)
        print_result(r)
        time.sleep(config.QUERY_DELAY_SEC)

    # Summary
    blocked = [r for r in results if r["status"] in ("BLOCKED_NXDOMAIN", "BLOCKED_NOANSWER", "SINKHOLED")]
    resolved = [r for r in results if r["status"] == "RESOLVED"]
    timeouts = [r for r in results if r["status"] == "TIMEOUT"]

    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY")
    print(f"  Blocked / Sinkholed : {Fore.GREEN}{len(blocked)}{Style.RESET_ALL}")
    print(f"  Allowed (RESOLVED)  : {Fore.RED}{len(resolved)}{Style.RESET_ALL}")
    print(f"  Timeouts            : {Fore.YELLOW}{len(timeouts)}{Style.RESET_ALL}")
    print(f"{'='*70}\n")

    # Save results
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(config.RESULTS_DIR, f"uc1_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump({
            "resolver": args.resolver,
            "timestamp": datetime.now().isoformat(),
            "total": len(results),
            "blocked": len(blocked),
            "resolved": len(resolved),
            "timeouts": len(timeouts),
            "domains": results,
        }, f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {out_file}")


if __name__ == "__main__":
    main()
