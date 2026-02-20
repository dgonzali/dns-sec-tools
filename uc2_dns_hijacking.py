#!/usr/bin/env python3
"""
UC2 – DNS Hijacking / Response Spoofing Detection
===================================================
Sends DNS queries for known "clean" domains to the ROGUE DNS server.
The rogue server returns spoofed IPs (configured in its spoofing.conf).
The PAN-OS firewall, sitting between client and rogue server, should detect
the anomalous/spoofed response and generate a DNS hijacking threat log.

This script does NOT need scapy or raw sockets – it simply points its
resolver at the ROGUE_DNS_IP and sends normal queries. The spoofing happens
server-side (CoreDNS with custom zone files).

The test domains and their expected real IPs are defined in test_domains.txt
(one domain per line). The script resolves each domain twice:
  1) via 8.8.8.8         → "real" IP baseline
  2) via ROGUE_DNS_IP    → spoofed IP (through the firewall)

A mismatch between (1) and (2) confirms the spoof is active.

Usage:
  python uc2_dns_hijacking.py [--rogue-ip IP] [--resolver IP]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import dns.resolver
from colorama import Fore, Style, init
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
import config

init(autoreset=True)

# ---------------------------------------------------------------------------
# Default test domains (also read from test_domains.txt if present)
# ---------------------------------------------------------------------------
DEFAULT_TEST_DOMAINS = [
    "google.com",
    "bancosantander.es",
    "paypal.com",
    "microsoft.com",
    "amazon.com",
]


def load_test_domains(path: str = "test_domains.txt") -> list[str]:
    """Load domain list from file, fall back to defaults if not found."""
    if os.path.exists(path):
        with open(path) as f:
            domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"{Fore.CYAN}[*] Loaded {len(domains)} domains from {path}")
        return domains
    print(f"{Fore.YELLOW}[!] {path} not found – using built-in default domains")
    return DEFAULT_TEST_DOMAINS


def resolve_domain(nameserver: str, domain: str, timeout: int = 5) -> list[str]:
    """Resolve domain via given nameserver. Returns list of IPs or [] on failure."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, "A")
        return [r.address for r in answers]
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except dns.resolver.NoAnswer:
        return ["NO_ANSWER"]
    except dns.resolver.Timeout:
        return ["TIMEOUT"]
    except Exception as e:
        return [f"ERROR:{e}"]


def analyse(domain: str, real_ips: list[str], spoofed_ips: list[str]) -> dict:
    """Compare real vs spoofed resolution and determine status."""
    real_set = set(real_ips)
    spoofed_set = set(spoofed_ips)

    is_spoofed = not real_set.intersection(spoofed_set) and "TIMEOUT" not in spoofed_ips

    # Detect if firewall blocked the rogue response
    fw_blocked = spoofed_ips in (["NXDOMAIN"], ["NO_ANSWER"], ["TIMEOUT"])

    return {
        "domain": domain,
        "real_ips": real_ips,
        "spoofed_response": spoofed_ips,
        "is_spoofed": is_spoofed,
        "firewall_blocked": fw_blocked,
        "status": "FW_BLOCKED" if fw_blocked else ("SPOOFED_DELIVERED" if is_spoofed else "SAME_RESPONSE"),
    }


STATUS_COLOR = {
    "FW_BLOCKED":        Fore.GREEN,
    "SPOOFED_DELIVERED": Fore.RED,
    "SAME_RESPONSE":     Fore.YELLOW,
}


def main():
    parser = argparse.ArgumentParser(description="UC2 – DNS Hijacking / Response Spoofing Detection")
    parser.add_argument("--rogue-ip", default=config.ROGUE_DNS_IP, help="Rogue DNS server IP (Azure VM)")
    parser.add_argument("--resolver", default="8.8.8.8", help="Trusted resolver for baseline (default: 8.8.8.8)")
    parser.add_argument("--domains-file", default="test_domains.txt")
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN)
    args = parser.parse_args()

    print(f"\n{'='*70}")
    print(f"  UC2 – DNS Hijacking / Response Spoofing")
    print(f"  Rogue DNS  : {args.rogue_ip}")
    print(f"  Baseline   : {args.resolver}")
    print(f"  Dry-run    : {args.dry_run}")
    print(f"{'='*70}\n")

    domains = load_test_domains(args.domains_file)

    if args.dry_run:
        print(f"{Fore.YELLOW}[DRY-RUN] Would query these domains via rogue server {args.rogue_ip}:")
        for d in domains:
            print(f"  → {d}")
        print(f"\n  Rogue server should return spoofed IPs; firewall should block them.")
        return

    if args.rogue_ip == "0.0.0.0":
        print(f"{Fore.RED}[!] ROGUE_DNS_IP is not set in config.py. Please deploy the Azure server first.")
        sys.exit(1)

    results = []
    print(f"{'Domain':<35} {'Real IPs':<25} {'Rogue Response':<25} Status")
    print("-" * 95)

    for domain in tqdm(domains, desc="Testing", unit="domain"):
        real_ips = resolve_domain(args.resolver, domain)
        time.sleep(0.2)
        spoofed_ips = resolve_domain(args.rogue_ip, domain)
        r = analyse(domain, real_ips, spoofed_ips)
        results.append(r)

        color = STATUS_COLOR.get(r["status"], Fore.WHITE)
        print(
            f"  {r['domain']:<33} "
            f"{', '.join(r['real_ips']):<25} "
            f"{', '.join(r['spoofed_response']):<25} "
            f"{color}{r['status']}{Style.RESET_ALL}"
        )
        time.sleep(config.QUERY_DELAY_SEC)

    # Summary
    fw_blocked = [r for r in results if r["status"] == "FW_BLOCKED"]
    spoofed    = [r for r in results if r["status"] == "SPOOFED_DELIVERED"]
    same       = [r for r in results if r["status"] == "SAME_RESPONSE"]

    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY")
    print(f"  Firewall BLOCKED spoofed response : {Fore.GREEN}{len(fw_blocked)}{Style.RESET_ALL}")
    print(f"  Spoofed response DELIVERED        : {Fore.RED}{len(spoofed)}{Style.RESET_ALL}")
    print(f"  Same response (not spoofed?)       : {Fore.YELLOW}{len(same)}{Style.RESET_ALL}")
    print(f"{'='*70}\n")

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(config.RESULTS_DIR, f"uc2_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump({
            "rogue_dns": args.rogue_ip,
            "baseline_dns": args.resolver,
            "timestamp": datetime.now().isoformat(),
            "total": len(results),
            "fw_blocked": len(fw_blocked),
            "spoofed_delivered": len(spoofed),
            "domains": results,
        }, f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {out_file}")


if __name__ == "__main__":
    main()
