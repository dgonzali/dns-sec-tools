#!/usr/bin/env python3
"""
UC4 – DGA Domain Detection
============================
Generates pseudo-random domain names using real DGA algorithms from known
malware families and resolves each through the configured DNS resolver
(PAN-OS firewall).

Families implemented:
  conficker   – MD5-based, date-seeded (variant B)
  cryptolocker – MD5 dictionary-based, date-seeded
  mirai       – Simple PRNG-based short domains
  locky       – MD5 chained hash

The firewall's ML-based DGA detection engine should recognise the statistical
patterns of these domain names and block/sinkhole them.

Usage:
  python uc4_dga_domains.py [--families conficker,locky] [--count 20]
"""

import argparse
import hashlib
import json
import os
import random
import struct
import sys
import time
from datetime import date, datetime

import dns.resolver
from colorama import Fore, Style, init
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
import config

init(autoreset=True)


# ---------------------------------------------------------------------------
# DGA Implementations
# ---------------------------------------------------------------------------

def dga_conficker(seed_date: date, count: int) -> list[str]:
    """
    Conficker variant B DGA.
    Generates domains seeded by the current date using MD5.
    TLDs rotate through a fixed list.
    """
    tlds = [".com", ".net", ".org", ".info", ".biz"]
    domains = []
    year, month, day = seed_date.year, seed_date.month, seed_date.day

    for i in range(count):
        seed = f"{year}{month:02d}{day:02d}{i}"
        domain = hashlib.md5(seed.encode()).hexdigest()[:12]
        tld = tlds[i % len(tlds)]
        domains.append(domain + tld)

    return domains


def dga_cryptolocker(seed_date: date, count: int) -> list[str]:
    """
    CryptoLocker DGA.
    Uses MD5 of date string and maps bytes to alphabet characters.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    tlds = [".com", ".net", ".biz", ".org", ".info", ".co.uk"]
    domains = []

    for i in range(count):
        seed = f"{seed_date.year}{seed_date.month}{seed_date.day}{i}"
        h = hashlib.md5(seed.encode()).digest()
        length = 12 + (h[0] % 5)   # domain length 12-16
        domain = "".join(alphabet[b % 26] for b in h[:length])
        tld = tlds[i % len(tlds)]
        domains.append(domain + tld)

    return domains


def dga_mirai(seed: int, count: int) -> list[str]:
    """
    Mirai-style DGA.
    Simple linear congruential generator producing short domains.
    """
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    tlds = [".com", ".net", ".org"]
    domains = []
    state = seed & 0xFFFFFFFF

    for i in range(count):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        length = 6 + (state % 9)   # 6-14 chars
        domain_chars = []
        for _ in range(length):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            domain_chars.append(chars[state % len(chars)])
        tld = tlds[i % len(tlds)]
        domains.append("".join(domain_chars) + tld)

    return domains


def dga_locky(seed_date: date, count: int) -> list[str]:
    """
    Locky DGA.
    Chained MD5 hash sequence seeded from the date.
    """
    tlds = [".com", ".de", ".ru", ".uk", ".info", ".net", ".org"]
    domains = []
    seed = f"locky_{seed_date.year}_{seed_date.month}_{seed_date.day}"
    h = hashlib.md5(seed.encode()).hexdigest()

    for i in range(count):
        h = hashlib.md5(h.encode()).hexdigest()
        length = 8 + (int(h[:2], 16) % 8)   # 8-15 chars
        domain = h[:length]
        tld = tlds[int(h[2:4], 16) % len(tlds)]
        domains.append(domain + tld)

    return domains


FAMILIES = {
    "conficker":    dga_conficker,
    "cryptolocker": dga_cryptolocker,
    "mirai":        None,           # special – uses int seed
    "locky":        dga_locky,
}


def generate_dga_domains(families: list[str], count: int) -> dict[str, list[str]]:
    today = date.today()
    result = {}
    for fam in families:
        fam = fam.lower().strip()
        if fam not in FAMILIES:
            print(f"{Fore.YELLOW}[!] Unknown family: {fam} – skipping")
            continue
        if fam == "mirai":
            seed = int(datetime.now().timestamp()) & 0xFFFFFFFF
            domains = dga_mirai(seed, count)
        else:
            domains = FAMILIES[fam](today, count)
        result[fam] = domains
        print(f"{Fore.CYAN}[*] {fam:<15} generated {len(domains)} domains")
    return result


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve(resolver_obj, domain: str) -> dict:
    try:
        answers = resolver_obj.resolve(domain, "A")
        return {"domain": domain, "status": "RESOLVED", "ips": [r.address for r in answers]}
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "status": "BLOCKED_NXDOMAIN", "ips": []}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "status": "BLOCKED_NOANSWER", "ips": []}
    except dns.resolver.Timeout:
        return {"domain": domain, "status": "TIMEOUT", "ips": []}
    except Exception as e:
        return {"domain": domain, "status": "ERROR", "ips": [], "error": str(e)}


STATUS_COLOR = {
    "BLOCKED_NXDOMAIN": Fore.GREEN,
    "BLOCKED_NOANSWER": Fore.GREEN,
    "RESOLVED":         Fore.RED,
    "TIMEOUT":          Fore.YELLOW,
    "ERROR":            Fore.MAGENTA,
}


def main():
    parser = argparse.ArgumentParser(description="UC4 – DGA Domain Detection")
    parser.add_argument("--families", default=",".join(config.DGA_FAMILIES),
                        help="Comma-separated list: conficker,cryptolocker,mirai,locky")
    parser.add_argument("--count", type=int, default=config.DGA_DOMAINS_PER_FAMILY)
    parser.add_argument("--resolver", default=config.DNS_RESOLVER)
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN)
    args = parser.parse_args()

    families = [f.strip() for f in args.families.split(",")]

    print(f"\n{'='*70}")
    print(f"  UC4 – DGA Domain Detection")
    print(f"  Resolver  : {args.resolver}")
    print(f"  Families  : {', '.join(families)}")
    print(f"  Per family: {args.count} domains")
    print(f"  Dry-run   : {args.dry_run}")
    print(f"{'='*70}\n")

    all_domains = generate_dga_domains(families, args.count)
    total = sum(len(v) for v in all_domains.values())
    print(f"\n{Fore.CYAN}[*] Total DGA domains generated: {total}\n")

    if args.dry_run:
        for fam, domains in all_domains.items():
            print(f"\n  [{fam.upper()}]")
            for d in domains:
                print(f"    → {d}")
        print(f"\n{Fore.YELLOW}[DRY-RUN] No queries sent.")
        return

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [args.resolver]
    resolver.timeout = config.QUERY_TIMEOUT
    resolver.lifetime = config.QUERY_TIMEOUT

    all_results = {}
    for fam, domains in all_domains.items():
        print(f"\n{Fore.CYAN}  ── {fam.upper()} ──")
        results = []
        for domain in tqdm(domains, desc=f"  {fam}", unit="domain"):
            r = resolve(resolver, domain)
            results.append(r)
            color = STATUS_COLOR.get(r["status"], Fore.WHITE)
            ips = ", ".join(r["ips"]) if r["ips"] else "-"
            print(f"    {color}[{r['status']:<20}]{Style.RESET_ALL} {r['domain']:<35} {ips}")
            time.sleep(config.QUERY_DELAY_SEC)
        all_results[fam] = results

    # Summary
    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY (per family)")
    for fam, results in all_results.items():
        blocked  = sum(1 for r in results if "BLOCKED" in r["status"])
        resolved = sum(1 for r in results if r["status"] == "RESOLVED")
        print(f"  {fam:<15}  Blocked: {Fore.GREEN}{blocked:<4}{Style.RESET_ALL}  Resolved: {Fore.RED}{resolved}{Style.RESET_ALL}")
    print(f"{'='*70}\n")

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(config.RESULTS_DIR, f"uc4_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump({
            "resolver": args.resolver,
            "timestamp": datetime.now().isoformat(),
            "families": {
                fam: {
                    "domains_generated": len(res),
                    "blocked": sum(1 for r in res if "BLOCKED" in r["status"]),
                    "resolved": sum(1 for r in res if r["status"] == "RESOLVED"),
                    "results": res,
                }
                for fam, res in all_results.items()
            }
        }, f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {out_file}")


if __name__ == "__main__":
    main()
