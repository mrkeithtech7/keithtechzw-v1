# language: Python 3.11, file: kts.py
"""KEITH TECH SCANNER V1.2 — main menu + self-test."""
import asyncio
import ipaddress
import os
import sys
import time

import banner
from banner import RED, CYAN, GREEN, YELLOW, GREY, RESET, DIM
from scanner import (scan_many, discover_subdomains,
                     DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT)
from dns_tools import dns_scan, format_dns
from related import find_related

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds.txt")


def _offline_enabled() -> bool:
    return os.environ.get("KTS_OFFLINE", "").strip() in ("1", "true", "yes")


# ─── Self-test ────────────────────────────────────────────────────────────

def run_self_test() -> int:
    print(f"{CYAN}  KEITH TECH SCANNER — self-test{RESET}\n")

    ok = 0
    fail = 0

    def check(label, fn):
        nonlocal ok, fail
        try:
            result = fn()
            if result:
                print(f"  {GREEN}[✓]{RESET} {label}: {result}")
                ok += 1
            else:
                print(f"  {YELLOW}[~]{RESET} {label}: no result (network may be down)")
                ok += 1  # not a code failure
        except Exception as e:
            print(f"  {RED}[✗]{RESET} {label}: {type(e).__name__}: {e}")
            fail += 1

    print(f"  python: {sys.version.split()[0]}")
    print(f"  platform: {sys.platform}")
    print(f"  offline flag: {_offline_enabled()}")
    print()

    # 1. imports
    check("import fingerprint", lambda: __import__("fingerprint") and "ok")
    check("import scanner",     lambda: __import__("scanner") and "ok")
    check("import dns_tools",   lambda: __import__("dns_tools") and "ok")
    check("import related",     lambda: __import__("related") and "ok")

    # 2. dnspython presence
    try:
        import dns.resolver
        print(f"  {GREEN}[✓]{RESET} dnspython: installed (full DNS scan available)")
        ok += 1
    except ImportError:
        print(f"  {YELLOW}[~]{RESET} dnspython: not installed (A-record fallback only)")
        # not a failure — scanner still works
        ok += 1

    # 3. CIDR fingerprint offline test
    from fingerprint import identify
    name, tag = identify("104.16.132.229")   # a known Cloudflare IP
    if name == "Cloudflare":
        print(f"  {GREEN}[✓]{RESET} offline fingerprint: {name} via {tag}")
        ok += 1
    else:
        print(f"  {RED}[✗]{RESET} offline fingerprint: got {name} via {tag}")
        fail += 1

    # 4. live probe (only if online)
    if _offline_enabled():
        print(f"  {YELLOW}[~]{RESET} live probe: skipped (KTS_OFFLINE=1)")
        ok += 1
    else:
        try:
            res = asyncio.run(scan_many(["cloudflare.com"], timeout=6))
            r = res[0]
            if r["ip"]:
                print(f"  {GREEN}[✓]{RESET} live probe: cloudflare.com → "
                      f"{r['ip']} ({r['latency_ms']:.0f}ms, {r['cdn']})")
                ok += 1
            else:
                print(f"  {YELLOW}[~]{RESET} live probe: no IP (no network?)")
                ok += 1
        except Exception as e:
            print(f"  {RED}[✗]{RESET} live probe: {type(e).__name__}: {e}")
            fail += 1

    # 5. seeds file
    seeds = _load_seeds()
    if seeds:
        print(f"  {GREEN}[✓]{RESET} seeds.txt: {len(seeds)} entries")
        ok += 1
    else:
        print(f"  {YELLOW}[~]{RESET} seeds.txt: missing or empty")
        ok += 1

    print()
    if fail == 0:
        print(f"{GREEN}  ✓ all checks passed ({ok} ok, 0 failed){RESET}")
        return 0
    print(f"{RED}  ✗ {fail} checks failed{RESET}")
    return 1


# ─── Output helpers ───────────────────────────────────────────────────────

def _fmt_result(r: dict) -> str:
    cdn_color = {
        "Cloudflare": CYAN, "Akamai": YELLOW, "AWS CloudFront": YELLOW,
        "Azure": CYAN, "Fastly": GREEN, "Sucuri": GREEN,
        "Google": GREEN, "Google Cloud": GREEN,
        "Imperva": YELLOW, "Bunny CDN": YELLOW,
    }.get(r["cdn"], GREY)

    status = r.get("http_status")
    s_str = (f"{GREEN}{status}{RESET}" if status == 200
             else f"{YELLOW}{status}{RESET}" if status
             else f"{DIM}—{RESET}")

    host = r["host"]
    if len(host) > 34:
        host = host[:31] + "..."
    ip = r["ip"] or "-"
    lat = f"{r['latency_ms']:>6.0f}ms"
    cdn = f"{cdn_color}{r['cdn']:<16}{RESET}"
    err = r.get("error", "")
    tail = f" {DIM}({err}){RESET}" if err else ""
    return (f"  {host:<34} {ip:<16} {lat}  {s_str:<12} "
            f"{cdn} {DIM}{r['evidence']}{RESET}{tail}")


def _print_header():
    print(f"{DIM}  {'HOST':<34} {'IP':<16} {'LAT':<8} "
          f"{'STATUS':<12} {'NETWORK':<16} EVIDENCE{RESET}")
    print(f"{DIM}  {'-'*110}{RESET}")


def _load_seeds() -> list:
    if not os.path.isfile(SEEDS):
        return []
    with open(SEEDS, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.startswith("#")]


def _run_scan(hosts: list, port: int) -> list:
    _print_header()
    t0 = time.time()
    try:
        results = asyncio.run(scan_many(hosts, port=port))
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  interrupted{RESET}")
        return []
    for r in sorted(results, key=lambda x: (x["cdn"], x["host"])):
        print(_fmt_result(r))
    print(f"\n{GREEN}  ✓ scanned {len(results)} hosts "
          f"in {time.time()-t0:.1f}s{RESET}")
    return results


# ─── Option 1 ─────────────────────────────────────────────────────────────

def option_sni_scan():
    banner.clear()
    off = _offline_enabled()
    print(f"{RED}  ── SNI HOST SCAN ──{RESET}")
    if off:
        print(f"{YELLOW}  [offline mode] crt.sh discovery disabled{RESET}\n")
    else:
        print()
    target = input(f"{CYAN}  domain or IP » {RESET}").strip()
    if not target:
        return

    try:
        ipaddress.ip_address(target)
        hosts = [target]
        print(f"\n{DIM}  target is an IP — probing directly{RESET}")
    except ValueError:
        if off:
            hosts = discover_subdomains(target, offline=True)
            print(f"{DIM}  offline: {len(hosts)} host guesses "
                  f"(common subs + apex){RESET}")
        else:
            print(f"\n{DIM}  querying crt.sh for {target}...{RESET}")
            hosts = discover_subdomains(target)
            print(f"{GREEN}  ✓ {len(hosts)} candidate hosts{RESET}")

    port_in = input(f"{CYAN}  port [443] » {RESET}").strip() or "443"
    try:
        port = int(port_in)
    except ValueError:
        port = 443

    print(f"\n{DIM}  scanning {len(hosts)} hosts on port {port} "
          f"(concurrency {DEFAULT_CONCURRENCY})...{RESET}\n")
    results = _run_scan(hosts, port)
    if results:
        tally = {}
        for r in results:
            tally[r["cdn"]] = tally.get(r["cdn"], 0) + 1
        print(f"\n{DIM}  network breakdown:{RESET}")
        for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
            print(f"    {k:<24} {v}")


# ─── Option 2 ─────────────────────────────────────────────────────────────

def option_file_scan():
    banner.clear()
    print(f"{RED}  ── TXT FILE SCAN ──{RESET}\n")
    path = input(f"{CYAN}  path to .txt » {RESET}").strip()
    if not path or not os.path.isfile(path):
        print(f"{YELLOW}  file not found{RESET}")
        return

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        hosts = [ln.strip() for ln in f
                 if ln.strip() and not ln.strip().startswith("#")]
    if not hosts:
        print(f"{YELLOW}  empty file{RESET}")
        return

    port_in = input(f"{CYAN}  port [443] » {RESET}").strip() or "443"
    try:
        port = int(port_in)
    except ValueError:
        port = 443

    print(f"\n{DIM}  scanning {len(hosts)} hosts on port {port}...{RESET}\n")
    results = _run_scan(hosts, port)
    if not results:
        return

    out = f"kts_scan_{int(time.time())}.csv"
    with open(out, "w", encoding="utf-8") as f:
        f.write("host,port,ip,latency_ms,http_status,cdn,evidence,"
                "server,tls_cn,error\n")
        for r in results:
            row = [
                r["host"], str(r["port"]), r["ip"],
                f"{r['latency_ms']:.1f}",
                str(r["http_status"] or ""),
                r["cdn"], r["evidence"],
                (r.get("server") or "").replace(",", ";"),
                (r.get("tls_cn") or "").replace(",", ";"),
                (r.get("error") or "").replace(",", ";"),
            ]
            f.write(",".join(row) + "\n")
    print(f"\n{GREEN}  ✓ saved → {out}{RESET}")


# ─── Option 3 ─────────────────────────────────────────────────────────────

def option_dns():
    banner.clear()
    print(f"{RED}  ── DNS SCAN ──{RESET}\n")
    domain = input(f"{CYAN}  domain » {RESET}").strip()
    if not domain:
        return
    print(f"\n{DIM}  querying records for {domain}...{RESET}\n")
    res = dns_scan(domain)
    print(f"{CYAN}  {domain}{RESET}")
    print(format_dns(res))


# ─── Option 4 ─────────────────────────────────────────────────────────────

def option_related():
    banner.clear()
    off = _offline_enabled()
    print(f"{RED}  ── RELATED DOMAINS ──{RESET}")
    if off:
        print(f"{YELLOW}  [offline mode] external recon disabled{RESET}")
    print()
    domain = input(f"{CYAN}  domain » {RESET}").strip()
    if not domain:
        return

    print(f"\n{DIM}  gathering data...{RESET}")
    data = find_related(domain, offline=off)

    print(f"\n{CYAN}  ip        {RESET}{data['ip'] or '-'}")
    print(f"{CYAN}  subdomains{RESET} ({len(data['subdomains'])})")
    for s in data["subdomains"][:40]:
        print(f"    {s}")
    if len(data["subdomains"]) > 40:
        print(f"    {DIM}... +{len(data['subdomains'])-40} more{RESET}")

    print(f"\n{CYAN}  same IP   {RESET}({len(data['same_ip'])})")
    for s in data["same_ip"][:40]:
        print(f"    {s}")

    print(f"\n{CYAN}  same NS   {RESET}({len(data['same_ns'])})")
    for s in data["same_ns"][:40]:
        print(f"    {s}")


# ─── Option 5 ─────────────────────────────────────────────────────────────

def option_seeds():
    banner.clear()
    print(f"{RED}  ── OFFLINE SEED SCAN ──{RESET}\n")
    seeds = _load_seeds()
    if not seeds:
        print(f"{YELLOW}  seeds.txt not found or empty{RESET}")
        return
    print(f"{DIM}  {len(seeds)} seeds from seeds.txt "
          f"(no external APIs){RESET}\n")
    _run_scan(seeds, 443)


# ─── Menu ─────────────────────────────────────────────────────────────────

MENU = [
    ("1", "SNI host scan     — auto-discover + fingerprint"),
    ("2", "TXT file scan     — bulk probe + CSV export"),
    ("3", "DNS scan          — A/AAAA/CNAME/MX/NS/TXT/SOA/PTR"),
    ("4", "Related domains   — CT + reverse-IP + shared NS"),
    ("5", "Offline seed scan — probe seeds.txt, zero external APIs"),
    ("6", "Self-test         — verify install works"),
    ("7", "Exit"),
]


def menu_loop():
    while True:
        banner.show_banner()
        if _offline_enabled():
            print(f"{YELLOW}  [KTS_OFFLINE=1 active — external APIs disabled]{RESET}\n")
        for k, label in MENU:
            print(f"  {RED}[{k}]{RESET} {label}")
        print()
        try:
            choice = input(f"{CYAN}  » {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}  bye.{RESET}\n")
            return

        try:
            if choice == "1":     option_sni_scan()
            elif choice == "2":   option_file_scan()
            elif choice == "3":   option_dns()
            elif choice == "4":   option_related()
            elif choice == "5":   option_seeds()
            elif choice == "6":   run_self_test()
            elif choice in ("7", "q", "exit"):
                print(f"\n{DIM}  bye.{RESET}\n"); return
            else:
                print(f"{YELLOW}  unknown option{RESET}")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}  cancelled{RESET}")
        except Exception as e:
            print(f"\n{RED}  error: {type(e).__name__}: {e}{RESET}")

        try:
            input(f"\n{DIM}  [enter] to return{RESET}")
        except (EOFError, KeyboardInterrupt):
            return


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        sys.exit(run_self_test())
    try:
        menu_loop()
    except KeyboardInterrupt:
        print(f"\n\n{DIM}  bye.{RESET}\n")
