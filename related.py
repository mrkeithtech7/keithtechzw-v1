# language: Python 3.11, file: related.py
"""Related-domain recon. All external calls short-timeout, fail-safe."""
import json as _json
import socket
import urllib.request

UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "Chrome/120.0 Mobile Safari/537.36")
TIMEOUT = 8.0


def _get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")


def ct_subdomains(domain: str, offline: bool = False) -> list:
    if offline:
        return []
    try:
        data = _json.loads(_get(f"https://crt.sh/?q=%25.{domain}&output=json"))
    except Exception:
        return []
    hosts = set()
    for e in data:
        for n in e.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.").lower()
            if n and n.endswith(domain) and "*" not in n:
                hosts.add(n)
    return sorted(hosts)


def reverse_ip(ip: str, offline: bool = False) -> list:
    if offline or not ip:
        return []
    try:
        text = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if "No records" in text or text.lower().startswith("error"):
            return []
        return sorted({h.strip() for h in text.splitlines() if h.strip()})
    except Exception:
        return []


def shared_ns(domain: str, offline: bool = False) -> list:
    if offline:
        return []
    ns_hosts = []
    try:
        import dns.resolver
        ans = dns.resolver.resolve(domain, "NS", lifetime=8)
        ns_hosts = [r.to_text().rstrip(".").lower() for r in ans]
    except Exception:
        pass

    peers = set()
    for ns in ns_hosts:
        parts = ns.split(".")
        for i in range(1, len(parts) - 1):
            apex = ".".join(parts[i:])
            try:
                data = _json.loads(
                    _get(f"https://crt.sh/?q=%25.{apex}&output=json"))
                for e in data[:200]:
                    for n in e.get("name_value", "").split("\n"):
                        n = n.strip().lstrip("*.").lower()
                        if (n and n.endswith(apex)
                                and n.count(".") == apex.count(".") + 1):
                            peers.add(n)
            except Exception:
                continue
    peers = {p for p in peers if not p.endswith("." + domain) and p != domain}
    return sorted(peers)[:50]


def find_related(domain: str, offline: bool = False) -> dict:
    ip = ""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass
    return {
        "domain": domain,
        "ip": ip,
        "subdomains": ct_subdomains(domain, offline),
        "same_ip": reverse_ip(ip, offline),
        "same_ns": shared_ns(domain, offline),
    }
