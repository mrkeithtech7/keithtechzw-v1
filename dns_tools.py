# language: Python 3.11, file: dns_tools.py
"""DNS scan — stdlib fallback when dnspython is absent."""
import socket

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def dns_scan(domain: str, timeout: float = 8.0) -> dict:
    out = {t: [] for t in RECORD_TYPES}
    out["PTR"] = []
    out["_error"] = ""

    if not _HAS_DNS:
        out["_error"] = "dnspython not installed — A record only (stdlib)"
        try:
            out["A"] = [socket.gethostbyname(domain)]
        except Exception as e:
            out["_error"] += f" ({e})"
        return out

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    for rtype in RECORD_TYPES:
        try:
            ans = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            out[rtype] = [r.to_text().strip('"') for r in ans]
        except Exception:
            pass

    if out["A"]:
        try:
            rev = dns.reversename.from_address(out["A"][0])
            ptr = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
            out["PTR"] = [r.to_text() for r in ptr]
        except Exception:
            pass
    return out


def format_dns(result: dict) -> str:
    lines = []
    for t in RECORD_TYPES + ("PTR",):
        vals = result.get(t) or []
        if vals:
            lines.append(f"  {t:<6} {vals[0]}")
            for v in vals[1:]:
                lines.append(f"         {v}")
    if result.get("_error"):
        lines.append(f"  ! {result['_error']}")
    return "\n".join(lines) if lines else "  (no records)"
