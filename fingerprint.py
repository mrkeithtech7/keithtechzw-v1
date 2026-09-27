# language: Python 3.11, file: fingerprint.py
"""CDN / network fingerprint — CIDR table + header + PTR + cert SAN signals.
Fully offline: the CIDR table is embedded, zero network calls."""
import ipaddress
import re

_CIDRS: list[tuple[str, str]] = [
    # Cloudflare
    ("173.245.48.0/20", "Cloudflare"), ("103.21.244.0/22", "Cloudflare"),
    ("103.22.200.0/22", "Cloudflare"), ("103.31.4.0/22",  "Cloudflare"),
    ("141.101.64.0/18", "Cloudflare"), ("108.162.192.0/18","Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"), ("188.114.96.0/20","Cloudflare"),
    ("197.234.240.0/22","Cloudflare"), ("198.41.128.0/17","Cloudflare"),
    ("162.158.0.0/15",  "Cloudflare"), ("104.16.0.0/13",  "Cloudflare"),
    ("104.24.0.0/14",   "Cloudflare"), ("172.64.0.0/13",  "Cloudflare"),
    ("131.0.72.0/22",   "Cloudflare"),
    # Fastly
    ("151.101.0.0/16",  "Fastly"), ("199.232.0.0/16",   "Fastly"),
    ("23.235.32.0/20",  "Fastly"), ("43.249.72.0/22",   "Fastly"),
    ("103.244.50.0/24", "Fastly"), ("103.245.222.0/23", "Fastly"),
    ("103.245.224.0/24","Fastly"), ("104.156.80.0/20",  "Fastly"),
    ("146.75.0.0/16",   "Fastly"), ("157.52.64.0/18",   "Fastly"),
    ("167.82.0.0/17",   "Fastly"), ("185.31.16.0/22",   "Fastly"),
    # Akamai
    ("23.32.0.0/11",    "Akamai"), ("23.192.0.0/11",    "Akamai"),
    ("104.64.0.0/10",   "Akamai"), ("184.24.0.0/13",    "Akamai"),
    ("184.50.0.0/15",   "Akamai"), ("184.84.0.0/14",    "Akamai"),
    ("2.16.0.0/13",     "Akamai"), ("23.0.0.0/12",      "Akamai"),
    ("96.6.0.0/15",     "Akamai"), ("96.16.0.0/15",     "Akamai"),
    ("23.62.0.0/15",    "Akamai"), ("23.72.0.0/13",     "Akamai"),
    # AWS CloudFront
    ("13.32.0.0/15",    "AWS CloudFront"), ("13.35.0.0/16",  "AWS CloudFront"),
    ("52.84.0.0/15",    "AWS CloudFront"), ("54.182.0.0/16", "AWS CloudFront"),
    ("54.192.0.0/16",   "AWS CloudFront"), ("54.230.0.0/16", "AWS CloudFront"),
    ("54.239.128.0/18", "AWS CloudFront"), ("99.84.0.0/16",  "AWS CloudFront"),
    ("143.204.0.0/16",  "AWS CloudFront"), ("204.246.164.0/22","AWS CloudFront"),
    ("3.160.0.0/13",    "AWS CloudFront"),
    # Azure / Microsoft
    ("13.107.0.0/16",   "Azure"), ("40.64.0.0/10",   "Azure"),
    ("52.96.0.0/12",    "Azure"), ("204.79.197.0/24","Azure"),
    ("13.80.0.0/14",    "Azure"), ("20.190.128.0/18","Azure"),
    ("40.126.0.0/18",   "Azure"),
    # Sucuri
    ("192.124.249.0/24","Sucuri"), ("66.248.200.0/22","Sucuri"),
    ("185.93.228.0/22", "Sucuri"),
    # Imperva / Incapsula
    ("45.64.64.0/22",   "Imperva"), ("103.28.248.0/22","Imperva"),
    ("107.154.0.0/16",  "Imperva"), ("149.126.72.0/21","Imperva"),
    ("185.11.124.0/22", "Imperva"), ("192.230.64.0/18","Imperva"),
    ("199.83.128.0/21", "Imperva"),
    # Google
    ("34.64.0.0/10",    "Google Cloud"), ("35.184.0.0/13","Google Cloud"),
    ("35.192.0.0/12",   "Google Cloud"), ("35.208.0.0/12","Google Cloud"),
    ("142.250.0.0/15",  "Google"), ("172.217.0.0/16","Google"),
    ("216.58.192.0/19", "Google"),
    # Bunny CDN
    ("145.14.0.0/16",   "Bunny CDN"), ("185.151.28.0/22","Bunny CDN"),
    # StackPath
    ("151.139.0.0/16",  "StackPath"), ("185.53.40.0/22","StackPath"),
    # KeyCDN
    ("45.113.120.0/22", "KeyCDN"),
    # Alibaba
    ("47.246.0.0/16",   "Alibaba CDN"), ("47.235.0.0/16","Alibaba CDN"),
    # Vercel / Netlify
    ("76.76.21.0/24",   "Vercel"), ("216.150.16.0/20","Vercel"),
    ("75.2.0.0/16",     "Netlify"),
]

_NETS: list[tuple] = []
for _c, _p in _CIDRS:
    try:
        _NETS.append((ipaddress.ip_network(_c), _p))
    except ValueError:
        pass


def cdn_from_ip(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, name in _NETS:
        if a in net:
            return name
    return None


_HEADER_SIGNS = [
    ("cf-ray",              "Cloudflare"),
    ("cf-cache-status",     "Cloudflare"),
    ("x-sucuri-id",         "Sucuri"),
    ("x-sucuri-cache",      "Sucuri"),
    ("x-akamai-transformed","Akamai"),
    ("x-akamai-request-id", "Akamai"),
    ("akamai-grn",          "Akamai"),
    ("x-azure-ref",         "Azure"),
    ("x-msedge-ref",        "Azure"),
    ("x-served-by",         "Fastly"),
    ("x-fastly-request-id", "Fastly"),
    ("x-amz-cf-id",         "AWS CloudFront"),
    ("x-amz-cf-pop",        "AWS CloudFront"),
    ("x-amzn-requestid",    "AWS"),
    ("x-cache-hits",        "Fastly"),
    ("x-iinfo",             "Imperva"),
]

_SERVER_SIGNS = [
    (r"cloudflare", "Cloudflare"),
    (r"sucuri",     "Sucuri"),
    (r"akamai",     "Akamai"),
    (r"ghost",      "Akamai"),
    (r"cloudfront","AWS CloudFront"),
    (r"azure",      "Azure"),
    (r"microsoft",  "Azure"),
    (r"gws\b",      "Google"),
    (r"gse\b",      "Google"),
    (r"bunny",      "Bunny CDN"),
    (r"imperva",    "Imperva"),
    (r"incapsula",  "Imperva"),
]

_PTR_SIGNS = [
    (r"cloudflare", "Cloudflare"),
    (r"akamai",     "Akamai"),
    (r"akamaitech", "Akamai"),
    (r"fastly",     "Fastly"),
    (r"amazonaws",  "AWS"),
    (r"cloudfront", "AWS CloudFront"),
    (r"azure",      "Azure"),
    (r"microsoft",  "Azure"),
    (r"google",     "Google"),
    (r"1e100",      "Google"),
    (r"sucuri",     "Sucuri"),
    (r"incap",      "Imperva"),
    (r"imperva",    "Imperva"),
    (r"bunny",      "Bunny CDN"),
]


def cdn_from_headers(headers: dict) -> str | None:
    lower = {k.lower(): v for k, v in headers.items()}
    for h, name in _HEADER_SIGNS:
        if h in lower:
            return name
    srv = lower.get("server", "")
    for pat, name in _SERVER_SIGNS:
        if re.search(pat, srv, re.I):
            return name
    via = lower.get("via", "")
    for pat, name in _SERVER_SIGNS:
        if re.search(pat, via, re.I):
            return name
    return None


def cdn_from_ptr(ptr: str) -> str | None:
    if not ptr:
        return None
    for pat, name in _PTR_SIGNS:
        if re.search(pat, ptr, re.I):
            return name
    return None


def cdn_from_cert(sans: list, cn: str = "") -> str | None:
    blob = (" ".join(sans) + " " + cn).lower()
    if "cloudflare" in blob:                return "Cloudflare"
    if "sucuri" in blob:                    return "Sucuri"
    if "akamai" in blob or "edgekey" in blob or "akamaiedge" in blob:
        return "Akamai"
    if "cloudfront" in blob or "amazonaws" in blob:
        return "AWS CloudFront"
    if "azure" in blob or "microsoft" in blob or "msedge" in blob:
        return "Azure"
    if "fastly" in blob:                    return "Fastly"
    if "imperva" in blob or "incapsula" in blob:
        return "Imperva"
    if "google" in blob or "gstatic" in blob:
        return "Google"
    return None


def identify(ip: str, headers: dict | None = None,
             ptr: str = "", cert_cn: str = "",
             cert_sans: list | None = None) -> tuple:
    """Return (cdn_name, evidence_tag). First match wins, most specific first."""
    h = headers or {}
    sans = cert_sans or []
    checks = (
        (lambda: cdn_from_headers(h),                "http-header"),
        (lambda: cdn_from_cert(sans, cert_cn),       "tls-cert"),
        (lambda: cdn_from_ptr(ptr),                  "ptr"),
        (lambda: cdn_from_ip(ip),                    "cidr"),
    )
    for fn, tag in checks:
        try:
            name = fn()
        except Exception:
            name = None
        if name:
            return name, tag
    return "Unknown / Origin", "none"
