# language: Python 3.11, file: scanner.py
"""Async SNI/TLS/HTTP probe + CDN fingerprint + CT discovery.
Core probe is stdlib-only — works with zero installs."""
import asyncio
import json as _json
import os
import socket
import ssl
import tempfile
import time
import urllib.request

from fingerprint import identify

DEFAULT_TIMEOUT = 8.0
DEFAULT_CONCURRENCY = 32
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "Chrome/120.0 Mobile Safari/537.36")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _parse_cert(der: bytes) -> dict:
    if not der:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception:
        return {}
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _cert_cn_sans(cert: dict) -> tuple:
    cn = ""
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    sans = []
    for kind, val in cert.get("subjectAltName", ()):
        if kind == "DNS":
            sans.append(val)
    return cn, sans


def _parse_http(data: bytes) -> tuple:
    if not data:
        return None, {}
    head, _, _ = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return None, {}
    parts = lines[0].decode("latin1", "replace").split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin1").strip()] = v.decode("latin1").strip()
    return status, headers


async def probe(host: str, port: int = 443,
                timeout: float = DEFAULT_TIMEOUT) -> dict:
    res = {
        "host": host, "port": port, "ip": "", "ptr": "",
        "latency_ms": 0.0,
        "tls_cn": "", "tls_sans": [],
        "http_status": None, "server": "",
        "cdn": "Unknown / Origin", "evidence": "none",
        "error": "",
    }
    t0 = time.perf_counter()

    try:
        loop = asyncio.get_event_loop()
        res["ip"] = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, host),
            timeout=timeout,
        )
    except Exception as e:
        res["error"] = f"resolve:{type(e).__name__}"
        res["latency_ms"] = (time.perf_counter() - t0) * 1000
        return res

    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_CTX, server_hostname=host),
            timeout=timeout,
        )
    except Exception as e:
        res["error"] = f"{type(e).__name__}"
        res["latency_ms"] = (time.perf_counter() - t0) * 1000
        name, tag = identify(res["ip"])
        res["cdn"], res["evidence"] = name, tag
        return res

    res["latency_ms"] = (time.perf_counter() - t0) * 1000

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            der = ssl_obj.getpeercert(binary_form=True)
            cert = _parse_cert(der)
            cn, sans = _cert_cn_sans(cert)
            res["tls_cn"], res["tls_sans"] = cn, sans
    except Exception:
        pass

    headers = {}
    try:
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        status, headers = _parse_http(data)
        res["http_status"] = status
        res["server"] = headers.get("Server") or headers.get("server") or ""
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    try:
        loop = asyncio.get_event_loop()
        ptr = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, res["ip"]),
            timeout=3.0,
        )
        res["ptr"] = ptr[0] if ptr else ""
    except Exception:
        pass

    name, tag = identify(res["ip"], headers, res["ptr"],
                         res["tls_cn"], res["tls_sans"])
    res["cdn"], res["evidence"] = name, tag
    return res


async def scan_many(hosts: list, port: int = 443,
                    concurrency: int = DEFAULT_CONCURRENCY,
                    timeout: float = DEFAULT_TIMEOUT) -> list:
    sem = asyncio.Semaphore(concurrency)

    async def worker(h):
        async with sem:
            try:
                return await probe(h, port, timeout)
            except Exception as e:
                return {"host": h, "port": port, "ip": "", "ptr": "",
                        "latency_ms": 0.0, "tls_cn": "", "tls_sans": [],
                        "http_status": None, "server": "",
                        "cdn": "Unknown / Origin", "evidence": "none",
                        "error": f"{type(e).__name__}"}

    return await asyncio.gather(*(worker(h) for h in hosts))


COMMON_SUBS = ("www", "api", "cdn", "static", "assets", "media", "mail",
               "app", "admin", "m", "dev", "test", "staging", "portal",
               "auth", "login", "secure", "img", "files", "download")


def discover_subdomains(domain: str, timeout: float = 8.0,
                        offline: bool = False) -> list:
    """CT discovery. offline=True skips crt.sh, returns common-word guesses only."""
    hosts = set()
    if not offline:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = _json.loads(r.read().decode("utf-8", "replace"))
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name and name.endswith(domain) and "*" not in name:
                        hosts.add(name)
        except Exception:
            pass
    for sub in COMMON_SUBS:
        hosts.add(f"{sub}.{domain}")
    hosts.add(domain)
    return sorted(h for h in hosts if h and " " not in h)
