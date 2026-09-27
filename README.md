# KEITH TECH SCANNER V1.2

Multi-purpose network recon toolkit — SNI host scanning, CDN / network
fingerprinting, DNS enumeration, related-domain discovery.

Built for **Termux on Android**, runs on **Linux** and **macOS**.
Core scan is pure Python stdlib — **works with zero installs and zero
external APIs** in offline mode.

Repo: `github.com/mrkeithtech7/keithtechzw-v1`

---

## Install — Termux (Android)

Copy-paste one block at a time:

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
git clone https://github.com/mrkeithtech7/keithtechzw-v1.git
cd keithtechzw-v1
bash install.sh
python kts.py
```

That's it. The red skeleton banner appears, pick a number, go.

### Run from anywhere on Termux

`install.sh` on Termux drops a launcher at `$PREFIX/bin/kts`, so after
install you can type just:

```bash
kts
```

from any directory.

---

## Install — Linux / macOS

```bash
git clone https://github.com/mrkeithtech7/keithtechzw-v1.git
cd keithtechzw-v1
bash install.sh
python3 kts.py
```

---

## Zero-bundle / offline mode

**Core scan uses the network only to reach the target** — no external
recon APIs are needed for the probe itself. All optional helpers
(crt.sh, HackerTarget) have short timeouts and fail silently.

To run with **no external recon APIs**:

```bash
KTS_OFFLINE=1 python kts.py
```

In offline mode:
- **Option 1** probes only the apex + common subdomain guesses — no crt.sh.
- **Option 4** disables CT / reverse-IP / shared-NS — returns apex IP only.
- **Option 5** (seed scan) is unaffected — it's already 100% offline.

### Pure zero-bundle path

If you never want to pip install anything:

```bash
pkg install -y python           # only Python — no pip, no git even
# copy the .py files into a folder
python kts.py
```

Everything works. The DNS scan falls back to A-record via stdlib.
No `pip install` step required.

### Truly zero-network scan

Menu **Option 5 — Offline seed scan** probes a bundled list
(`seeds.txt`). No DNS-based discovery, no CT lookups. Just hosts you
or the repo already know about, probed over TLS.

Edit `seeds.txt` to add your own hosts. One per line, `#` for comments.

---

## Verify the install works

```bash
python3 kts.py --check
```

Runs a self-test:
- Imports all modules
- Tests the offline CDN fingerprint against a known Cloudflare IP
- Runs a live probe (skipped in `KTS_OFFLINE=1`)
- Confirms `seeds.txt` loads

You'll see `[✓]` for each check that passes. If anything is broken,
the self-test tells you exactly what.

---

## Files

```
kts.py            main menu + self-test
kts               shell launcher (installs to PATH on Termux)
banner.py         skeleton ASCII + colors
scanner.py        TLS/HTTP probe + CT discovery
fingerprint.py    CDN CIDR table + header / cert / PTR signals
dns_tools.py      DNS record scan (dnspython optional)
related.py        CT + reverse-IP + shared-NS recon
seeds.txt         bundled hosts for offline seed scan
requirements.txt  optional python deps
install.sh        one-shot installer
.gitignore
LICENSE           MIT
README.md         you are here
```

---

## Menu

**[1] SNI host scan — auto-discover + fingerprint.**
Enter a domain or IP. Domain → pulls every subdomain from certificate
transparency (crt.sh) plus a common-word list, then probes each on 443
over real TLS. Output: resolved IP, latency, HTTP status, and the
network / CDN the target sits behind.

**[2] TXT file scan — bulk probe + CSV export.**
Same probe, reads a list — one host per line, `#` for comments. Writes
`kts_scan_<timestamp>.csv`.

**[3] DNS scan.**
A / AAAA / CNAME / MX / NS / TXT / SOA + reverse PTR. `dnspython`
optional — without it, A record only via stdlib.

**[4] Related domains.**
CT subdomains, reverse-IP (HackerTarget), shared-NS peer discovery.

**[5] Offline seed scan.**
Probes `seeds.txt` — zero external APIs.

**[6] Self-test.**
Verifies every module loads and the fingerprint engine works.

**[7] Exit.**

---

## How the CDN fingerprint works

Four independent signals, ranked, first match wins:

1. **HTTP response headers** — `cf-ray` → Cloudflare, `x-sucuri-id` →
   Sucuri, `x-akamai-*` → Akamai, `x-azure-ref` → Azure, `x-amz-cf-id`
   → CloudFront.
2. **TLS certificate CN/SAN** — operator names in edge certs.
3. **Reverse DNS (PTR)** — `*.cloudflare.com`, `*.akamaiedge.net`, etc.
4. **CIDR table** — offline map of published CDN ranges.

The `evidence` tag on each row tells you which signal decided it:
`http-header`, `tls-cert`, `ptr`, or `cidr`. If it says `cidr`, the
target is behind that CDN but didn't serve headers — usually a proxy
in front of a cached object.

Everything except the live probe itself is offline-capable.

---

## Troubleshooting

**`ModuleNotFoundError: dnspython`**
Run `pip install dnspython`. Or skip — DNS falls back to A-record via
stdlib. Everything else works.

**DNS scan returns A only**
Same — dnspython failed to install. Everything else still works.

**crt.sh returns nothing**
Rate-limited or offline. Retry in a minute, or use `KTS_OFFLINE=1`.

**Scan is slow**
Concurrency is 32. Edit `DEFAULT_CONCURRENCY` in `scanner.py` to raise.
Carrier gateways start lying above ~256.

**All hosts show `Unknown / Origin`**
The target has no CDN. That's a real answer, not a bug.

**`kts: command not found` after install**
PATH launcher is only installed on Termux. On Linux/macOS, run
`python3 kts.py` or add the folder to your PATH.

**Colors don't show**
Set `NO_COLOR=` or run in an interactive terminal. The script drops
colors cleanly when piped or in a dumb shell.

---

## Upload to your GitHub

First-time push:

```bash
cd keithtechzw-v1
git init
git add .
git commit -m "KEITH TECH SCANNER V1.2"
git branch -M main
git remote add origin https://github.com/mrkeithtech7/keithtechzw-v1.git
git push -u origin main
```

Update an existing repo:

```bash
git add .
git commit -m "update"
git push
```

---

## License

MIT — see `LICENSE`.
