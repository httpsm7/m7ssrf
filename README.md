# M7 SSRF — Advanced SSRF Research Tool

```
  ███╗   ███╗ ███████╗     ███████╗███████╗██████╗ ███████╗
  ████╗ ████║ ╚════██║     ██╔════╝██╔════╝██╔══██╗██╔════╝
  ██╔████╔██║     ██╔╝     ███████╗███████╗██████╔╝█████╗
  ██║╚██╔╝██║    ██╔╝      ╚════██║╚════██║██╔══██╗██╔══╝
  ██║ ╚═╝ ██║   ██║███████╗███████║███████║██║  ██║██║
  ╚═╝     ╚═╝   ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
```

**Made by Milkyway Intelligence | Author: Sharlix Martin**

---

## Features

- **Auto Parameter Discovery** — Detects `url`, `redirect`, `path`, `file`, `src`, `dest`, and 50+ SSRF-prone parameters automatically
- **Payload Mutation Engine** — Generates decimal, hex, octal, IPv6, and encoding variants of target IPs
- **Blind SSRF Detection** — OOB via Interactsh, DNSlog.cn, or custom callback host
- **SSRF Chaining Engine** — Probes 25+ internal ports/services after initial SSRF
- **Cloud Metadata Detection** — AWS, GCP, Azure, DigitalOcean, Alibaba Cloud
- **Protocol Fuzzing** — `file://`, `dict://`, `gopher://`, `sftp://`, `ftp://`, `ldap://`
- **Filter Bypasses** — IP encoding, octal, hex, unicode, whitespace tricks, URL wrappers
- **Response Analysis** — 50+ detection signatures for credentials, banners, services
- **Async Engine** — httpx + asyncio for fast multi-threaded scanning
- **Proxy Support** — Burp Suite / SOCKS proxy passthrough

---

## Installation

```bash
git clone https://github.com/Sharlix/m7ssrf
cd m7ssrf
sudo chmod +x install.sh
sudo ./install.sh
```

The installer automatically checks for `python3`, `pip`, `git`, `curl` and installs all dependencies.

---

## Usage

### Basic scan
```bash
m7ssrf -u https://target.com
```

### Scan URL with known SSRF parameter
```bash
m7ssrf -u "https://target.com/api?url=test"
```

### Specify parameters manually
```bash
m7ssrf -u https://target.com --params url,redirect,path,file
```

### Full scan (all modules)
```bash
m7ssrf -u https://target.com --full
```

### Blind SSRF with Interactsh
```bash
m7ssrf -u https://target.com --blind --interactsh-url https://your.oast.fun
```

### Blind SSRF with DNSlog
```bash
m7ssrf -u https://target.com --blind --dnslog-domain abc123.dnslog.cn
```

### Cloud metadata detection
```bash
m7ssrf -u https://target.com --cloud-detect
```

### SSRF chaining (port scan via SSRF)
```bash
m7ssrf -u https://target.com --chain
```

### Mutation engine (IP encoding variants)
```bash
m7ssrf -u https://target.com --mutate
```

### Scan multiple targets
```bash
m7ssrf -f targets.txt --threads 20
```

### Safe mode (pentest restrictions)
```bash
m7ssrf -u https://target.com --safe
```

### With Burp Suite proxy
```bash
m7ssrf -u https://target.com --proxy http://127.0.0.1:8080
```

### JSON output
```bash
m7ssrf -u https://target.com --json -o ./my-results
```

### Custom headers
```bash
m7ssrf -u https://target.com -H "Authorization: Bearer TOKEN" -H "X-Custom: value"
```

---

## Options

| Flag | Description |
|------|-------------|
| `-u URL` | Single target URL |
| `-f FILE` | File with URLs (one per line) |
| `-p PARAMS` | Custom parameter list (comma-separated) |
| `--blind` | Enable blind SSRF detection |
| `--chain` | Enable SSRF chaining engine |
| `--safe` | Safe mode — localhost/metadata only |
| `--cloud-detect` | AWS/GCP/Azure metadata endpoints |
| `--mutate` | Payload mutation engine |
| `--full` | Enable all modules |
| `--interactsh-url` | Interactsh/OAST server URL |
| `--dnslog-domain` | DNSlog domain for OOB |
| `--callback-host` | Custom OOB callback host |
| `--threads N` | Concurrent threads (default: 10) |
| `--timeout SEC` | Request timeout (default: 10) |
| `--delay SEC` | Delay between requests |
| `--retries N` | Retry count (default: 2) |
| `--proxy URL` | HTTP/SOCKS proxy |
| `-H HEADER` | Custom header (repeatable) |
| `--method` | HTTP method: GET/POST/PUT |
| `--no-redirects` | Disable redirect following |
| `-o DIR` | Output directory (default: results/) |
| `--json` | JSON report output |
| `-q` | Quiet mode |
| `-v` | Verbose mode |
| `--no-color` | Disable colored output |

---

## Output Files

```
results/
  vulnerable.txt   — Confirmed CRITICAL/HIGH findings
  possible.txt     — MEDIUM/LOW findings
  logs.txt         — Full scan log
  results_*.json   — JSON report (with --json flag)
```

---

## Architecture

```
m7ssrf/
├── m7ssrf/
│   ├── cli.py              — Argument parsing, entry point
│   ├── engine.py           — Core orchestration engine
│   ├── scanner.py          — Payload injection & scanning
│   ├── requestor.py        — Async HTTP engine (httpx + urllib fallback)
│   └── analyzer.py         — Response analysis (50+ signatures)
├── discovery/
│   ├── parameter_discovery.py  — Auto SSRF param detection
│   └── url_parser.py           — URL manipulation utilities
├── modules/
│   ├── blind_ssrf.py       — OOB blind SSRF detection
│   ├── ssrf_chain.py       — Internal network pivoting
│   └── dns_monitor.py      — DNS callback monitoring
├── integrations/
│   ├── interactsh.py       — Interactsh client
│   └── dnslog.py           — DNSlog.cn client
├── payloads/
│   ├── basic.json
│   ├── bypass.json
│   ├── localhost.json
│   └── metadata.json
├── data/
│   └── payload_db.json     — Extensible payload database
├── utils/
│   ├── logger.py           — Colored terminal output
│   ├── output.py           — Results writer (TXT + JSON)
│   ├── validator.py        — Input validation
│   └── dependency_checker.py
├── install.sh              — Single-command installer
├── setup.py
└── requirements.txt
```

---

## Requirements

- Python 3.7+
- httpx (recommended): `pip install httpx`
- Falls back to urllib if httpx not installed

---

## Legal

This tool is for authorized security research and bug bounty hunting only.
Only test targets you have explicit permission to test.

**Made by Milkyway Intelligence | Author: Sharlix Martin**
