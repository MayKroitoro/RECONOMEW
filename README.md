# RECONOMEW v1.0
### Professional Reconnaissance Framework

> For authorised security testing only

RECONOMEW is a comprehensive bash-based reconnaissance framework that automates the information gathering phase of a penetration test. It performs passive and active reconnaissance and generates a clean HTML report.

<p align="center">
  <img src="assets/logo.png" width="300"/>
</p>

---

## Features

- **WHOIS & DNS** — full record enumeration, zone transfer attempts, dangling CNAME detection
- **TLS Analysis** — certificate details, protocol support (TLS 1.0–1.3)
- **Web Headers** — technology fingerprinting, WAF detection, robots.txt, sitemap
- **Subdomain Enumeration** — subfinder, dnsx brute-force, CT logs, smart permutations
- **HTTP Probing** — live host detection with httpx
- **Subdomain Takeover** — CNAME chain analysis, fingerprint matching
- **ASN / IP Ownership** — ASN lookup, geolocation
- **Email Security** — SPF, DMARC, DKIM validation
- **JS Discovery** — URL collection via gau/waybackurls, entropy-based secret scanner
- **Cloud Storage** — S3, GCS bucket enumeration
- **Leak Search** — GitHub, Grep.app, Pastebin, GitLab
- **Nmap** — TCP/UDP port scanning, service detection, vulnerability scripts
- **Dirsearch** — directory brute-force with WAF-aware rate limiting
- **WPScan** — WordPress vulnerability scanning
- **HTML Report** — interactive dashboard with severity filtering

---

## Project Structure

```
RECONOMEW/
├── reconomew.sh          # Main entry point
└── modules/
    ├── utils.sh          # Globals, helpers, dependency checks, setup
    ├── passive_recon.sh  # WHOIS, DNS, TLS, CT logs, subdomain enum
    ├── asn_email.sh      # ASN enumeration, email security (SPF/DKIM/DMARC)
    ├── web_recon.sh      # Web headers, sensitive paths, HTTPX, takeover
    ├── osint.sh          # SecurityTrails, Shodan, email harvest, social, JS, cloud, leaks, dorks
    ├── active_scan.sh    # Nmap, dirsearch, WPScan, nuclei, screenshots
    └── report.sh         # HTML report generator
```

---

## Requirements

- Bash 4.0+
- Kali Linux (recommended) or any Debian-based system

### Required tools
```
dig  curl  whois  openssl  python3
```

### Optional tools (install for full functionality)
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# apt tools
sudo apt install nmap whatweb wafw00f wpscan dirsearch theharvester jq
```

---

## Installation

```bash
git clone https://github.com/MayKroitoro/RECONOMEW.git
cd RECONOMEW
chmod +x reconomew.sh
```

---

## Usage

```bash
# Interactive mode
bash reconomew.sh

# Full scan
bash reconomew.sh -d example.com

# Quick mode (~2 min)
bash reconomew.sh -d example.com --quick

# Passive only (no nmap/dirsearch)
bash reconomew.sh -d example.com --no-active

# Specific modules
bash reconomew.sh -d example.com --only whois,dns,tls
bash reconomew.sh -d example.com --only nmap,dirsearch
bash reconomew.sh -d example.com --only js-discovery
```

---

## Flags

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain |
| `-i <ip>` | Target IP address |
| `--quick` | Quick mode — WHOIS, DNS, TLS, headers only |
| `--no-active` | Passive only — no nmap, dirsearch, wpscan |
| `--only <mods>` | Run specific modules (comma separated) |
| `--threads <n>` | Thread count (default: 50) |
| `--wordlist <f>` | Custom directory wordlist |
| `--output <dir>` | Custom output directory |
| `--version` | Show version |
| `--help` | Show help |

---

## Available Modules

```
whois, dns, tls, web-headers, ct, subdomains, httpx,
takeover, asn, email-security, shodan, securitytrails,
email-harvest, social, js-discovery, cloud, leaks,
dorks, nmap, dirsearch, wpscan
```

---

## Output

Results are saved to `~/recon_<domain>_<timestamp>/`:

```
recon_example.com_20260519_120000/
├── report.html       ← Interactive HTML report
└── raw_output.txt    ← Full scan log
```

View the report:
```bash
cd ~/recon_example.com_*/
python3 -m http.server 8080
# Open http://localhost:8080/report.html
```

---

## Disclaimer

This tool is intended for **authorised security testing and educational purposes only**. You are solely responsible for ensuring you have explicit written permission before scanning any target. Unauthorised use against systems you do not own or have permission to test is illegal. The author assumes no liability for any misuse or damage caused by this tool.

---

## License

GPL v3 License — Copyright (c) 2026 May Kroitoro

See [LICENSE](LICENSE) for full details.
