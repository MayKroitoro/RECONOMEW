#!/usr/bin/env bash
# RECONOMEW — report.sh
# Module: HTML Report Generator

generate_report() {
  section "Generating HTML Report"
  printf "  \033[2m      building report...\033[0m\r"

  local report_file="${OUT_DIR}/report.html"

  OUT_DIR="$(realpath "$OUT_DIR")" \
  DOMAIN="$DOMAIN" \
  IP="$IP" \
  TIMESTAMP="$TIMESTAMP" \
  LOG_FILE="$(realpath "$LOG_FILE" 2>/dev/null || echo "$LOG_FILE")" \
  ACTIVE="$ACTIVE" \
  QUICK="$QUICK" \
  timeout 300 python3 - << 'PYEOF'
import json, os, sys, re, subprocess, glob

OUT_DIR   = os.path.abspath(os.environ.get('OUT_DIR', ''))
import datetime as _dt
ts_fmt = _dt.datetime.now().strftime('%Y-%m-%d %H:%M')
DOMAIN    = os.environ.get('DOMAIN', '')
IP        = os.environ.get('IP', '')
TIMESTAMP = os.environ.get('TIMESTAMP', '')
LOG_FILE  = os.environ.get('LOG_FILE', '')
ACTIVE    = os.environ.get('ACTIVE', 'true')
QUICK     = os.environ.get('QUICK', 'false')
target    = DOMAIN or IP

def read(path, maxlines=None):
    try:
        with open(path) as fh:
            content = fh.read()
        if maxlines:
            content = '\n'.join(content.splitlines()[:maxlines])
        return content
    except:
        return ''

def readjson(path):
    try:
        return json.load(open(path))
    except:
        return None

def status_color(code):
    c = str(code)
    if c.startswith('2'):        return 'style="color:#16a34a"'
    if c in ('301','302','307'): return 'style="color:#2563eb"'
    if c == '403':               return 'style="color:#ca8a04"'
    if c.startswith('4'):        return 'style="color:#dc2626"'
    return ''

def sev_class(sev):
    return {'critical':'sev-critical','high':'sev-high','medium':'sev-medium','low':'sev-low'}.get(sev,'sev-info')

def kv(label, val, warn=False):
    c = 'style="color:#dc2626"' if warn else ''
    return '<tr><td style="color:var(--text-muted);width:210px">' + label + '</td><td ' + c + '>' + (str(val) or '-') + '</td></tr>'

def tbl(rows, heads=None):
    h = ''
    if heads:
        h = '<thead><tr>' + ''.join('<th>' + x + '</th>' for x in heads) + '</tr></thead>'
    return '<table>' + h + '<tbody>' + ''.join(rows) + '</tbody></table>'

def pre(x):
    if not x or not x.strip():
        return '<p style="color:var(--text-muted);font-style:italic">Not run or no results.</p>'
    return '<pre>' + x.replace('<','&lt;').replace('>','&gt;') + '</pre>'

def fhtml(f):
    sc2 = sev_class(f['sev'])
    return ('<div class="finding"><span class="sev ' + sc2 + '">' + f['sev'].upper() + '</span>'
            '<div class="finding-main">'
            '<div class="finding-desc">' + f['desc'] + '</div>'
            '<div class="finding-id">' + f['id'] + '</div>'
            '<div class="finding-url">' + f['url'] + '</div>'
            '</div></div>')

raw_log_full = read(LOG_FILE)
raw_log = raw_log_full[-40000:] if len(raw_log_full) > 40000 else raw_log_full

def read_lines(path, limit=50):
    try:
        with open(path) as fh:
            lines = [l.rstrip() for l in fh]
        return lines if limit == 0 else lines[:limit]
    except:
        return []

# ── Subdomains ──
def resolve_sub(host):
    try:
        r = subprocess.run(['dig','+short','A',host,'@1.1.1.1'],
                           capture_output=True, text=True, timeout=3)
        ips = [l.strip() for l in r.stdout.splitlines()
               if l.strip() and not l.startswith(';') and not 'error' in l.lower()]
        return ips[0] if ips else ''
    except:
        return ''

def http_status(host):
    try:
        r = subprocess.run(['curl','-sIL','--max-time','4','-o','/dev/null',
                            '-w','%{http_code}','https://'+host],
                           capture_output=True, text=True, timeout=6)
        code = r.stdout.strip()
        return code if code.isdigit() else ''
    except:
        return ''

# Build IP and status maps from httpx results (format: URL [status] [1.2.3.4] [title])
httpx_ip_map     = {}
httpx_status_map = {}
_httpx_file = os.path.join(OUT_DIR, 'httpx_results.txt')
if os.path.exists(_httpx_file):
    for _line in open(_httpx_file, errors='ignore').read().splitlines():
        _parts = _line.strip().split()
        if not _parts: continue
        _m = re.match(r'https?://([^/:]+)', _parts[0])
        if not _m: continue
        _host = _m.group(1)
        for _p in _parts[1:]:
            if re.match(r'^\[\d{3}\]$', _p): httpx_status_map[_host] = _p.strip('[]')
            elif re.match(r'^\[\d+\.\d+\.\d+\.\d+\]$', _p): httpx_ip_map[_host] = _p.strip('[]')

subdomains = []
seen = set()

for fname, src in [
    ('subfinder.txt',                        'subfinder'),
    ('ct_subdomains.txt',                    'crt.sh'),
    ('dnsx_brute.txt',                       'dnsx'),
    ('subdomains_permutations_resolved.txt', 'permutation'),
    ('securitytrails/subdomains.txt',        'securitytrails'),
    ('subdomains_found.txt',                 'other'),
]:
    fp = os.path.join(OUT_DIR, fname)
    if os.path.exists(fp):
        for line in open(fp).read().splitlines():
            line = line.strip()
            if line and line not in seen and '.' in line:
                seen.add(line)
                subdomains.append({'name': line, 'source': src, 'ip': '', 'status': ''})

# ffuf subdomain discovery removed - DNS brute-force via dnsx is used instead

# ── Ports ──
ports = []
nmap_fp = os.path.join(OUT_DIR, 'nmap/top1000.txt')
if os.path.exists(nmap_fp):
    for line in open(nmap_fp).read().splitlines():
        m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
        if m:
            ports.append({'port': m.group(1), 'service': m.group(2), 'version': m.group(3).strip()})
# Also add from common ports scan
nmap_fp2 = os.path.join(OUT_DIR, 'nmap/common.txt')
if os.path.exists(nmap_fp2):
    existing = {p['port'] for p in ports}
    for line in open(nmap_fp2).read().splitlines():
        m = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
        if m and m.group(1) not in existing:
            ports.append({'port': m.group(1), 'service': m.group(2), 'version': m.group(3).strip()})

# ── Security headers ──
SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-XSS-Protection',
]
web_hdr_content = read(os.path.join(OUT_DIR, 'web_headers.txt'))
headers = []
for h in SECURITY_HEADERS:
    val = ''
    for line in web_hdr_content.splitlines():
        ll = line.strip().lower()
        if ll.startswith(h.lower() + ':'):
            val = line.split(':', 1)[-1].strip()
            break
    headers.append({'name': h, 'value': val or 'Missing', 'missing': not bool(val)})

# ── TLS issues ──
tls_issues = []
tls_raw = read(os.path.join(OUT_DIR, 'tls.txt'))
for proto, label in [('TLS 1.0', 'TLS 1.0'), ('TLS 1.1', 'TLS 1.1')]:
    if proto + ': supported' in tls_raw:
        tls_issues.append(label)

# ── Nuclei findings ──
findings = []
nuclei_lines = []
for nf_name in ['all_findings.txt', 'tech_misconfig.txt', 'cves.txt', 'default_logins.txt']:
    nf = os.path.join(OUT_DIR, 'nuclei', nf_name)
    if os.path.exists(nf):
        nuclei_lines.extend(open(nf).read().splitlines())
nuclei_lines = list(dict.fromkeys(l for l in nuclei_lines if l.strip()))

for line in nuclei_lines:
    if not line.strip():
        continue
    sev = 'info'
    for sv in ['critical', 'high', 'medium', 'low']:
        if '[' + sv + ']' in line.lower():
            sev = sv
            break
    tags  = re.findall(r'\[([^\]]+)\]', line)
    fid   = tags[0] if tags else ''
    furl  = (re.findall(r'https?://[^\s\[]+', line) or [''])[0]
    fdesc = tags[-1] if len(tags) > 1 else line.strip()
    findings.append({'sev': sev, 'id': fid, 'url': furl, 'desc': fdesc})

# ── Auto-generated findings from passive data ──
for h in headers:
    if h['missing']:
        sev = 'medium' if h['name'] in ('Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options') else 'low'
        findings.append({'sev': sev, 'id': 'missing-header', 'url': 'https://' + target, 'desc': 'Missing security header: ' + h['name']})

has_spf   = any('v=spf1' in l.lower() for l in raw_log.splitlines())
has_dmarc = any('v=dmarc1' in l.lower() for l in raw_log.splitlines())
dmarc_val = next((l.strip() for l in raw_log.splitlines() if 'v=dmarc1' in l.lower()), '')

if not has_spf:
    findings.append({'sev': 'medium', 'id': 'missing-spf', 'url': target, 'desc': 'No SPF record - email spoofing possible'})
elif '~all' in raw_log:
    findings.append({'sev': 'low', 'id': 'weak-spf', 'url': target, 'desc': 'SPF uses ~all (softfail) - consider upgrading to -all'})

if not has_dmarc:
    findings.append({'sev': 'medium', 'id': 'missing-dmarc', 'url': target, 'desc': 'No DMARC record - no email spoofing protection'})
elif 'p=none' in dmarc_val.lower():
    findings.append({'sev': 'low', 'id': 'weak-dmarc', 'url': target, 'desc': 'DMARC policy is p=none (monitor only, no enforcement)'})

dnssec_val = next((l.split(':',1)[-1].strip().lower() for l in raw_log.splitlines() if 'dnssec' in l.lower() and ':' in l), '')
if 'unsigned' in dnssec_val or not dnssec_val:
    findings.append({'sev': 'low', 'id': 'dnssec-unsigned', 'url': target, 'desc': 'DNSSEC not enabled - DNS hijacking risk'})

for proto_label in tls_issues:
    findings.append({'sev': 'medium', 'id': 'legacy-tls', 'url': target, 'desc': proto_label + ' supported - deprecated, should be disabled'})

wp_detected = any('wp-' in l.lower() or 'wordpress' in l.lower() for l in web_hdr_content.splitlines())
if wp_detected:
    findings.append({'sev': 'info', 'id': 'wordpress-detected', 'url': 'https://' + target + '/wp-login.php', 'desc': 'WordPress CMS detected - check /wp-admin, /xmlrpc.php, /wp-json/wp/v2/users'})

# PHP version exposed
php_exposed = re.search(r'PHP/([0-9.]+)', web_hdr_content, re.IGNORECASE)
if php_exposed:
    findings.append({'sev': 'low', 'id': 'php-version-exposed', 'url': target, 'desc': 'PHP version exposed in headers: ' + php_exposed.group(0) + ' - remove X-Powered-By header'})

# Wildcard DNS
if os.path.exists(os.path.join(OUT_DIR, 'wildcard.txt')):
    wc_ip = read(os.path.join(OUT_DIR, 'wildcard.txt')).strip()
    findings.append({'sev': 'info', 'id': 'wildcard-dns', 'url': target, 'desc': 'Wildcard DNS detected (* -> ' + wc_ip + ') - subdomain brute-force may have false positives'})

# Leak findings
emails_found = read(os.path.join(OUT_DIR, 'emails/emails.txt'))
if emails_found:
    email_list = [e for e in emails_found.splitlines() if e.strip()]
    if email_list:
        findings.append({'sev': 'info', 'id': 'emails-harvested', 'url': target, 'desc': str(len(email_list)) + ' email addresses harvested - potential phishing/social engineering targets'})

# CVE findings
cve_raw = read(os.path.join(OUT_DIR, 'cve/cve_results.txt'))
if cve_raw:
    for line in cve_raw.splitlines():
        m = re.match(r'(CVE-\d{4}-\d+)\s*\|\s*CVSS:([\d.]*)\s*\|\s*(.*)', line)
        if m:
            cve_id, score_str, desc = m.group(1), m.group(2), m.group(3)
            try:
                score = float(score_str) if score_str else 0
            except:
                score = 0
            sev = 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'
            findings.append({'sev': sev, 'id': cve_id, 'url': target, 'desc': desc[:100]})

# Deduplicate findings by id+desc
seen_f = set()
deduped = []
for f in findings:
    key = f['id'] + f['desc'][:40]
    if key not in seen_f:
        seen_f.add(key)
        deduped.append(f)
findings = deduped

# Sort by severity
sev_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
findings.sort(key=lambda x: sev_order.get(x['sev'], 5))

# Counts
sc = {
    'subdomains': len(subdomains),
    'ports': len(ports),
    'critical': sum(1 for f in findings if f['sev']=='critical'),
    'high': sum(1 for f in findings if f['sev']=='high'),
    'medium': sum(1 for f in findings if f['sev']=='medium'),
    'low': sum(1 for f in findings if f['sev']=='low'),
}

# ── WHOIS ──
whois_raw = read(os.path.join(OUT_DIR, 'whois.txt'))
def extract_whois(field):
    for line in whois_raw.splitlines():
        if field.lower() in line.lower() and ':' in line:
            return line.split(':',1)[-1].strip()
    return ''

whois = {
    'domain':    extract_whois('Domain Name'),
    'registrar': extract_whois('Registrar'),
    'org':       extract_whois('Registrant Organization'),
    'created':   extract_whois('Creation Date'),
    'updated':   extract_whois('Updated Date'),
    'expires':   extract_whois('Expir'),
    'ns':        extract_whois('Name Server'),
    'dnssec':    extract_whois('DNSSEC'),
}

# ── DNS ──
def extract_dns(rtype):
    lines = []
    in_block = False
    for line in raw_log.splitlines():
        if f'[{rtype}]' in line:
            in_block = True
            continue
        if in_block:
            if line.strip().startswith('[') or line.strip().startswith('╔') or line.strip().startswith('###'):
                break
            v = line.strip().lstrip('│').strip()
            if v and 'communications error' not in v and 'timed out' not in v:
                lines.append(v)
    return ', '.join(lines[:5])

dns = {t: extract_dns(t) for t in ['A','AAAA','MX','TXT','NS','SOA']}

# ── TLS ──
tls_cert    = read(os.path.join(OUT_DIR, 'cert.txt'))
tls_protos  = read(os.path.join(OUT_DIR, 'tls.txt'))
def tls_field(field):
    for l in tls_cert.splitlines():
        if field.lower() in l.lower():
            return l.split('=',1)[-1].strip() if '=' in l else l.strip()
    return ''

# ── Directory results ──
dir_rows = []

# Read dirsearch results (primary tool)
ds_fp = os.path.join(OUT_DIR, 'dirsearch/dirsearch.txt')
if os.path.exists(ds_fp):
    for l in open(ds_fp).read().splitlines():
        l = l.strip()
        if not l or l.startswith('#'): continue
        parts = l.split()
        if len(parts) >= 2 and parts[0].isdigit() and len(parts[0]) == 3:
            url = parts[-1] if parts[-1].startswith('http') else ''
            if url:
                dir_rows.append({'status': parts[0], 'size': parts[1] if len(parts) > 2 else '', 'url': url, 'tool': 'dirsearch'})

# Also read feroxbuster if present
ferox_fp = os.path.join(OUT_DIR, 'feroxbuster/ferox.txt')
if os.path.exists(ferox_fp):
    for l in open(ferox_fp).read().splitlines():
        m = re.match(r'^(\d{3})\s+\w+\s+\S+\s+\S+\s+\S+\s+(https?://\S+)', l.strip())
        if not m:
            m = re.match(r'^(\d{3})\s+\S+\s+(https?://\S+)', l.strip())
        if m:
            dir_rows.append({'status': m.group(1), 'size': '', 'url': m.group(2), 'tool': 'feroxbuster'})



if dir_rows:
    dir_table_rows = []
    for r in dir_rows[:300]:
        sc2 = status_color(r['status'])
        dir_table_rows.append(
            '<tr><td ' + sc2 + '>' + r['status'] + '</td>'
            '<td>' + r.get('size','') + '</td>'
            '<td style="font-family:var(--mono);font-size:12px"><a href="' + r['url'] + '" target="_blank" style="color:inherit">' + r['url'] + '</a></td>'
            '<td style="color:var(--text-muted)">' + r['tool'] + '</td></tr>'
        )
    dir_results_html = tbl(dir_table_rows, ['Status','Size','URL','Tool'])
else:
    dir_results_html = '<p style="color:var(--text-muted);font-style:italic">Not run or blocked by WAF.</p>'

# ffuf table
ffuf_rows = []
ffuf_d = readjson(os.path.join(OUT_DIR, 'ffuf/dirs.json'))
if ffuf_d:
    for r in ffuf_d.get('results', []):
        ffuf_rows.append({'status': str(r.get('status','')), 'size': str(r.get('length','')), 'url': str(r.get('url',''))})

if ffuf_rows:
    ffuf_table_rows = []
    for r in ffuf_rows[:300]:
        sc2 = status_color(r['status'])
        ffuf_table_rows.append(
            '<tr><td ' + sc2 + '>' + r['status'] + '</td>'
            '<td>' + r.get('size','') + '</td>'
            '<td style="font-family:var(--mono);font-size:12px"><a href="' + r['url'] + '" target="_blank" style="color:inherit">' + r['url'] + '</a></td></tr>'
        )
    ffuf_results_html = tbl(ffuf_table_rows, ['Status','Size','URL'])
else:
    ffuf_results_html = '<p style="color:var(--text-muted);font-style:italic">Not run or no results.</p>'

# ── Shodan ──
shodan = None
sd = readjson(os.path.join(OUT_DIR, 'shodan.json'))
if sd:
    shodan = {
        'org': sd.get('org',''), 'isp': sd.get('isp',''),
        'country': sd.get('country_name',''),
        'ports': ', '.join(map(str, sd.get('ports',[]))),
        'hostnames': ', '.join(sd.get('hostnames',[]))
    }

# ── HTML build ──
sub_rows = []
for s in subdomains:
    status  = s.get('status','')
    sc2 = status_color(status)
    sub_rows.append(
        '<tr><td style="font-family:var(--mono)">'
        '<a href="https://' + s['name'] + '" target="_blank" style="color:inherit">' + s['name'] + '</a>'
        '</td><td style="font-family:var(--mono)">' + s.get('ip','') + '</td>'
        '<td ' + sc2 + '>' + (status or '-') + '</td>'
        '<td style="color:var(--text-muted)">' + s['source'] + '</td></tr>'
    )
sub_html = tbl(sub_rows, ['Subdomain','IP','HTTP Status','Source']) if sub_rows else '<p style="color:var(--text-muted);font-style:italic">None discovered.</p>'

port_rows = []
for p in ports:
    port_rows.append(
        '<tr><td style="font-family:var(--mono)">' + p['port'] + '</td>'
        '<td><span class="tag-open">open</span></td>'
        '<td>' + p['service'] + '</td>'
        '<td style="color:var(--text-muted)">' + p['version'] + '</td></tr>'
    )
port_html = tbl(port_rows, ['Port','State','Service','Version']) if port_rows else '<p style="color:var(--text-muted);font-style:italic">No open ports found.</p>'

hdr_rows = []
for h in headers:
    cls = 'style="color:#dc2626"' if h['missing'] else 'style="color:#16a34a"'
    val = '[X] Missing' if h['missing'] else '[OK] ' + h['value'][:80]
    hdr_rows.append('<tr><td style="font-family:var(--mono)">' + h['name'] + '</td><td ' + cls + '>' + val + '</td></tr>')
hdr_html = tbl(hdr_rows, ['Header','Status'])

shodan_html = (tbl([kv('Org',shodan['org']),kv('ISP',shodan['isp']),kv('Country',shodan['country']),kv('Ports',shodan['ports']),kv('Hostnames',shodan['hostnames'])]) if shodan
               else '<p style="color:var(--text-muted);font-style:italic">Not run (no Shodan API key).</p>')

dns_html = ''.join(
    '<div class="dns-row"><span class="dns-type">' + t + '</span><span class="dns-val">' + dns[t] + '</span></div>'
    for t in ['A','AAAA','MX','TXT','NS','SOA'] if dns.get(t)
) or '<p style="padding:1rem;color:var(--text-muted)">No DNS data.</p>'

findings_html = ''.join(fhtml(f) for f in findings) or '<p style="padding:1rem;color:var(--text-muted)">No findings.</p>'

scan_mode = 'Quick (~2 min)' if QUICK == 'true' else ('Full scan' if ACTIVE not in ('false','0','') else 'Passive only')

CSS = '''
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f0f2f5;--surface:#fff;--surface-alt:#f8f9fb;--border:rgba(0,0,0,.08);--border-strong:rgba(0,0,0,.13);
  --text:#1a1d23;--text-muted:#6b7280;--text-faint:#9ca3af;
  --accent:#4f46e5;--accent-soft:rgba(79,70,229,.08);
  --sidebar:#1e2235;--sidebar-text:#a8b0c8;--sidebar-active:#fff;
  --mono:'Menlo','Consolas','Monaco',monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --radius:8px;--radius-lg:12px;
  --crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#2563eb;--info:#6b7280;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;display:flex;min-height:100vh}

/* Sidebar */
.sidebar{width:220px;flex-shrink:0;background:var(--sidebar);min-height:100vh;padding:1.5rem 0;display:flex;flex-direction:column}
.sidebar-brand{padding:0 1.25rem 1.5rem;border-bottom:1px solid rgba(255,255,255,.07);margin-bottom:1rem}
.sidebar-brand-name{font-size:13px;font-weight:700;color:#fff;letter-spacing:.08em;text-transform:uppercase}
.sidebar-brand-sub{font-size:10px;color:var(--sidebar-text);margin-top:2px;font-family:var(--mono)}
.sidebar-section{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:rgba(168,176,200,.4);padding:.5rem 1.25rem .25rem}
.sidebar-item{display:flex;align-items:center;gap:8px;padding:.55rem 1.25rem;font-size:13px;color:var(--sidebar-text);cursor:pointer;border-left:3px solid transparent;transition:all .15s;text-decoration:none}
.sidebar-item:hover{color:#fff;background:rgba(255,255,255,.05)}
.sidebar-item.active{color:#fff;background:rgba(255,255,255,.08);border-left-color:var(--accent)}
.sidebar-item .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}

/* Main content */
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:.875rem 1.75rem;display:flex;align-items:center;justify-content:space-between}
.topbar-title{font-size:18px;font-weight:600;color:var(--text)}
.topbar-meta{font-size:12px;color:var(--text-muted);font-family:var(--mono)}
.content{padding:1.5rem 1.75rem;flex:1}

/* Severity pills (like the screenshot) */
.sev-pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1.25rem;align-items:center}
.sev-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 14px;border-radius:999px;font-size:13px;font-weight:500;border:1.5px solid;cursor:pointer;transition:opacity .15s;user-select:none}
.sev-pill:hover{opacity:.8}
.sev-pill.active{opacity:1}.sev-pill.inactive{opacity:.45}
.sev-pill .pill-count{font-weight:700;font-size:13px}
.pill-crit{border-color:#dc2626;color:#dc2626;background:rgba(220,38,38,.06)}
.pill-high{border-color:#ea580c;color:#ea580c;background:rgba(234,88,12,.06)}
.pill-med{border-color:#d97706;color:#d97706;background:rgba(217,119,6,.06)}
.pill-low{border-color:#2563eb;color:#2563eb;background:rgba(37,99,235,.06)}
.pill-info{border-color:#6b7280;color:#6b7280;background:rgba(107,114,128,.06)}
.pill-total{border-color:#1a1d23;color:#1a1d23;background:rgba(26,29,35,.06);font-weight:700}

/* Search + filter bar */
.filter-bar{display:flex;gap:10px;align-items:center;margin-bottom:1rem;flex-wrap:wrap}
.search-box{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;flex:1;min-width:200px}
.search-box input{border:none;outline:none;font-size:13px;color:var(--text);background:transparent;width:100%;font-family:var(--sans)}
.search-box input::placeholder{color:var(--text-faint)}
.filter-select{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:6px 10px;font-size:13px;color:var(--text);font-family:var(--sans);cursor:pointer;outline:none}
.filter-count{font-size:13px;color:var(--text-muted);white-space:nowrap}

/* Score cards */
.score-row{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:1.5rem}
.score{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.score-val{font-size:26px;font-weight:700;line-height:1;font-family:var(--mono)}
.score-label{font-size:10px;color:var(--text-muted);margin-top:5px;text-transform:uppercase;letter-spacing:.07em;font-weight:600}
.s-crit .score-val{color:var(--crit)}.s-high .score-val{color:var(--high)}.s-med .score-val{color:var(--med)}.s-low .score-val{color:var(--low)}

/* Tabs */
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:1.5rem;overflow-x:auto}
.tab{padding:8px 18px;font-size:13px;color:var(--text-muted);cursor:pointer;background:none;border:none;border-bottom:2px solid transparent;white-space:nowrap;font-family:var(--sans);transition:color .15s;font-weight:500}
.tab:hover{color:var(--text)}.tab.on{color:var(--accent);border-bottom-color:var(--accent)}
.panel{display:none}.panel.on{display:block}

/* Sections */
.section{margin-bottom:1.75rem}
.st{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text-muted);margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.04)}

/* Table */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);padding:8px 14px;border-bottom:1px solid var(--border-strong);background:var(--surface-alt)}
td{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top;font-size:13px}
tr:last-child td{border-bottom:none}tr:hover td{background:var(--surface-alt)}

/* DNS rows */
.dns-row{display:flex;gap:10px;align-items:baseline;padding:8px 14px;border-bottom:1px solid var(--border);font-size:13px}
.dns-row:last-child{border-bottom:none}
.dns-type{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--accent);min-width:48px;background:var(--accent-soft);padding:2px 6px;border-radius:4px;text-align:center}
.dns-val{font-family:var(--mono);color:var(--text);font-size:12px}

/* Findings */
.finding{display:flex;gap:12px;align-items:flex-start;padding:11px 14px;border-bottom:1px solid var(--border);transition:background .1s}
.finding:last-child{border-bottom:none}.finding:hover{background:var(--surface-alt)}
.sev{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;padding:3px 9px;border-radius:999px;white-space:nowrap;font-family:var(--mono);flex-shrink:0;margin-top:1px;border:1.5px solid}
.sev-critical{background:rgba(220,38,38,.08);color:#b91c1c;border-color:#dc2626}
.sev-high{background:rgba(234,88,12,.08);color:#c2410c;border-color:#ea580c}
.sev-medium{background:rgba(217,119,6,.08);color:#b45309;border-color:#d97706}
.sev-low{background:rgba(37,99,235,.08);color:#1d4ed8;border-color:#2563eb}
.sev-info{background:rgba(107,114,128,.08);color:var(--text-muted);border-color:#9ca3af}
.finding-main{flex:1;min-width:0}
.finding-desc{color:var(--text);font-weight:500;font-size:13px}
.finding-id{font-size:11px;font-family:var(--mono);color:var(--text-muted);margin-top:3px}
.finding-url{font-size:11px;font-family:var(--mono);color:var(--text-faint);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag-open{font-size:11px;font-family:var(--mono);background:rgba(37,99,235,.08);color:#1d4ed8;border:1px solid rgba(37,99,235,.2);border-radius:4px;padding:1px 6px}

/* Pre */
pre{background:var(--surface-alt);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;font-family:var(--mono);font-size:12px;line-height:1.75;color:var(--text-muted);overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:480px;overflow-y:auto}
a{color:var(--accent)}
.footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:12px;color:var(--text-faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
@media print{.sidebar,.tabs,.tab{display:none}.panel{display:block!important}.main{width:100%}pre{max-height:none}body{background:white;color:black}}
'''

def _asn_table(asn_raw):
    if not asn_raw or not asn_raw.strip():
        return pre('Not run.')
    rows = []
    for blk in asn_raw.split('==='):
        if not blk.strip() or '|' not in blk:
            continue
        lines = blk.splitlines()
        ip = lines[0].strip() if lines else ''
        data_line = next((l for l in lines if '|' in l and not l.strip().startswith('AS ')), '')
        parts = [p.strip() for p in data_line.split('|')] if data_line else []
        asn    = parts[0] if len(parts) > 0 else ''
        prefix = parts[2] if len(parts) > 2 else ''
        cc     = parts[3] if len(parts) > 3 else ''
        org      = next((l.split('Org:')[1].strip()      for l in lines if 'Org:'      in l), '')
        city     = next((l.split('City:')[1].strip()     for l in lines if 'City:'     in l), '')
        hostname = next((l.split('Hostname:')[1].strip() for l in lines if 'Hostname:' in l), '')
        if asn or ip:
            rows.append(
                '<tr>'
                + '<td style="font-family:var(--mono)">' + (ip or '-') + '</td>'
                + '<td style="font-family:var(--mono)">' + (asn or '-') + '</td>'
                + '<td style="font-family:var(--mono);font-size:11px">' + (prefix or '-') + '</td>'
                + '<td>' + (cc or '-') + '</td>'
                + '<td>' + (org or '-') + '</td>'
                + '<td>' + (city or '-') + '</td>'
                + '<td style="font-size:11px">' + (hostname or '-') + '</td>'
                + '</tr>'
            )
    if not rows:
        return pre(asn_raw)
    return '<div class="card">' + tbl(rows, ['IP','ASN','BGP Prefix','CC','Org','City','Hostname']) + '</div>'


html = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>RECONOMEW - ' + target + '</title>'
    '<style>' + CSS + '</style></head><body>'

    # ── Sidebar ──
    '<div class="sidebar">'
    '<div class="sidebar-brand">'
    '<div class="sidebar-brand-name">RECONOMEW</div>'
    '<div class="sidebar-brand-sub">v1.0 &bull; Recon Report</div>'
    '<div class="sidebar-brand-sub" style="margin-top:4px;opacity:.6">' + ts_fmt + '</div>'
    '</div>'
    '<div class="sidebar-section">Navigation</div>'
    '<a class="sidebar-item active" onclick="sw(\'vulns\',this);setActive(this)"><span class="dot" style="background:#dc2626"></span>Threat List</a>'
    '<a class="sidebar-item" onclick="sw(\'dns\',this);setActive(this)"><span class="dot" style="background:#4f46e5"></span>DNS &amp; WHOIS</a>'
    '<a class="sidebar-item" onclick="sw(\'subs\',this);setActive(this)"><span class="dot" style="background:#0891b2"></span>Subdomains</a>'
    '<a class="sidebar-item" onclick="sw(\'ports\',this);setActive(this)"><span class="dot" style="background:#059669"></span>Ports &amp; Services</a>'
    '<a class="sidebar-item" onclick="sw(\'web\',this);setActive(this)"><span class="dot" style="background:#d97706"></span>Web Recon</a>'
    '<a class="sidebar-item" onclick="sw(\'leaks\',this);setActive(this)"><span class="dot" style="background:#db2777"></span>Leaks &amp; Emails</a>'
    '<a class="sidebar-item" onclick="sw(\'raw\',this);setActive(this)"><span class="dot" style="background:#6b7280"></span>Raw Output</a>'
    '</div>'

    # ── Main content ──
    '<div class="main">'
    '<div class="topbar">'
    '<div>'
    '<div class="topbar-title">' + target + '</div>'
    '<div class="topbar-meta">IP: ' + (IP or '-') + ' &bull; ' + TIMESTAMP[:4] + '-' + TIMESTAMP[4:6] + '-' + TIMESTAMP[6:8] + ' ' + TIMESTAMP[9:11] + ':' + TIMESTAMP[11:13] + ' &bull; ' + scan_mode + '</div>'
    '</div>'
    '<button onclick="window.print()" style="font-size:12px;padding:6px 14px;background:var(--surface);border:1px solid var(--border);color:var(--text-muted);cursor:pointer;border-radius:var(--radius);font-family:var(--sans)">Export PDF</button>'
    '</div>'
    '<div class="content">'

    '<div class="score-row">'
    '<div class="score"><div class="score-val">' + str(sc['subdomains']) + '</div><div class="score-label">Subdomains</div></div>'
    '<div class="score"><div class="score-val">' + str(sc['ports']) + '</div><div class="score-label">Open Ports</div></div>'
    '<div class="score s-crit"><div class="score-val">' + str(sc['critical']) + '</div><div class="score-label">Critical</div></div>'
    '<div class="score s-high"><div class="score-val">' + str(sc['high']) + '</div><div class="score-label">High</div></div>'
    '<div class="score s-med"><div class="score-val">' + str(sc['medium']) + '</div><div class="score-label">Medium</div></div>'
    '<div class="score s-low"><div class="score-val">' + str(sc['low']) + '</div><div class="score-label">Low</div></div>'
    '</div>'

    # DNS & WHOIS tab
    '<div id="p-dns" class="panel on">'

    # ── WHOIS (full fields) ──
    '<div class="section"><div class="st">WHOIS</div><div class="card">'
    + tbl([
        kv('Domain',          whois['domain']),
        kv('Registrar',       whois['registrar']),
        kv('Registrant Name', extract_whois('Registrant Name')),
        kv('Registrant Org',  whois['org']),
        kv('Registrant Email',extract_whois('Registrant Email')),
        kv('Admin Email',     extract_whois('Admin Email')),
        kv('Tech Email',      extract_whois('Tech Email')),
        kv('Country',         extract_whois('Registrant Country')),
        kv('Created',         whois['created']),
        kv('Updated',         whois['updated']),
        kv('Expires',         whois['expires']),
        kv('Name Servers',    whois['ns']),
        kv('Domain Status',   extract_whois('Domain Status')),
        kv('DNSSEC',          whois['dnssec']),
    ])
    + '</div></div>'

    # ── DNS Records ──
    '<div class="section"><div class="st">DNS Records</div><div class="card" style="padding:0">' + dns_html + '</div></div>'

    # ── ASN ──
    '<div class="section"><div class="st">ASN &amp; IP Ownership</div>' + _asn_table(read(os.path.join(OUT_DIR, 'asn.txt'))) + '</div>'

    # ── SecurityTrails ──
    '<div class="section"><div class="st">Historical DNS (SecurityTrails)</div>' + pre(read(os.path.join(OUT_DIR, 'securitytrails_history.txt')) or 'Not run (no API key).') + '</div>'

    # ── TLS Certificate (full fields) ──
    '<div class="section"><div class="st">TLS Certificate</div><div class="card">'
    + tbl([
        kv('Subject',     tls_field('subject')),
        kv('Issuer',      tls_field('issuer')),
        kv('Valid From',  tls_field('notBefore')),
        kv('Valid Until', tls_field('notAfter')),
        kv('Alt Names',   tls_field('DNS')),
    ])
    + '</div></div>'
    '<div class="section"><div class="st">Protocol Support</div>' + pre(tls_protos or 'Not retrieved.') + '</div>'

    # ── Certificate Transparency ──
    '<div class="section"><div class="st">Certificate Transparency (crt.sh)</div>'
    + pre('\n'.join(sorted(set(open(os.path.join(OUT_DIR,'ct_subdomains.txt')).read().splitlines()))) if os.path.exists(os.path.join(OUT_DIR,'ct_subdomains.txt')) else 'No results.')
    + '</div>'

    # ── Email Security ──
    '<div class="section"><div class="st">Email Security (SPF / DKIM / DMARC)</div><div class="card">'
    + tbl([
        kv('SPF Record',   dns.get('TXT','') or 'Not found', not has_spf),
        kv('SPF Policy',   'Strict (-all)' if '-all' in dns.get('TXT','') else ('Softfail (~all)' if '~all' in dns.get('TXT','') else 'Unknown'), '~all' in dns.get('TXT','')),
        kv('DMARC',        dmarc_val or 'Missing', not has_dmarc),
        kv('DMARC Policy', ('None (monitor only)' if 'p=none' in (dmarc_val or '') else ('Quarantine' if 'p=quarantine' in (dmarc_val or '') else ('Reject' if 'p=reject' in (dmarc_val or '') else 'Unknown'))), 'p=none' in (dmarc_val or '')),
        kv('DKIM',         'Selectors checked - see raw output'),
    ])
    + '</div></div>'
    '</div>'

    # ── Subdomains tab ──
    '<div id="p-subs" class="panel">'
    '<div class="section"><div class="st">Live Hosts - httpx (' + str(len([l for l in (read(os.path.join(OUT_DIR,'httpx_results.txt')) or '').splitlines() if l.strip()])) + ')</div>'
    + pre(read(os.path.join(OUT_DIR,'httpx_results.txt')) or 'httpx not run or no live hosts found.')
    + '</div>'
    '<div class="section"><div class="st">All Discovered Subdomains (' + str(len(subdomains)) + ')</div>'
    '<div class="card">' + sub_html + '</div></div>'
    '<div class="section"><div class="st">Subdomain Takeover</div>'
    + pre(read(os.path.join(OUT_DIR,'takeover/takeover.txt')) or 'No takeover vulnerabilities found.')
    + '</div>'
    '</div>'

    # ── Ports tab ──
    '<div id="p-ports" class="panel">'
    '<div class="section"><div class="st">Open TCP Ports</div><div class="card">' + port_html + '</div></div>'
    '<div class="section"><div class="st">UDP Ports</div>'
    + pre('\n'.join(l for l in (read(os.path.join(OUT_DIR,'nmap/udp.txt')) or '').splitlines() if 'open' in l) or 'No open UDP ports found.')
    + '</div>'
    '<div class="section"><div class="st">Nmap Vuln Scripts</div>' + pre(read(os.path.join(OUT_DIR,'nmap/vulns.txt'), 80) or 'No vuln script findings.') + '</div>'
    '<div class="section"><div class="st">Shodan Intelligence</div><div class="card">' + shodan_html + '</div></div>'
    '<div class="section"><div class="st">WPScan Results</div>' + pre(re.sub(r'\033\[[0-9;]*m|\x1b\[[0-9;]*m','',read(os.path.join(OUT_DIR,'wpscan.txt')) or 'Not run (WordPress not detected or wpscan not installed).')) + '</div>'
    '</div>'

    # ── Web Recon tab ──
    '<div id="p-web" class="panel">'
    '<div class="section"><div class="st">HTTP Headers</div><div class="card">' + hdr_html + '</div></div>'
    '<div class="section"><div class="st">robots.txt</div>' + pre(read(os.path.join(OUT_DIR,'robots.txt')) or 'Not found or blocked.') + '</div>'
    '<div class="section"><div class="st">sitemap.xml</div>'
    + pre(read(os.path.join(OUT_DIR,'sitemap.txt')) or (
        '\n'.join(l for l in (read(os.path.join(OUT_DIR,'web_headers.txt')) or '').splitlines() if 'sitemap' in l.lower())
        or 'Not found.'))
    + '</div>'
    '<div class="section"><div class="st">Sensitive Paths</div>'
    + pre('\n'.join(l for l in raw_log.splitlines() if re.search(r'\[(200|401|500)\].*https?://',l) and 'catch-all' not in l) or 'None found.')
    + '</div>'
    '<div class="section"><div class="st">Technology Fingerprint (WhatWeb)</div>' + pre(re.sub(r'\033\[[0-9;]*m|\x1b\[[0-9;]*m','',read(os.path.join(OUT_DIR,'whatweb.txt')) or 'Not run.')) + '</div>'
    '<div class="section"><div class="st">WAF Detection (wafw00f)</div>' + pre(re.sub(r'\033\[[0-9;]*m|\x1b\[[0-9;]*m','',read(os.path.join(OUT_DIR,'wafw00f.txt')) or 'Not run.')) + '</div>'
    '<div class="section"><div class="st">Parameter Discovery (arjun)</div>'
    + pre('\n'.join(
        open(f).read() for f in sorted(glob.glob(os.path.join(OUT_DIR,'params','*.json')))
        if os.path.exists(f)
    ) or 'No parameters discovered.')
    + '</div>'
    '<div class="section"><div class="st">JavaScript &amp; URL Discovery</div>'
    + pre(
        'JS Files: ' + str(len((read_lines(os.path.join(OUT_DIR,'js/js_files.txt'), 0)) or [])) + '\n'
        + 'Interesting Endpoints: ' + str(len((read_lines(os.path.join(OUT_DIR,'js/interesting_urls.txt'), 0)) or [])) + '\n\n'
        + '--- Interesting Endpoints (first 100) ---\n'
        + '\n'.join(read_lines(os.path.join(OUT_DIR,'js/interesting_urls.txt'), 100) or [])
    )
    + '</div>'
    '<div class="section"><div class="st">JS Bundle - API Endpoints</div>'
    + pre(read(os.path.join(OUT_DIR,'js/api_endpoints.txt')) or 'No API endpoints found in JS bundles.')
    + '</div>'
    '<div class="section"><div class="st">JS Bundle - Potential Secrets</div>'
    + (('<div style="background:#fff3cd;border-left:4px solid #ffc107;padding:8px 12px;margin-bottom:8px;border-radius:4px"><b>⚠ Potential secrets found - review carefully</b></div>'
        + pre(read(os.path.join(OUT_DIR,'js/secrets.txt'))))
       if os.path.exists(os.path.join(OUT_DIR,'js/secrets.txt')) and os.path.getsize(os.path.join(OUT_DIR,'js/secrets.txt')) > 0
       else pre('No secrets found in JS bundles.'))
    + '</div>'
    '<div class="section"><div class="st">Wayback Sensitive Files</div>'
    + pre(read(os.path.join(OUT_DIR,'js/wayback_sensitive.txt')) or 'No sensitive files found in Wayback URLs.')
    + '</div>'
    '<div class="section"><div class="st">Google Dorks</div>'
    + pre(read(os.path.join(OUT_DIR,'dorks/dorks.txt')) or 'Not run.')
    + '</div>'
    '</div>'

    # ── Vulnerabilities tab ──
    '<div id="p-vulns" class="panel">'
    '<div class="section">'
    '<div class="st">Threat List</div>'
    '<div class="sev-pills">'
    '<div class="sev-pill pill-crit active" onclick="filterFindings(\'critical\',this)"><span class="pill-count">' + str(sc['critical']) + '</span> Critical</div>'
    '<div class="sev-pill pill-high active" onclick="filterFindings(\'high\',this)"><span class="pill-count">' + str(sc['high']) + '</span> High</div>'
    '<div class="sev-pill pill-med active" onclick="filterFindings(\'medium\',this)"><span class="pill-count">' + str(sc['medium']) + '</span> Medium</div>'
    '<div class="sev-pill pill-low active" onclick="filterFindings(\'low\',this)"><span class="pill-count">' + str(sc['low']) + '</span> Low</div>'
    '<div class="sev-pill pill-info active" onclick="filterFindings(\'info\',this)"><span class="pill-count">' + str(sum(1 for f in findings if f["sev"]=="info")) + '</span> Info</div>'
    '<div class="sev-pill pill-total" style="margin-left:auto"><span class="pill-count">' + str(len(findings)) + '</span> Total</div>'
    '</div>'
    '<div class="filter-bar">'
    '<div class="search-box"><svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg><input type="text" id="finding-search" placeholder="Filter by threat title" oninput="applyFindingFilters()"></div>'
    '<select class="filter-select" id="finding-sev-filter" onchange="applyFindingFilters()"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>'
    '<span class="filter-count" id="finding-count">Displaying ' + str(len(findings)) + ' findings</span>'
    '</div>'
    '<div class="card" style="padding:0"><div id="findings-list">' + findings_html + '</div></div>'
    '</div></div>'

    # ── Leaks & Emails tab ──
    '<div id="p-leaks" class="panel">'
    '<div class="section"><div class="st">Harvested Emails</div>' + pre(read(os.path.join(OUT_DIR,'emails/emails.txt')) or 'No emails found.') + '</div>'
    '<div class="section"><div class="st">Breach Check</div><div class="card"><p style="color:var(--text-muted)">Check emails manually at <a href="https://haveibeenpwned.com" target="_blank">haveibeenpwned.com</a></p>' + pre(read(os.path.join(OUT_DIR,'emails/emails.txt')) or 'No emails harvested.') + '</div></div>'
    '<div class="section"><div class="st">Leak Search Results</div>'
    + pre('\n'.join(l.strip() for l in raw_log.splitlines()
        if any(x in l for x in ['GitHub:','Grep.app:','Pastebin:','GitLab:','no exposures','no results']))
        or 'No leak results.')
    + '</div>'
    '<div class="section"><div class="st">Cloud Storage</div>'
    + pre('\n'.join(l.strip() for l in raw_log.splitlines()
        if any(x in l for x in ['S3 bucket','GCS bucket','Azure blob','public bucket','no public bucket']))
        or 'No cloud storage findings.')
    + '</div>'
    '<div class="section"><div class="st">Social Engineering Intel</div>'
    + pre('\n'.join(l.strip() for l in raw_log.splitlines()
        if any(x in l for x in ['Tech stack','Detected tech','LinkedIn','Hunter.io','Crunchbase','Email format','Gathering OSINT']))
        or 'No social intel gathered.')
    + '</div>'
    '</div>'

    # ── Raw Output tab ──
    '<div id="p-raw" class="panel">'    '<div class="section"><div class="st">Raw Scan Output</div>'    '<div style="margin-bottom:8px"><button onclick="copyRaw()" style="font-size:12px;padding:4px 12px;background:var(--surface);border:1px solid var(--border);color:var(--text-muted);cursor:pointer;border-radius:var(--radius)">Copy to clipboard</button></div>'    '<pre id="rawlog" style="max-height:700px;overflow-y:auto">' + (raw_log_full[:200000].replace('<','&lt;').replace('>','&gt;')) + '</pre>'    '</div></div>'

    '<div class="footer">'
    '<span>RECONOMEW v1.0 &mdash; ' + target + '</span>'
    '<span>For authorised testing only &mdash; point-in-time results</span>'
    '</div>'
    '</div>'  # close .content
    '</div>'  # close .main

    '<script>'
    'function sw(id,el){'
    'document.querySelectorAll(\'.panel\').forEach(p=>p.classList.remove(\'on\'));'
    'document.getElementById(\'p-\'+id).classList.add(\'on\');}'
    'function setActive(el){'
    'document.querySelectorAll(\'.sidebar-item\').forEach(i=>i.classList.remove(\'active\'));'
    'el.classList.add(\'active\');}'
    'function filterFindings(sev,pill){'
    'const pills=document.querySelectorAll(\'.sev-pill\');'
    'if(pill.classList.contains(\'active\')){'
    'pill.classList.remove(\'active\');pill.classList.add(\'inactive\');'
    '}else{pill.classList.remove(\'inactive\');pill.classList.add(\'active\');}'
    'applyFindingFilters();}'
    'function applyFindingFilters(){'
    'const search=document.getElementById(\'finding-search\').value.toLowerCase();'
    'const sevFilter=document.getElementById(\'finding-sev-filter\').value;'
    'const activePills=[...document.querySelectorAll(\'.sev-pill.active\')].map(p=>p.onclick.toString().match(/\'(\\w+)\'/)?.[1]).filter(Boolean);'
    'const items=document.querySelectorAll(\'#findings-list .finding\');'
    'let shown=0;'
    'items.forEach(item=>{'
    'const sev=item.querySelector(\'.sev\').textContent.toLowerCase().trim();'
    'const desc=item.querySelector(\'.finding-desc\').textContent.toLowerCase();'
    'const matchSearch=!search||desc.includes(search);'
    'const matchSev=(!sevFilter||sev.includes(sevFilter))&&(activePills.length===0||activePills.some(p=>sev.includes(p)));'
    'const vis=matchSearch&&matchSev;'
    'item.style.display=vis?\'\':"none";if(vis)shown++;});'
    'const c=document.getElementById(\'finding-count\');if(c)c.textContent="Displaying "+shown+" findings";}'
    'function copyRaw(){'
    'const t=document.getElementById(\'rawlog\').textContent;'
    'navigator.clipboard.writeText(t).then(()=>{'
    'const b=document.querySelector(\'button[onclick="copyRaw()"]\');'
    'const o=b.textContent;b.textContent=\'Copied!\';'
    'setTimeout(()=>b.textContent=o,2000);});}'
    '</script></body></html>'
)

report_file = os.path.join(OUT_DIR, 'report.html')
with open(report_file, 'w') as fh:
    fh.write(html)

# stats printed by bash after PYEOF
PYEOF
  local report_exit=$?
  printf "\033[2K\r"
  if [[ $report_exit -eq 124 ]]; then
    warn "Report generation timed out - partial report may exist"
  elif [[ $report_exit -ne 0 ]]; then
    warn "Report generation failed (exit $report_exit)"
  else
    info "Report written: ${W}${OUT_DIR}/report.html${NC}"
    # Clean up intermediate files - keep only report.html and raw_output.txt
    find "${OUT_DIR}" -type f \
      ! -name "report.html" \
      ! -name "raw_output.txt" \
      -delete 2>/dev/null || true
    # Remove empty subdirectories
    find "${OUT_DIR}" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    info "Cleaned up intermediate files - keeping report.html and raw_output.txt"
  fi
}

