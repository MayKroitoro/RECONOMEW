#!/usr/bin/env bash
# RECONOMEW — osint.sh
# Modules: SecurityTrails, Shodan, Email harvest, Social Intel, JS Discovery, Cloud Enum, Leak Search, Google Dorks

# ================================================================
#  MODULE: CVE LOOKUP
# ================================================================


# ================================================================
#  MODULE: SECURITYTRAILS
# ================================================================

run_securitytrails() {
  module_enabled "securitytrails" || return
  [[ -z "$SECURITYTRAILS_KEY" ]] && skip "SecurityTrails (no API key - get free key at securitytrails.com)" && return
  [[ -z "$DOMAIN" ]] && return
  section "SecurityTrails Intelligence"

  local st_headers=(-H "APIKEY: $SECURITYTRAILS_KEY" -H "Accept: application/json")

  info "Fetching subdomains from SecurityTrails..."
  local st_subs
  st_subs=$(curl -s --max-time 20 "${st_headers[@]}" \
    "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains?children_only=false&include_inactive=true" \
    2>/dev/null || true)

  local sub_list
  sub_list=$(echo "$st_subs" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    subs = d.get('subdomains',[])
    domain = d.get('apex_domain','')
    for s in subs:
        print(s + '.' + domain)
except: pass
" 2>/dev/null || true)

  if [[ -n "$sub_list" ]]; then
    local sub_count
    sub_count=$(echo "$sub_list" | wc -l | tr -d ' ')
    info "SecurityTrails: $sub_count subdomains found"
    echo "$sub_list" | head -10 | while read -r l; do result "$l"; done
    echo "$sub_list" >> "${OUT_DIR}/subfinder.txt"
    sort -u "${OUT_DIR}/subfinder.txt" -o "${OUT_DIR}/subfinder.txt" 2>/dev/null || true
  else
    result "No subdomains returned (check API key or quota)"
  fi

  info "Fetching historical DNS records..."
  local hist_out=""
  for rtype in a mx ns txt; do
    local hist
    hist=$(curl -s --max-time 15 "${st_headers[@]}" \
      "https://api.securitytrails.com/v1/history/$DOMAIN/dns/$rtype" \
      2>/dev/null || true)

    local parsed
    parsed=$(echo "$hist" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    records = d.get('records',[])
    rtype = '$rtype'.upper()
    for r in records[:5]:
        first = r.get('first_seen','')
        last  = r.get('last_seen','')
        vals  = r.get('values',[])
        for v in vals[:3]:
            ip = v.get('ip') or v.get('value') or v.get('host','')
            if ip:
                print(rtype + '  ' + ip + '  [' + first + ' -> ' + last + ']')
except: pass
" 2>/dev/null || true)

    if [[ -n "$parsed" ]]; then
      result "[$(echo "$rtype" | tr '[:lower:]' '[:upper:]')] Historical:"
      echo "$parsed" | while read -r l; do result "  $l"; done
      hist_out+="=== ${rtype^^} ===${IFS}$parsed${IFS}"
    fi
  done
  echo "$hist_out" > "${OUT_DIR}/securitytrails_history.txt"
}

# ================================================================
#  MODULE: SHODAN
# ================================================================

run_shodan() {
  module_enabled "shodan" || return
  [[ -z "$SHODAN_API_KEY" ]] && skip "Shodan (no API key)" && return
  [[ -z "$IP" ]] && skip "Shodan (no IP)" && return
  section "Shodan Intelligence"

  if tool_ok "jq"; then
    printf "  \033[0;36m[→]\033[0m Querying Shodan for $IP...\r"
    local shodan_out shodan_error
    shodan_out=$(curl -s --max-time 20 \
      "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY" 2>/dev/null || true)
    printf "\r\033[2K"

    shodan_error=$(echo "$shodan_out" | jq -r '.error // empty' 2>/dev/null || true)
    if [[ -n "$shodan_error" ]]; then
      warn "Shodan error: $shodan_error"
    elif [[ -z "$shodan_out" ]] || [[ "$shodan_out" == "null" ]]; then
      warn "Shodan: no response"
    else
      local org isp country hostnames ports tags
      org=$(echo "$shodan_out"       | jq -r '.org          // "N/A"' 2>/dev/null)
      isp=$(echo "$shodan_out"       | jq -r '.isp          // "N/A"' 2>/dev/null)
      country=$(echo "$shodan_out"   | jq -r '.country_name // "N/A"' 2>/dev/null)
      hostnames=$(echo "$shodan_out" | jq -r '(.hostnames // []) | join(", ")' 2>/dev/null)
      ports=$(echo "$shodan_out"     | jq -r '(.ports // []) | map(tostring) | join(", ")' 2>/dev/null)
      tags=$(echo "$shodan_out"      | jq -r '(.tags // []) | join(", ")' 2>/dev/null)
      # If all fields are N/A, Shodan has no data (common for Cloudflare IPs)
      if [[ "$org" == "N/A" && "$isp" == "N/A" && "$country" == "N/A" ]]; then
        info "Shodan: no data for this IP (CDN/Cloudflare IP not indexed by Shodan)"
      else
        result "  Org       : $org"
        result "  ISP       : $isp"
        result "  Country   : $country"
        [[ -n "$hostnames" ]] && result "  Hostnames : $hostnames"
        [[ -n "$ports"     ]] && result "  Open Ports: $ports"
        [[ -n "$tags"      ]] && result "  Tags      : $tags"
      fi
      echo "$shodan_out" | jq -r '.data[]? | "  [Port \(.port)/\(.transport)] \(.product // "unknown") \(.version // "")"' \
        2>/dev/null | head -20 | while read -r l; do result "$l"; done || true
    fi
    echo "$shodan_out" > "${OUT_DIR}/shodan.json"
  else
    skip "Shodan (jq not installed)"
  fi
}

# ================================================================
#  MODULE: EMAIL HARVESTING
# ================================================================

run_email_harvest() {
  module_enabled "email-harvest" || return
  [[ -z "$DOMAIN" ]] && return
  section "Email Harvesting"

  mkdir -p "${OUT_DIR}/emails"
  local emails_found=""
  local UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

  printf "  \033[0;36m[→]\033[0m Scanning main page for email addresses...\r"
  local page_emails
  page_emails=$(curl -s --max-time 15 -L \
    -H "User-Agent: $UA" \
    "https://$DOMAIN" 2>/dev/null \
    | sed 's/u003e//g; s/u003c//g; s/u0026//g; s/&gt;//g; s/&lt;//g; s/&#[0-9]*;//g' \
    | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
    | grep -vE "example\.com|test\.com|sentry\.io|w3\.org|schema\.org|email@email|test@test|name@|user@|admin@example|info@example|noreply@example|your@|yourname@|contact@contact|placeholder|lorem|email@domain|@domain\." \
    | grep -vE "@[0-9]+x\.|@[0-9]|\.(png|jpg|gif|svg|webp|ico|bmp|tiff|jpeg)$|\.js$|\.css$|\.html$" \
    | sort -u | head -20 || true)

  printf "\r\033[2K"
  if [[ -n "$page_emails" ]]; then
    info "Found emails in main page:"
    echo "$page_emails" | while read -r e; do result "$e"; done
    emails_found+="$page_emails"$'\n'
  fi

  # ── Scrape contact/about pages + crawl links from main page ──
  # Build list of pages to scrape: hardcoded candidates + links found on main page
  local scrape_paths=(/contact /about /team /about-us /contact-us /support /our-team /staff /people /company /careers /jobs /press /media)

  # Also grab internal links from main page that look like they might have contacts
  printf "  \033[0;36m[→]\033[0m Finding contact pages from main page links...\r"
  local main_html
  main_html=$(curl -s --max-time 15 -L -H "User-Agent: $UA" "https://$DOMAIN" 2>/dev/null || true)
  local extra_paths
  extra_paths=$(echo "$main_html" | grep -oE 'href="(/[^"]*)"' | sed 's/href="//;s/"//' \
    | grep -iE "contact|about|team|staff|people|reach|connect|support|careers|press" \
    | grep -v "^#" | sort -u | head -10 || true)
  while IFS= read -r p; do
    [[ -n "$p" ]] && scrape_paths+=("$p")
  done <<< "$extra_paths"
  printf "\r\033[2K"

  # Follow redirects to get the real base URL for scraping
  local scrape_base
  scrape_base=$(curl -sk --max-time 8 -o /dev/null -w "%{url_effective}" -L \
    "${TARGET_URL:-https://$DOMAIN}/" 2>/dev/null || echo "")
  if [[ -n "$scrape_base" ]]; then
    # Extract just scheme+host
    scrape_base=$(echo "$scrape_base" | grep -oE "^https?://[^/]+" || echo "${TARGET_URL:-https://$DOMAIN}")
  else
    scrape_base="${TARGET_URL:-https://$DOMAIN}"
  fi

  local scraped_pages=0
  local _scrape_total=${#scrape_paths[@]}
  local _scrape_done=0
  for path in "${scrape_paths[@]}"; do
    _scrape_done=$((_scrape_done + 1))
    printf "\r  \033[0;36m[→]\033[0m Scraping pages %d/%d — %s\033[K" "$_scrape_done" "$_scrape_total" "$path"
    local url="${scrape_base}${path}"
    local status
    status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" -L "$url" 2>/dev/null || echo "000")
    status=$(echo "$status" | grep -oE "[0-9]{3}$" || echo "000")
    [[ "$status" != "200" && "$status" != "301" && "$status" != "302" ]] && continue

    local page_out
    page_out=$(curl -s --max-time 10 -L \
      -H "User-Agent: $UA" \
      "$url" 2>/dev/null \
      | sed 's/u003e//g; s/u003c//g; s/u0026//g; s/&gt;//g; s/&lt;//g; s/&#[0-9]*;//g' \
      | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
      | grep -vE "example\.com|test\.com|sentry\.io|w3\.org|schema\.org|email@email|test@test|name@|user@|admin@example|info@example|noreply@example|your@|yourname@|contact@contact|placeholder|lorem|email@domain|@domain\." \
      | grep -vE "@[0-9]+x\.|@[0-9]|\.(png|jpg|gif|svg|webp|ico|bmp|tiff|jpeg)$|\.js$|\.css$|\.html$" \
      | sort -u | head -10 || true)
    scraped_pages=$((scraped_pages + 1))

    if [[ -n "$page_out" ]]; then
      local printed_any=false
      while IFS= read -r e; do
        if ! echo "$emails_found" | grep -qxF "$e" 2>/dev/null; then
          if ! $printed_any; then
            printf "\r\033[2K"
            info "Found on $path:"
            printed_any=true
          fi
          result "  $e"
        fi
      done <<< "$page_out"
      emails_found+="$page_out"$'\n'
    fi
  done
  printf "\r\033[2K"
  info "Web scraping done: $scraped_pages pages checked"

  # ── theHarvester ──
  if command -v theHarvester &>/dev/null; then
    local th_json="${OUT_DIR}/emails/theharvester"
    local th_out="${OUT_DIR}/emails/theharvester_raw.txt"
    # Use -f to save JSON/XML, -q to suppress API key warnings
    # Best free sources that don't require API keys
    # Run theHarvester - stdout+stderr both captured for debugging
    # -q suppresses API key warnings, sources chosen as free/no-key-needed
    bash -c "theHarvester \
      -d '$DOMAIN' \
      -b bing,duckduckgo,hackertarget,rapiddns,urlscan,waybackarchive,yahoo \
      -l 200 \
      -q \
      -f '$th_json' \
      > '${th_out}.stdout' 2>'$th_out'" &
    local th_pid=$!
    local th_start; th_start=$(date +%s)
    local th_elapsed=0
    printf "\r  \033[0;36m[→]\033[0m theHarvester searching \033[2m0s\033[0m\033[K"
    while kill -0 "$th_pid" 2>/dev/null; do
      sleep 1
      th_elapsed=$(( $(date +%s) - th_start ))
      [[ $th_elapsed -ge 120 ]] && kill "$th_pid" 2>/dev/null && break
      printf "\r  \033[0;36m[→]\033[0m theHarvester searching \033[2m%ds\033[0m\033[K" "$th_elapsed"
    done
    wait "$th_pid" 2>/dev/null || true
    printf "\r\033[2K"
    # Show first line of stderr if it errored instantly (< 6s means crash)
    if [[ $th_elapsed -le 5 ]] && [[ -s "$th_out" ]]; then
      warn "theHarvester error: $(head -3 "$th_out" | grep -v '^$' | tail -1)"
    fi
    # Parse emails from JSON output
    local th_emails=""
    if [[ -f "${th_json}.json" ]]; then
      th_emails=$(python3 -c "
import json, sys
try:
    d = json.load(open('${th_json}.json'))
    emails = d.get('emails', [])
    for e in emails:
        print(e)
except: pass
" 2>/dev/null || true)
    fi
    # Fallback: grep raw output
    if [[ -z "$th_emails" ]] && [[ -f "$th_out" ]]; then
      th_emails=$(grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
        "$th_out" 2>/dev/null || true)
    fi
    th_emails=$(echo "$th_emails" \
      | grep -vE "sentry|schema|example|w3\.org|edge-security\.com|theharvester" \
      | sort -u || true)
    if [[ -n "$th_emails" ]]; then
      echo "$th_emails" | while read -r e; do
        [[ -z "$e" ]] && continue
        if ! echo "$emails_found" | grep -qxF "$e"; then
          info "theHarvester: $e"
          emails_found+="$e"$'\n'
        fi
      done
    fi
  fi

  # ── Hunter.io API ──
  if [[ -n "${HUNTER_API_KEY:-}" ]]; then
    printf "  \033[0;36m[→]\033[0m Hunter.io domain search...\r"
    local hunter_out
    hunter_out=$(curl -s --max-time 15 \
      "https://api.hunter.io/v2/domain-search?domain=$DOMAIN&api_key=$HUNTER_API_KEY" \
      2>/dev/null || true)
    printf "\r\033[2K"
    if [[ -n "$hunter_out" ]]; then
      local hunter_emails hunter_format
      hunter_emails=$(echo "$hunter_out" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  emails=d.get('data',{}).get('emails',[])
  for e in emails:
    print(e.get('value',''))
except: pass
" 2>/dev/null || true)
      hunter_format=$(echo "$hunter_out" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  fmt=d.get('data',{}).get('pattern','')
  print(fmt)
except: pass
" 2>/dev/null || true)
      if [[ -n "$hunter_emails" ]]; then
        info "Hunter.io emails found:"
        echo "$hunter_emails" | while read -r e; do
          [[ -z "$e" ]] && continue
          result "  $e"
          emails_found+="$e"$'\n'
        done
      fi
      [[ -n "$hunter_format" ]] && info "Hunter.io email format: ${hunter_format}@${DOMAIN}"
    fi
  fi

  if [[ -n "$emails_found" ]]; then
    echo "$emails_found" | sort -u | grep -v "^$" > "${OUT_DIR}/emails/emails.txt"
    local total
    total=$(wc -l < "${OUT_DIR}/emails/emails.txt" 2>/dev/null | tr -d ' ' || echo 0)
    info "Total unique emails found: $total"

    # ── Email format guesser — 14 formats + confidence scoring ──
    python3 - << 'PYEOF_EMAIL'
import re, os, math
from collections import Counter

domain     = os.environ.get('DOMAIN', '')
out_dir    = os.environ.get('OUT_DIR', '')
emails_f   = os.path.join(out_dir, 'emails/emails.txt')
format_f   = os.path.join(out_dir, 'emails/email_format.txt')
wordlist_f = os.path.join(out_dir, 'emails/email_wordlist.txt')

EMAIL_FORMATS = [
    ('first.last',  lambda f, l: f'{f}.{l}'),
    ('firstlast',   lambda f, l: f'{f}{l}'),
    ('f.last',      lambda f, l: f'{f[0]}.{l}'),
    ('flast',       lambda f, l: f'{f[0]}{l}'),
    ('first.l',     lambda f, l: f'{f}.{l[0]}'),
    ('firstl',      lambda f, l: f'{f}{l[0]}'),
    ('last.first',  lambda f, l: f'{l}.{f}'),
    ('lastfirst',   lambda f, l: f'{l}{f}'),
    ('l.first',     lambda f, l: f'{l[0]}.{f}'),
    ('lfirst',      lambda f, l: f'{l[0]}{f}'),
    ('first',       lambda f, l: f'{f}'),
    ('last',        lambda f, l: f'{l}'),
    ('f.l',         lambda f, l: f'{f[0]}.{l[0]}'),
    ('fl',          lambda f, l: f'{f[0]}{l[0]}'),
]

TEST_NAMES = [
    ('john','smith'),('jane','doe'),('mike','johnson'),('sarah','williams'),
    ('david','brown'),('lisa','jones'),('james','garcia'),('mary','davis'),
    ('robert','miller'),('jennifer','wilson'),
]

REAL_NAMES = [
    ('james','smith'),('mary','johnson'),('john','williams'),('patricia','brown'),
    ('robert','jones'),('jennifer','garcia'),('michael','miller'),('linda','davis'),
    ('william','rodriguez'),('barbara','martinez'),('david','hernandez'),('susan','lopez'),
    ('richard','gonzalez'),('jessica','wilson'),('joseph','anderson'),('sarah','thomas'),
    ('thomas','taylor'),('karen','moore'),('charles','jackson'),('lisa','martin'),
    ('daniel','lee'),('nancy','perez'),('matthew','thompson'),('betty','white'),
    ('anthony','harris'),('margaret','sanchez'),('mark','clark'),('dorothy','lewis'),
    ('donald','robinson'),('lisa','walker'),
]

def detect_format(emails):
    scores = {fmt: 0 for fmt, _ in EMAIL_FORMATS}
    for email in emails:
        local = email.split('@')[0].lower()
        for fmt, generator in EMAIL_FORMATS:
            for first, last in TEST_NAMES:
                try:
                    if local == generator(first, last):
                        scores[fmt] += 2
                except Exception:
                    pass
        parts = re.split(r'[._\-]', local)
        if len(parts) == 2:
            p0, p1 = parts
            if len(p0) == 1 and len(p1) > 2:   scores['f.last']  += 3
            elif len(p1) == 1 and len(p0) > 2:  scores['first.l'] += 3
            elif len(p0) > 2 and len(p1) > 2:   scores['first.last'] += 2
        elif len(parts) == 1:
            if len(local) > 6: scores['firstlast'] += 1
    best  = max(scores, key=scores.get)
    score = scores[best]
    conf  = 'high' if score >= 6 else 'medium' if score >= 2 else 'low'
    return best, conf, scores

def main():
    try:
        emails = [l.strip() for l in open(emails_f) if '@' + domain in l and l.strip()]
    except Exception:
        return

    if not emails:
        print('  [~] No emails harvested — generating multi-format wordlist')
        wordlist = []
        for fmt, generator in EMAIL_FORMATS[:6]:
            for first, last in REAL_NAMES[:10]:
                try: wordlist.append(generator(first, last) + '@' + domain)
                except: pass
        with open(wordlist_f, 'w') as fh:
            fh.write('\n'.join(sorted(set(wordlist))) + '\n')
        print(f'  [+] Multi-format wordlist: {len(set(wordlist))} entries -> {wordlist_f}')
        return

    best, conf, scores = detect_format(emails)
    print(f'  [+] Email format detected: {best}@{domain} (confidence: {conf})')

    top3 = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:3]
    for fmt, sc in top3:
        if sc > 0: print(f'      {fmt}: score {sc}')

    generator = dict(EMAIL_FORMATS)[best]
    examples = []
    for first, last in REAL_NAMES[:3]:
        try: examples.append(generator(first, last) + '@' + domain)
        except: pass

    with open(format_f, 'w') as fh:
        fh.write(f'Detected format : {best}@{domain}\n')
        fh.write(f'Confidence      : {conf}\n')
        fh.write(f'Top candidates  : {", ".join(f for f,s in top3 if s > 0)}\n')
        fh.write(f'Examples        : {", ".join(examples)}\n')
        fh.write(f'Known emails    : {", ".join(emails[:5])}\n')

    wordlist = []
    for first, last in REAL_NAMES:
        try: wordlist.append(generator(first, last) + '@' + domain)
        except: pass

    with open(wordlist_f, 'w') as fh:
        fh.write('\n'.join(wordlist) + '\n')
    print(f'  [+] Email wordlist: {len(wordlist)} entries ({best} format) -> {wordlist_f}')

main()
PYEOF_EMAIL
  else
    info "No emails found"
  fi
}

# ================================================================
#  MODULE: GITHUB / PASTE LEAK SEARCH
# ================================================================

run_leak_search() {
  module_enabled "leak-search" || return
  [[ -z "$DOMAIN" ]] && return
  section "Leak & Exposure Search"

  local UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  local total_hits=0

  # Derive company name from apex domain for broader searches
  local apex; apex=$(get_apex_domain "$DOMAIN" | awk -F. '{print $1}')

  # ── 1. GitHub API code search ────────────────────────────────────
  local gh_queries=(
    "$DOMAIN password"
    "$DOMAIN secret"
    "$DOMAIN api_key"
    "$DOMAIN token"
    "$DOMAIN credentials"
    "$DOMAIN passwd"
    "$DOMAIN private_key"
    "$apex password"
    "$apex secret"
    "$apex api_key"
  )

  local gh_hits=0
  local gh_total=${#gh_queries[@]}
  local gh_done=0
  local gh_start; gh_start=$(date +%s)
  for query in "${gh_queries[@]}"; do
    gh_done=$((gh_done + 1))
    printf "  \033[0;36m[→]\033[0m GitHub code search — query %d/%d\033[K\r" "$gh_done" "$gh_total"

    local encoded_query
    encoded_query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))" 2>/dev/null || echo "$query")
    local gh_out
    gh_out=$(curl -s --max-time 15 \
      -H "Accept: application/vnd.github.v3+json" \
      ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
      "https://api.github.com/search/code?q=${encoded_query}&per_page=5&sort=indexed&order=desc" \
      2>/dev/null || true)

    local items total_count
    items=$(echo "$gh_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    for item in d.get('items', [])[:5]:
        repo  = item.get('repository',{}).get('full_name','')
        url   = item.get('html_url','')
        fname = item.get('name','')
        print(url + ' | ' + repo + ' | ' + fname)
except: pass
" 2>/dev/null || true)

    total_count=$(echo "$gh_out" | python3 -c "
import json,sys
try:
    print(json.load(sys.stdin).get('total_count',0))
except: print(0)
" 2>/dev/null || echo 0)

    if [[ -n "$items" ]]; then
      printf "\r\033[2K"
      warn "GitHub: '$query' — ${total_count} result(s)"
      echo "$items" | while read -r l; do result "  $l"; done
      gh_hits=$((gh_hits + 1))
      total_hits=$((total_hits + 1))
    fi
    sleep 2
  done

  printf "\r\033[2K"
  local gh_elapsed=$(( $(date +%s) - gh_start ))
  if [[ $gh_hits -eq 0 ]]; then
    if [[ -z "$GITHUB_TOKEN" ]]; then
      info "GitHub code search — no results (${gh_elapsed}s, unauthenticated — set GITHUB_TOKEN for full results)"
    else
      info "GitHub code search — no results (${gh_elapsed}s)"
    fi
  else
    info "GitHub code search — ${gh_hits} quer(ies) with findings (${gh_elapsed}s)"
  fi

  # ── 2. Grep.app — all file types, domain + company name ──────────
  local grep_start; grep_start=$(date +%s)
  local grep_total_hits=0
  for grep_term in "$DOMAIN" "$apex"; do
    printf "  \033[0;36m[→]\033[0m Grep.app search: $grep_term\r"
    local grep_out
    grep_out=$(curl -s --max-time 15 \
      -H "User-Agent: $UA" \
      -H "Accept: application/json" \
      "https://grep.app/api/search?q=${grep_term}&per_page=10" \
      2>/dev/null || true)

    local grep_hits grep_total
    grep_total=$(echo "$grep_out" | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('hits',{}).get('total',{}).get('value',0))
except: print(0)
" 2>/dev/null || echo 0)

    grep_hits=$(echo "$grep_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    for h in d.get('hits',{}).get('hits',[])[:10]:
        repo  = h.get('repo',{}).get('raw','')
        fname = h.get('file',{}).get('raw','')
        print(repo + ' | ' + fname)
except: pass
" 2>/dev/null || true)

    printf "\r\033[2K"
    if [[ -n "$grep_hits" && "$grep_total" -gt 0 ]]; then
      warn "Grep.app: '$grep_term' — ${grep_total} result(s)"
      echo "$grep_hits" | while read -r l; do result "  $l"; done
      grep_total_hits=$((grep_total_hits + 1))
      total_hits=$((total_hits + 1))
    else
      info "Grep.app: '$grep_term' — no results"
    fi
    sleep 1
  done

  # ── 3. Pastebin (psbdmp.ws) — domain + company name ─────────────
  for paste_term in "$DOMAIN" "$apex"; do
    printf "  \033[0;36m[→]\033[0m Pastebin search: $paste_term\r"
    local psbdmp_out
    psbdmp_out=$(curl -s --max-time 15 \
      -H "User-Agent: $UA" \
      "https://psbdmp.ws/api/search/${paste_term}" \
      2>/dev/null || true)

    local paste_hits
    paste_hits=$(echo "$psbdmp_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    pastes = d.get('data',[])
    if pastes:
        print(str(len(pastes)) + ' paste(s) found')
        for p in pastes[:10]:
            pid  = p.get('id','')
            tags = p.get('tags','')
            print('https://pastebin.com/' + pid + ' | tags: ' + tags)
except: pass
" 2>/dev/null || true)

    printf "\r\033[2K"
    if [[ -n "$paste_hits" ]]; then
      warn "Pastebin: '$paste_term' found in paste(s)"
      echo "$paste_hits" | while read -r l; do result "  $l"; done
      total_hits=$((total_hits + 1))
    else
      info "Pastebin: '$paste_term' — no results"
    fi
    sleep 1
  done

  # ── 4. GitLab — domain + company name, with retry ────────────────
  for gl_term in "$DOMAIN" "$apex"; do
    printf "  \033[0;36m[→]\033[0m GitLab search: $gl_term\r"
    local gl_out=""
    for _attempt in 1 2; do
      gl_out=$(curl -s --max-time 15 \
        -H "User-Agent: $UA" \
        "https://gitlab.com/api/v4/search?scope=blobs&search=${gl_term}&per_page=5" \
        2>/dev/null || true)
      [[ -n "$gl_out" && "$gl_out" != "[]" ]] && break
      sleep 3
    done

    local gl_hits
    gl_hits=$(echo "$gl_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, list) and d:
        for item in d[:5]:
            proj  = str(item.get('project_id',''))
            fname = item.get('filename','')
            ref   = item.get('ref','')
            print('project:' + proj + ' | ' + fname + ' (' + ref + ')')
except: pass
" 2>/dev/null || true)

    printf "\r\033[2K"
    if [[ -n "$gl_hits" ]]; then
      warn "GitLab: '$gl_term' found in public code"
      echo "$gl_hits" | while read -r l; do result "  $l"; done
      total_hits=$((total_hits + 1))
    else
      info "GitLab: '$gl_term' — no results"
    fi
    sleep 1
  done

  # ── 5. HIBP breach check on harvested emails ─────────────────────
  local emails_file="${OUT_DIR}/emails/emails.txt"
  if [[ -f "$emails_file" ]] && [[ -s "$emails_file" ]]; then
    info "HaveIBeenPwned breach check..."
    local hibp_hits=0
    while IFS= read -r email; do
      [[ -z "$email" ]] && continue
      printf "  \033[0;36m[→]\033[0m HIBP checking: $email\r"
      local hibp_out
      hibp_out=$(curl -s --max-time 10 \
        -H "User-Agent: RECONOMEW" \
        -H "hibp-api-key: ${HIBP_API_KEY:-}" \
        "https://haveibeenpwned.com/api/v3/breachedaccount/${email}?truncateResponse=false" \
        2>/dev/null || true)
      printf "\r\033[2K"
      # Only flag as breach if response contains actual breach data (array of objects)
      # Without API key, HIBP returns 401 — skip that
      if [[ -n "$hibp_out" ]] && \
         echo "$hibp_out" | grep -q '"Name"' && \
         ! echo "$hibp_out" | grep -qi "unauthori\|api key\|Account not found"; then
        local breach_names
        breach_names=$(echo "$hibp_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    names = [b.get('Name','') for b in d]
    print(', '.join(names[:5]))
except: pass
" 2>/dev/null || true)
        warn "HIBP: $email found in breach(es): $breach_names"
        hibp_hits=$((hibp_hits + 1))
        total_hits=$((total_hits + 1))
      else
        result "HIBP: $email — not found in known breaches"
      fi
      sleep 1  # HIBP rate limit
    done < "$emails_file"
    [[ "$hibp_hits" -eq 0 ]] && info "HIBP: no breached accounts found"
  fi

  # ── Summary ──────────────────────────────────────────────────────
  echo ""
  if [[ $total_hits -gt 0 ]]; then
    warn "Leak search complete — ${total_hits} source(s) with findings"
  else
    info "Leak search complete — no exposures found"
    [[ -z "$GITHUB_TOKEN" ]] && info "Tip: set GITHUB_TOKEN for authenticated GitHub search (higher rate limits)"
  fi
}



# ================================================================
#  MODULE: JS / URL DISCOVERY (gau + waybackurls)
# ================================================================

run_js_discovery() {
  module_enabled "js-discovery" || return
  [[ -z "$DOMAIN" ]] && return

  local has_gau has_wayback
  { command -v gau &>/dev/null || [[ -x "$HOME/go/bin/gau" ]] || [[ -x "/root/go/bin/gau" ]]; } && has_gau=true || has_gau=false
  { command -v waybackurls &>/dev/null || [[ -x "$HOME/go/bin/waybackurls" ]] || [[ -x "/root/go/bin/waybackurls" ]]; } && has_wayback=true || has_wayback=false

  if ! $has_gau && ! $has_wayback; then
    section "JavaScript & URL Discovery"
    warn "gau and waybackurls not installed — skipping URL collection"
    warn "Install: go install github.com/lc/gau/v2/cmd/gau@latest"
    warn "Install: go install github.com/tomnomnom/waybackurls@latest"
    return
  fi

  section "JavaScript & URL Discovery"
  mkdir -p "${OUT_DIR}/js"
  info "Collecting URLs via gau + waybackurls, then scanning JS files for secrets..."

  local url_dump="${OUT_DIR}/js/all_urls.txt"
  > "$url_dump"

  # gau - pulls from Wayback Machine, Common Crawl, OTX, URLScan
  # Run gau + waybackurls in parallel with timeout
  local gau_err="${OUT_DIR}/gau_error.txt"
  local gau_pid="" wb_pid=""

  if $has_gau; then
    bash -c "echo '$DOMAIN' | gau >> '$url_dump' 2>'$gau_err' || true" &
    gau_pid=$!
  fi

  if $has_wayback; then
    bash -c "echo '$DOMAIN' | waybackurls >> '$url_dump' 2>/dev/null || true" &
    wb_pid=$!
  fi

  local _start_ts; _start_ts=$(date +%s)
  local _elapsed=0
  printf "  \033[0;36m[→]\033[0m URL collection (gau + waybackurls)"
  while [[ $_elapsed -lt 600 ]]; do
    local _running=false
    [[ -n "$gau_pid" ]] && kill -0 "$gau_pid" 2>/dev/null && _running=true
    [[ -n "$wb_pid" ]]  && kill -0 "$wb_pid"  2>/dev/null && _running=true
    $_running || break
    sleep 5; _elapsed=$((_elapsed + 5))
    local _url_so_far
    _url_so_far=$(wc -l < "$url_dump" 2>/dev/null | tr -d ' '); _url_so_far=${_url_so_far:-0}
    printf "\r  \033[0;36m[→]\033[0m URL collection (gau + waybackurls) \033[2m%ds | urls: %s\033[0m\033[K" \
      "$_elapsed" "$_url_so_far"
  done
  printf "\r\033[2K"

  local _end_ts; _end_ts=$(date +%s)
  local _took=$((_end_ts - _start_ts))

  # Kill any still running
  [[ -n "$gau_pid" ]] && kill "$gau_pid" 2>/dev/null || true
  [[ -n "$wb_pid" ]]  && kill "$wb_pid"  2>/dev/null || true
  wait 2>/dev/null || true

  if [[ $_elapsed -ge 600 ]]; then
    warn "URL collection: time limit reached (600s)"
  else
    info "URL collection done - ${_took}s"
  fi

  # Deduplicate and clean URLs
  sort -u "$url_dump" -o "$url_dump"
  # Filter malformed URLs: must start with http(s)://, no BBCode/markup/special chars
  local _clean_dump="${url_dump}.clean"
  grep -E "^https?://[a-zA-Z0-9._-]+(:[0-9]+)?/" "$url_dump" 2>/dev/null \
    | grep -vE "\[|\]|\(|\)|\{|\}|<|>" \
    | sort -u > "$_clean_dump" 2>/dev/null || true
  mv "$_clean_dump" "$url_dump" 2>/dev/null || true
  local total_urls
  total_urls=$(wc -l < "$url_dump" | tr -d ' ')
  total_urls=${total_urls:-0}
  info "Total unique URLs collected: $total_urls"

  if [[ "$total_urls" -eq 0 ]]; then
    warn "URL collection returned 0 URLs — gau/waybackurls may have failed or been rate-limited"
    # Only show gau errors if they are real errors, not just config warnings
    if [[ -s "${OUT_DIR}/gau_error.txt" ]]; then
      local _gau_real_err
      _gau_real_err=$(grep -iv "config file\|not found\|using default\|level=warning" "${OUT_DIR}/gau_error.txt" | head -3 || true)
      [[ -n "$_gau_real_err" ]] && warn "gau error: $_gau_real_err"
    fi
    return
  fi

  # Extract JavaScript files
  local js_files="${OUT_DIR}/js/js_files.txt"
  # Deduplicate by stripping query strings, cap at 500
  grep -iE "\.js(\?|$)" "$url_dump" \
    | sed 's/\?.*$//' \
    | sort -u \
    | head -500 > "$js_files"
  local js_count
  js_count=$(wc -l < "$js_files" | tr -d ' ')
  js_count=${js_count:-0}

  if [[ "$js_count" -gt 0 ]]; then
    info "JavaScript files found: $js_count"
    head -10 "$js_files" | while read -r l; do result "  $l"; done
    [[ "$js_count" -gt 10 ]] && result "  ... and $((js_count-10)) more (see report)"
  else
    info "No JavaScript files found — secrets scan skipped"
  fi

  # Extract interesting endpoints - API paths, admin, config
  local interesting="${OUT_DIR}/js/interesting_urls.txt"
  grep -iE "/api/|/admin|/config|/token|/secret|/key|/password|/auth|/login|/upload|\.env|\.git|/v[0-9]+/" \
    "$url_dump" \
    | grep -E "^https?://[a-zA-Z0-9._-]+/" \
    | grep -vE "^https?://[^/]+:[^0-9/]" \
    | grep -vE "\.(js|png|jpg|jpeg|gif|svg|webp|ico|bmp|tiff|woff|woff2|ttf|eot|css|mp4|mp3|pdf)(\?|$)" \
    | grep -vE "/media/catalog/|/cache/[a-f0-9]+/|/static/version|thumbnail|small_image|resized|/modules/v[0-9]+/|chunk\.|client\." \
    | grep -vE "\.(asp|aspx|php|html?|jsp)(\.\.\.|[A-Z][a-z][a-z])" \
    | grep -vE "%5[Bb]|%5[Dd]|%7[Bb]|%7[Dd]|%28|%29|%7[Bb]" \
    | grep -vE "[a-z]\.[a-z]{2,4}[A-Z0-9]{2}|[a-z]{2,}http://" \
    | sed 's/\?.*$//' \
    | sort -u \
    | head -500 > "$interesting"
  local int_count
  int_count=$(wc -l < "$interesting" | tr -d ' ')
  int_count=${int_count:-0}

  if [[ "$int_count" -gt 0 ]]; then
    warn "Interesting endpoints found: $int_count"
    head -10 "$interesting" | while read -r l; do result "  $l"; done
    [[ "$int_count" -gt 10 ]] && result "  ... and $((int_count-10)) more (see report)"
  fi

  # Extract S3 buckets / cloud storage
  local cloud="${OUT_DIR}/js/cloud_storage.txt"
  grep -iE "s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|\.s3\." \
    "$url_dump" | sort -u > "$cloud"
  local cloud_count
  cloud_count=$(wc -l < "$cloud" | tr -d ' ')
  cloud_count=${cloud_count:-0}
  [[ "$cloud_count" -gt 0 ]] && warn "Cloud storage URLs found: $cloud_count (see report)"

  # ── Wayback Machine sensitive file filter ──
  local wayback_sensitive="${OUT_DIR}/js/wayback_sensitive.txt"
  grep -iE "\.(sql|bak|backup|env|zip|tar\.gz|tgz|log|dump|db|sqlite|config|conf|passwd|shadow|htpasswd|pem|key|p12|pfx|cer|crt|DS_Store|git/config|svn/entries)(\?|$)" \
    "$url_dump" 2>/dev/null \
    | grep -vE "^https?://[^/]+/https?://" \
    | grep -vE "[a-zA-Z0-9](https?://)" \
    | grep -vE "\[|\]|%5B|%5D" \
    | grep -E "^https?://[a-zA-Z0-9._-]+(:[0-9]+)?/" \
    | sort -u > "$wayback_sensitive" || true
  local wb_count
  wb_count=$(wc -l < "$wayback_sensitive" 2>/dev/null | tr -d ' '); wb_count=${wb_count:-0}
  if [[ "$wb_count" -gt 0 ]]; then
    warn "Wayback sensitive files: $wb_count potentially exposed files found!"
    head -20 "$wayback_sensitive" | while read -r l; do warn "  $l"; done
    [[ "$wb_count" -gt 20 ]] && info "  ... and $((wb_count-20)) more (see report)"
  else
    info "Wayback sensitive files: none found"
  fi

  # ── Scan JS bundles for secrets and API endpoints (React/webpack bundles) ──
  if [[ "$js_count" -gt 0 ]]; then
    local secrets_file="${OUT_DIR}/js/secrets.txt"
    local api_endpoints="${OUT_DIR}/js/api_endpoints.txt"
    > "$secrets_file"
    > "$api_endpoints"

    # ── Create cache dir BEFORE scanning ──
    mkdir -p "${OUT_DIR}/js/cache"

    # Build scan list — prefer target domain JS, fall back to all collected
    local _js_scan_list=""
    local _noise="wp-includes|wp-content/plugins|/cache/|jquery|bootstrap|modernizr|fontawesome"

    # Priority 1: HTTPS JS from main domain
    local _main_js
    _main_js=$(grep -iE "^https://(www\.)?${DOMAIN}/" "$js_files" 2>/dev/null \
      | grep -vE "$_noise" | head -300 || true)

    # Priority 2: HTTP JS from main domain
    local _http_js
    _http_js=$(grep -iE "^http://(www\.)?${DOMAIN}/" "$js_files" 2>/dev/null \
      | grep -vE "$_noise" | head -50 || true)

    # Priority 3: any other JS (external CDNs etc)
    local _other_js
    _other_js=$(grep -vE "^https?://(www\.)?${DOMAIN}/" "$js_files" 2>/dev/null \
      | grep -vE "$_noise" | head -50 || true)

    # Merge, deduplicate, cap at 150
    _js_scan_list=$(printf "%s
%s
%s" "$_main_js" "$_http_js" "$_other_js" \
      | grep -v "^$" | sort -u | head -300)

    local _js_total; _js_total=$(echo "$_js_scan_list" | grep -c "." 2>/dev/null || echo 0)
    _js_total=${_js_total:-0}

    if [[ "$_js_total" -eq 0 ]]; then
      info "No JS files to scan"
    else
      printf "  \033[0;36m[→]\033[0m Scanning JS files"
      local _js_done=0
      local _js_start; _js_start=$(date +%s)

      while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        _js_done=$((_js_done + 1))
        local _js_elapsed=$(( $(date +%s) - _js_start ))
        printf "\r  \033[0;36m[→]\033[0m Scanning JS files \033[2m%d/%d — %ds\033[0m\033[K" \
          "$_js_done" "$_js_total" "$_js_elapsed"

        local js_content
        js_content=$(curl -sk --max-time 8 \
          -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" \
          -H "Accept: */*" \
          "$js_url" 2>/dev/null | head -c 500000 || true)
        [[ -z "$js_content" ]] && continue
        # Skip obvious error pages (too short or contains common block messages)
        [[ ${#js_content} -lt 50 ]] && continue
        echo "$js_content" | grep -qiE "not found|access denied|forbidden|blocked|error 4[0-9][0-9]|<!doctype|<html" && [[ ${#js_content} -lt 500 ]] && continue

        # API endpoints - look for quoted URL paths
        echo "$js_content" | grep -oE '"(/api/[^"]{3,80}|/v[0-9]+/[^"]{3,80})"' \
          | tr -d '"' | sort -u >> "$api_endpoints" 2>/dev/null || true

        # Save JS content to cache file for Python entropy scanner
        local _cache_name; _cache_name=$(echo "$js_url" | md5sum | cut -d' ' -f1)
        printf '%s' "$js_content" > "${OUT_DIR}/js/cache/${_cache_name}.js" 2>/dev/null || true
      done <<< "$_js_scan_list"
      printf "\033[2K\r"
      local _js_took=$(( $(date +%s) - _js_start ))
    fi

    # ── Entropy + per-type pattern secret scanner ──
    # Only run if we actually fetched and cached some JS files
    local _cached_count
    _cached_count=$(find "${OUT_DIR}/js/cache/" -name "*.js" 2>/dev/null | wc -l | tr -d ' ')
    _cached_count=${_cached_count:-0}
    info "Scanned $_js_done JS files in ${_js_took}s ($_cached_count successfully downloaded) — running entropy secret scanner"
    if [[ "$_cached_count" -eq 0 ]]; then
      info "No JS files to scan for secrets"
    else
      info "Scanning $_cached_count cached JS files for secrets..."
      OUT_DIR="$OUT_DIR" python3 - << 'PYEOF_SECRETS'
import re, math, os, glob
from collections import Counter

out_dir      = os.environ.get('OUT_DIR', '')
js_cache     = os.path.join(out_dir, 'js', 'cache')
secrets_file = os.path.join(out_dir, 'js', 'secrets.txt')
api_file     = os.path.join(out_dir, 'js', 'api_endpoints.txt')

PATTERNS = [
    # Cloud providers
    ('AWS Access Key',        r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret Key',        r'(?i)aws.{0,20}secret.{0,20}["\s=:]+([A-Za-z0-9/+=]{40})'),
    ('GCP API Key',           r'AIza[0-9A-Za-z\-_]{35}'),
    # Azure: UUID only valid near secret/client/tenant keywords to avoid FPs
    ('Azure Client Secret',   r'(?i)(client.?secret|tenant.?id|client.?id)["\'\s]*[:=]["\'\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
    # Source control / CI
    ('GitHub Token',          r'gh[pousr]_[A-Za-z0-9]{36,255}'),
    ('GitLab Token',          r'glpat-[A-Za-z0-9\-]{20}'),
    # Payment
    ('Stripe Secret Key',     r'sk_live_[0-9a-zA-Z]{24,}'),
    ('Stripe Pub Key',        r'pk_live_[0-9a-zA-Z]{24,}'),
    ('Braintree Key',         r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    ('Square Token',          r'sq0atp-[0-9A-Za-z\-_]{22}'),
    ('PayPal Token',          r'(?i)paypal.{0,20}["\s=:]+([A-Za-z0-9\-_]{20,60})'),
    # Communication — require context word near Twilio patterns to avoid FPs
    ('Twilio SID',            r'(?i)(account.?sid|twilio)["\'\s]*[:=]["\'\s]*AC[a-zA-Z0-9]{32}'),
    ('Twilio Auth Token',     r'(?i)(auth.?token|twilio)["\'\s]*[:=]["\'\s]*[a-zA-Z0-9]{32}'),
    ('SendGrid Key',          r'SG\.[a-zA-Z0-9\-._]{22}\.[a-zA-Z0-9\-._]{43}'),
    ('Mailgun Key',           r'key-[0-9a-zA-Z]{32}'),
    ('Slack Token',           r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ('Slack Webhook',         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    # AI / ML — OpenAI: match proj format or classic key with T3BlbkFJ fingerprint
    ('OpenAI Key',            r'sk-proj-[A-Za-z0-9\-_]{40,}'),
    ('OpenAI Key (classic)',  r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
    ('Anthropic Key',         r'sk-ant-[A-Za-z0-9\-_]{40,}'),
    ('HuggingFace Token',     r'hf_[A-Za-z0-9]{34,}'),
    # Auth
    ('JWT Token',             r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    ('Basic Auth URL',        r'https?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_\-!@#$%]{8,}@'),
    ('Private Key Block',     r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    # Other services
    ('Firebase URL',          r'https://[a-z0-9\-]+\.firebaseio\.com'),
    ('Firebase Key',          r'(?i)firebase.{0,20}["\s=:]+([A-Za-z0-9\-_]{20,60})'),
    ('Cloudinary URL',        r'cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-z0-9]+'),
    ('Heroku API Key',        r'[hH]eroku.{0,20}[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'),
    ('NPM Token',             r'npm_[A-Za-z0-9]{36}'),
    ('Shopify Token',         r'shpat_[A-Za-z0-9]{32}'),
    ('Shopify Secret',        r'shpss_[A-Za-z0-9]{32}'),
    # Generic (entropy-gated) — use [\x22\x27] to match both quote types without shell escaping
    ('Generic API Key',     r'(?i)(api[_-]?key|apikey)[\x22\x27\s]*[:=][\x22\x27\s]*[\x22\x27]([A-Za-z0-9\-_]{20,60})[\x22\x27]'),
    ('Generic Secret',      r'(?i)(client_secret|app_secret|secret_key)[\x22\x27\s]*[:=][\x22\x27\s]*[\x22\x27]([A-Za-z0-9\-_]{20,60})[\x22\x27]'),
    ('Generic Token',       r'(?i)(access_token|auth_token|bearer)[\x22\x27\s]*[:=][\x22\x27\s]*[\x22\x27]([A-Za-z0-9\-_\.]{20,100})[\x22\x27]'),
    ('Generic Password',    r'(?i)(password|passwd|pwd)[\x22\x27\s]*[:=][\x22\x27\s]*[\x22\x27]([A-Za-z0-9\-_!@#$%^&*]{8,60})[\x22\x27]'),
    # Key-format catch-all: high-entropy quoted strings
    ('High-Entropy String', r'[\x22\x27]([A-Za-z0-9+/]{32,}={0,2})[\x22\x27]'),
]


# Old-style broad regex as additional sweep (catches things typed patterns miss)
BROAD_PATTERNS = [
    ('Broad Match',  r'(?i)(api[_-]?key|apikey|secret|token|password|passwd)["\s]*[:=]["\s]*[A-Za-z0-9+/]{20,}'),
]

IGNORE_VALUES = {
    'your_api_key_here','insert_key_here','xxxxxxxxxxxxxxxxxxxx',
    'your-secret-here','placeholder','example','changeme',
    'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx','undefined','null','true','false',
}

# ASP.NET fields that always contain high-entropy non-secret values
IGNORE_CONTEXT_PATTERNS = [
    '__viewstate', '__eventvalidation', '__viewstategenerator',
    '__eventtarget', '__eventargument', 'viewstate', 'eventvalidation',
]

def shannon_entropy(s):
    if not s or len(s) < 8: return 0.0
    freq = Counter(s); n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

findings  = []
api_paths = set()
seen_sigs = set()

for fpath in glob.glob(os.path.join(js_cache, '*.js')):
    try: content = open(fpath, errors='ignore').read()
    except: continue

    for m in re.finditer(r'"(/(?:api|v[0-9]+)/[^"]{3,80})"', content):
        api_paths.add(m.group(1))

    for label, pattern in PATTERNS:
        for match in re.finditer(pattern, content):
            raw = match.group(0)
            if any(fp in raw.lower() for fp in IGNORE_VALUES): continue
            # Generic patterns: entropy-gate the extracted value
            if 'Generic' in label or 'Broad' in label or 'Password' in label:
                val_match = re.search(r'["\']([ A-Za-z0-9\-_\.!@#$%^&*]{8,})["\']', raw)
                if val_match:
                    if shannon_entropy(val_match.group(1)) < 3.5: continue
                else: continue
            # High-entropy catch-all: strip quotes, require non-alpha chars and high entropy
            if label == 'High-Entropy String':
                val = raw.strip('\"\' ')
                if len(val) < 32: continue
                if shannon_entropy(val) < 4.5: continue  # strict threshold
                # Must contain digits or special chars — pure camelCase strings are not secrets
                if not re.search(r'[0-9+/=_\-]', val): continue
                # Skip if it looks like a camelCase identifier (mostly alpha)
                alpha_ratio = sum(c.isalpha() for c in val) / len(val)
                if alpha_ratio > 0.85: continue
                # Skip ASP.NET __VIEWSTATE / __EVENTVALIDATION fields — always high-entropy, never secrets
                start_ctx = max(0, match.start()-120)
                pre_context = content[start_ctx:match.start()].lower()
                if any(p in pre_context for p in IGNORE_CONTEXT_PATTERNS): continue
            sig = label + raw[:30]
            if sig in seen_sigs: continue
            seen_sigs.add(sig)
            start = max(0, match.start()-60); end = min(len(content), match.end()+60)
            context = content[start:end].replace('\n', ' ').strip()
            findings.append(f'[{label}]\n  Match   : {raw}\n  Context : ...{context[:200]}...\n  File    : {os.path.basename(fpath)}\n')

    # Broad old-style sweep — catches patterns the typed list misses
    for label, pattern in BROAD_PATTERNS:
        for match in re.finditer(pattern, content):
            raw = match.group(0)
            if any(fp in raw.lower() for fp in IGNORE_VALUES): continue
            # Must have a high-entropy value after the = or :
            val_match = re.search(r'[:=][\s]*["\']?([A-Za-z0-9+/]{20,})["\']?', raw)
            if not val_match: continue
            if shannon_entropy(val_match.group(1)) < 3.5: continue
            sig = 'BROAD' + raw[:30]
            if sig in seen_sigs: continue
            seen_sigs.add(sig)
            start = max(0, match.start()-60); end = min(len(content), match.end()+60)
            context = content[start:end].replace('\n', ' ').strip()
            findings.append(f'[{label}]\n  Match   : {raw}\n  Context : ...{context[:200]}...\n  File    : {os.path.basename(fpath)}\n')

with open(secrets_file, 'w') as f:
    f.write('\n'.join(findings) if findings else 'No secrets found.\n')

existing_api = set()
if os.path.exists(api_file):
    existing_api = set(open(api_file).read().splitlines())
all_api = existing_api | api_paths
with open(api_file, 'w') as f:
    f.write('\n'.join(sorted(all_api)) if all_api else '')

PYEOF_SECRETS

    # Deduplicate api_endpoints
    sort -u "$api_endpoints" -o "$api_endpoints" 2>/dev/null || true

    local api_count secrets_count
    api_count=$(grep -c '.' "$api_endpoints" 2>/dev/null | tr -d ' '); api_count=${api_count:-0}
    secrets_count=$(grep -c "^\[" "$secrets_file" 2>/dev/null | tr -d ' '); secrets_count=${secrets_count:-0}

    if [[ "$api_count" -gt 0 ]]; then
      warn "API endpoints found in JS: $api_count"
      head -10 "$api_endpoints" | while read -r l; do result "  $l"; done
    fi
    if [[ "$secrets_count" -gt 0 ]]; then
      warn "Potential secrets in JS: $secrets_count (verify before reporting)"
      # Print findings separated by blank lines, up to 10
      local _shown=0
      local _in_finding=false
      while IFS= read -r l; do
        if [[ "$l" =~ ^\[ ]]; then
          [[ $_shown -ge 10 ]] && break
          _shown=$((_shown + 1))
        fi
        warn "  $l"
      done < "$secrets_file"
      if [[ "$secrets_count" -gt 10 ]]; then
        warn "  ... and $((secrets_count - 10)) more — see report"
      fi
    fi
    if [[ "$api_count" -eq 0 && "$secrets_count" -eq 0 ]]; then
      info "No secrets or API endpoints found in JS bundles"
    fi
    fi  # end cached_count check
  fi
}


# ================================================================
#  MODULE: BROKEN ACCESS CONTROL CHECK
# ================================================================




# ================================================================
#  MODULE: SUBDOMAIN TAKEOVER CHECK
# ================================================================

run_takeover() {
  module_enabled "takeover" || return
  [[ -z "$DOMAIN" ]] && return

  # Build subdomain list from ALL sources
  local sub_list="${OUT_DIR}/all_subdomains_takeover.txt"
  > "$sub_list"
  [[ -f "${OUT_DIR}/subdomains_found.txt" ]]              && cat "${OUT_DIR}/subdomains_found.txt" >> "$sub_list"
  [[ -f "${OUT_DIR}/ct_subdomains.txt"    ]]              && cat "${OUT_DIR}/ct_subdomains.txt"    >> "$sub_list"
  [[ -f "${OUT_DIR}/subfinder.txt"        ]]              && cat "${OUT_DIR}/subfinder.txt"        >> "$sub_list"
  [[ -f "${OUT_DIR}/subdomains_permutations_resolved.txt" ]] &&     cat "${OUT_DIR}/subdomains_permutations_resolved.txt" >> "$sub_list"
  [[ -f "${OUT_DIR}/httpx_results.txt"    ]] &&     grep -oE 'https?://[^ ]+' "${OUT_DIR}/httpx_results.txt" 2>/dev/null     | sed 's|https\?://||; s|/.*||' >> "$sub_list"
  echo "$DOMAIN" >> "$sub_list"
  sort -u "$sub_list" -o "$sub_list"

  local count
  count=$(wc -l < "$sub_list" | tr -d ' ')
  [[ "$count" -eq 0 ]] && return

  section "Subdomain Takeover Check"
  info "Checking $count subdomains..."

  mkdir -p "${OUT_DIR}/takeover"
  > "${OUT_DIR}/takeover/takeover.txt"

  # ── Fingerprints: service name → body string ──────────────────────
  # Format: "Service|fingerprint string"
  local fingerprints=(
    "Heroku|There is no app here"
    "Heroku|No such app"
    "Heroku|herokucdn.com/error-pages"
    "GitHub Pages|There isn't a GitHub Pages site here"
    "GitHub Pages|Repository not found"
    "GitHub Pages|For root URLs"
    "Tumblr|Whatever you were looking for doesn't live here"
    "Tumblr|The site you were looking for"
    "UserVoice|This UserVoice subdomain"
    "Zendesk|Help Center Closed"
    "Zendesk|Oops, this help center no longer exists"
    "Fastly|Fastly error: unknown domain"
    "Fastly|Please check that this domain has been added"
    "CloudFront|The request could not be satisfied"
    "CloudFront|ERROR: The request could not be satisfied"
    "AWS S3|NoSuchBucket"
    "AWS S3|The specified bucket does not exist"
    "Shopify|Sorry, this shop is currently unavailable"
    "Shopify|Only one step left"
    "Ghost|The thing you were looking for is no longer here"
    "Cargo|If you're moving your domain away from Cargo"
    "Surge.sh|project not found"
    "Surge.sh|No such file or directory"
    "Pantheon|The gods are wise"
    "WP Engine|The site you were looking for couldn't be found"
    "WP Engine|No such app"
    "StatusPage|You are being redirected"
    "Unbounce|The page you are looking for is currently unavailable"
    "HubSpot|does not exist in our system"
    "Agile CRM|Sorry, this page is no longer available"
    "Netlify|Not Found - Request ID"
    "Webflow|The page you are looking for doesn't exist"
    "Bitbucket|Repository not found"
    "Intercom|Uh oh. That page doesn't exist"
    "Intercom|App not found"
    "Campaign Monitor|Double check the URL"
    "Squarespace|No Such Account"
    "Azure|This web app is stopped"
    "Azure|404 Web Site not found"
    "Domain not configured|Domain not configured"
  )

  local hits=0
  local nxdomain_hits=0
  local _tk_total; _tk_total=$(wc -l < "$sub_list" | tr -d ' ')
  local _tk_done=0
  local _tk_start; _tk_start=$(date +%s)
  printf "  \033[0;36m[→]\033[0m Takeover check"

  while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    _tk_done=$((_tk_done + 1))
    local _tk_elapsed=$(( $(date +%s) - _tk_start ))
    printf "\r  \033[0;36m[→]\033[0m Takeover check \033[2m%d/%d — %ds\033[0m\033[K" \
      "$_tk_done" "$_tk_total" "$_tk_elapsed"

    # ── Step 1: DNS check — NXDOMAIN = strong takeover signal ──
    local resolves
    # Check A records — also follow CNAME chains by using +short which resolves them
    resolves=$(dig +short A "$sub" @1.1.1.1 +time=3 +tries=1 2>/dev/null \
      | grep -E '^[0-9]' | head -1 || true)
    # Also accept if subdomain has a valid CNAME that resolves
    if [[ -z "$resolves" ]]; then
      local _cname_check
      _cname_check=$(dig +short CNAME "$sub" @1.1.1.1 +time=3 +tries=1 2>/dev/null \
        | grep -vE '^;;|NXDOMAIN' | sed 's/\.//' | head -1 || true)
      if [[ -n "$_cname_check" ]]; then
        resolves=$(dig +short A "$_cname_check" @1.1.1.1 +time=3 +tries=1 2>/dev/null \
          | grep -E '^[0-9]' | head -1 || true)
      fi
    fi

    if [[ -z "$resolves" ]]; then
      # Check if it has a CNAME pointing somewhere (dangling CNAME)
      local cname
      cname=$(dig +short CNAME "$sub" @1.1.1.1 +time=2 +tries=1 2>/dev/null         | grep -vE '^;;|NXDOMAIN|no servers' | sed 's/\.$//' | head -1 || true)
      if [[ -n "$cname" ]]; then
        local cname_resolves
        cname_resolves=$(dig +short A "$cname" @1.1.1.1 +time=2 +tries=1 2>/dev/null           | grep -E '^[0-9]' | head -1 || true)
        # Skip known CDN private DNS that legitimately dont resolve via public DNS
        if echo "$cname" | grep -qiE "impervadns\.net|incapsula\.com|cloudflare\.net$|akamaiedge\.net|fastly\.net$"; then
          continue
        fi
        if [[ -z "$cname_resolves" ]]; then
          printf "\033[2K\r"
          warn "Dangling CNAME: $sub → $cname (does not resolve) — HIGH takeover risk"
          echo "$sub | DANGLING CNAME → $cname" >> "${OUT_DIR}/takeover/takeover.txt"
          ((hits++)); ((nxdomain_hits++))
          continue
        fi
      else
        # No A record, no CNAME — skip HTTP check
        continue
      fi
    fi

    # ── Step 2: HTTP body fingerprint check (https + http) ──
    local body=""
    body=$(curl -sk --max-time 8 "https://$sub" 2>/dev/null | head -c 8000 || true)
    [[ -z "$body" ]] &&       body=$(curl -sk --max-time 8 "http://$sub" 2>/dev/null | head -c 8000 || true)

    [[ -z "$body" ]] && continue

    for fp_entry in "${fingerprints[@]}"; do
      local service="${fp_entry%%|*}"
      local fp="${fp_entry##*|}"
      if echo "$body" | grep -qi "$fp"; then
        printf "\033[2K\r"
        warn "Potential takeover [$service]: $sub"
        warn "  Fingerprint: '$fp'"
        echo "$sub | $service | $fp" >> "${OUT_DIR}/takeover/takeover.txt"
        ((hits++))
        break
      fi
    done
  done < "$sub_list"
  printf "\033[2K\r"

  if [[ "$hits" -gt 0 ]]; then
    warn "$hits potential takeover(s) found ($nxdomain_hits dangling CNAME) — see ${OUT_DIR}/takeover/takeover.txt"
    cat "${OUT_DIR}/takeover/takeover.txt" | while IFS= read -r l; do result "  $l"; done
  else
    info "No subdomain takeover indicators found"
  fi
}


# ================================================================
#  MODULE: HTTPX - HTTP PROBING ON SUBDOMAINS
# ================================================================

run_httpx() {
  module_enabled "httpx" || return
  [[ -z "$DOMAIN" ]] && return
  # Find ProjectDiscovery httpx - check Go bin dirs first, then verify with help output
  # ProjectDiscovery httpx has -silent, -status-code, -tech-detect flags; Python httpx does not
  local httpx_bin=""
  for _candidate in "$HOME/go/bin/httpx" "/root/go/bin/httpx" "/home/kali/go/bin/httpx" "/usr/local/go/bin/httpx" "/usr/local/bin/httpx"; do
    if [[ -x "$_candidate" ]]; then
      local _help; _help=$("$_candidate" -h 2>&1 || true)
      if echo "$_help" | grep -qE "status-code|tech-detect|input-list|silent.*flag"; then
        httpx_bin="$_candidate"
        break
      fi
    fi
  done
  # Scan all httpx in PATH as fallback
  if [[ -z "$httpx_bin" ]]; then
    while IFS= read -r _candidate; do
      if [[ -x "$_candidate" ]]; then
        local _help; _help=$("$_candidate" -h 2>&1 || true)
        if echo "$_help" | grep -qE "status-code|tech-detect|input-list"; then
          httpx_bin="$_candidate"
          break
        fi
      fi
    done < <(which -a httpx 2>/dev/null || true)
  fi
  if [[ -z "$httpx_bin" ]]; then
    skip "httpx ProjectDiscovery version not found - install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    return
  fi

  section "HTTP Probing (httpx)"

  # Build combined subdomain list
  local sub_list="${OUT_DIR}/all_subdomains.txt"
  > "$sub_list"
  [[ -f "${OUT_DIR}/subdomains_found.txt" ]] && cat "${OUT_DIR}/subdomains_found.txt" >> "$sub_list"
  [[ -f "${OUT_DIR}/ct_subdomains.txt"    ]] && cat "${OUT_DIR}/ct_subdomains.txt"    >> "$sub_list"
  [[ -f "${OUT_DIR}/subfinder.txt"        ]] && cat "${OUT_DIR}/subfinder.txt"        >> "$sub_list"
  echo "$DOMAIN" >> "$sub_list"
  sort -u "$sub_list" -o "$sub_list"

  local sub_count
  sub_count=$(wc -l < "$sub_list" | tr -d ' ')
  sub_count=${sub_count:-0}

  if [[ "$sub_count" -eq 0 ]]; then
    info "httpx: no subdomains to probe"
    return
  fi

  local httpx_out="${OUT_DIR}/httpx_results.txt"

  # Run httpx directly (not via run_timed) - run_timed suppresses stdout which breaks -o flag
  local httpx_start httpx_elapsed
  httpx_start=$(date +%s)
  local httpx_err="${OUT_DIR}/httpx_error.txt"
  timeout 300 "$httpx_bin" \
    -l "$sub_list" \
    -title \
    -status-code \
    -ip \
    -follow-redirects \
    -timeout 10 \
    -retries 1 \
    -threads 50 \
    -silent \
    -o "$httpx_out" \
    2>"$httpx_err" >/dev/null &
  local httpx_pid=$!

  printf "  \033[0;36m[→]\033[0m httpx probing $sub_count hosts"
  local httpx_tick=0
  while kill -0 "$httpx_pid" 2>/dev/null; do
    sleep 5; httpx_tick=$((httpx_tick + 5))
    kill -0 "$httpx_pid" 2>/dev/null && \
      printf "\r  \033[0;36m[→]\033[0m httpx probing $sub_count hosts \033[2m%ds\033[0m\033[K" "$httpx_tick"
  done
  wait "$httpx_pid" 2>/dev/null || true
  printf "\r\033[2K"
  httpx_elapsed=$(( $(date +%s) - httpx_start ))
  info "httpx probing $sub_count hosts - done (${httpx_elapsed}s)"

  if [[ ! -f "$httpx_out" ]] || [[ ! -s "$httpx_out" ]]; then
    if [[ -f "$httpx_err" ]] && [[ -s "$httpx_err" ]]; then
      warn "httpx: no results — error output:"
      head -3 "$httpx_err" | while read -r l; do result "  $l"; done
    else
      warn "httpx: no results — all hosts may be down, blocking, or HTTPS-only on non-standard ports"
      info "Tip: check if hosts respond manually: curl -Lsk https://$DOMAIN -o /dev/null -w '%{http_code}'"
    fi
    return
  fi

  local alive_count
  alive_count=$(wc -l < "$httpx_out" | tr -d ' ')
  alive_count=${alive_count:-0}
  info "Live hosts: $alive_count"

  # Format httpx results - show URL, status, title only (truncate tech list)
  cat "$httpx_out" | while IFS= read -r l; do
    # Extract URL, status code, title - truncate at 120 chars
    local url status title
    url=$(echo "$l" | awk '{print $1}')
    status=$(echo "$l" | grep -oE '\[[0-9,]+\]' | head -1)
    title=$(echo "$l" | grep -oE '\[([^\]]{1,50})\]' | tail -1)
    local display="${url} ${status} ${title}"
    if echo "$url" | grep -qiE "admin|jenkins|grafana|kibana|jira|gitlab|phpmyadmin|wp-admin|swagger|api"; then
      warn "  ${display:0:120}"
    else
      result "  ${display:0:120}"
    fi
  done
}





# ================================================================
#  MODULE: SOCIAL ENGINEERING INTEL
# ================================================================

run_social_intel() {
  module_enabled "social" || return
  [[ -z "$DOMAIN" ]] && return

  section "Social Engineering Intel"

  local apex; apex=$(get_apex_domain "$DOMAIN" | awk -F. '{print $1}')
  # Convert domain name to readable company name - handle hyphens and compound words
  local company
  company=$(echo "$apex" | sed 's/-/ /g; s/_/ /g' | python3 -c "
import sys, re
raw = sys.stdin.read().strip()
# Insert space before capital letters in camelCase
raw = re.sub(r'([a-z])([A-Z])', r'\1 \2', raw)
print(raw.title())
")

  info "Gathering OSINT for: $company ($DOMAIN)"

  # ── LinkedIn via Google dork ──
  printf "  \033[0;36m[→]\033[0m LinkedIn employee search...\r"
  local li_results
  li_results=$(curl -s --max-time 10 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "https://www.google.com/search?q=site:linkedin.com+%22${apex}%22+employees&num=10" \
    2>/dev/null \
    | grep -oE '"https://www\.linkedin\.com/in/[^"]*"' \
    | sed 's/"//g' | sort -u | head -10 || true)
  printf "\r\033[2K"
  if [[ -n "$li_results" ]]; then
    info "LinkedIn profiles found:"
    echo "$li_results" | while IFS= read -r l; do result "  $l"; done

  else
    info "LinkedIn: no results (Google may have blocked)"
  fi

  # ── Tech stack from scan results (WhatWeb, httpx, headers) ──
  info "Tech stack analysis from scan data..."
  local tech_results=""
  local tech_pat="WordPress|WooCommerce|Shopify|BigCommerce|Magento|PHP|nginx|Apache|IIS|jQuery|React|Angular|Vue|Bootstrap|Laravel|Django|Ruby on Rails|Node\.js|Cloudflare|Fastly|Akamai|Varnish|AWS|Azure|GCP|DataDome|Imperva|Sucuri|Barracuda|Netlify|Vercel|Heroku|OpenResty|Caddy|Litespeed|Express|Next\.js|Nuxt|Gatsby|Hugo|BentoBox|Squarespace|Wix|Webflow|Drupal|Joomla|PrestaShop|OpenCart|osCommerce|Contentful|Sanity|HubSpot|Salesforce|Zendesk|Intercom|Hotjar|Segment|Mixpanel|Marketo|Pardot|Klaviyo|Braintree|Stripe|PayPal"
  # From WhatWeb output
  if [[ -f "${OUT_DIR}/whatweb.txt" ]]; then
    tech_results+=$(grep -oiE "$tech_pat" "${OUT_DIR}/whatweb.txt" 2>/dev/null || true)
    # Also extract PoweredBy values directly
    tech_results+=$'\n'
    tech_results+=$(grep -oiE "PoweredBy\[[^]]+\]" "${OUT_DIR}/whatweb.txt" 2>/dev/null | sed "s/PoweredBy\[//;s/\]//" || true)
    tech_results+=$'\n'
  fi
  # From httpx results
  if [[ -f "${OUT_DIR}/httpx_results.txt" ]]; then
    tech_results+=$(grep -oiE "$tech_pat" "${OUT_DIR}/httpx_results.txt" 2>/dev/null || true)
    tech_results+=$'\n'
  fi
  # From web headers - server, powered-by, via, x-generator
  if [[ -f "${OUT_DIR}/web_headers.txt" ]]; then
    tech_results+=$(grep -iE "^\s*(server|x-powered-by|via|x-generator|x-platform|powered-by):" \
      "${OUT_DIR}/web_headers.txt" 2>/dev/null \
      | grep -oiE "$tech_pat" || true)
    tech_results+=$'\n'
  fi
  # From raw headers in terminal output (wafw00f, WhatWeb)
  tech_results+=$(grep -oiE "$tech_pat" "${OUT_DIR}/wafw00f.txt" 2>/dev/null || true)
  tech_results+=$'\n'
  # From TXT records - detect Klaviyo, Marketo etc
  tech_results+=$(dig +short TXT "$DOMAIN" @1.1.1.1 2>/dev/null \
    | grep -oiE "klaviyo|hubspot|marketo|mailchimp|sendgrid|sparkpost|mandrill|mailgun|salesforce|zendesk|intercom|drift|hotjar|segment|mixpanel" || true)

  local stack_summary
  stack_summary=$(echo "$tech_results" | tr '[:upper:]' '[:lower:]' | grep -vE "^$" | sort | uniq -c | sort -rn | head -10)
  if [[ -n "$stack_summary" ]]; then
    info "Detected tech stack:"
    echo "$stack_summary" | while IFS= read -r l; do result "  $l"; done

  else
    info "Tech stack: not detected from scan data"
  fi

  # ── Email format discovery ──
  printf "  \033[0;36m[→]\033[0m Email format discovery...\r"
  # Check hunter.io (no API needed for basic format)
  local hunter_out
  hunter_out=$(curl -s --max-time 10 \
    "https://hunter.io/email-finder?domain=$DOMAIN" 2>/dev/null \
    | grep -oE "(first|last|first\.last|first_last|f\.last|flast)\." \
    | sort | uniq -c | sort -rn | head -3 || true)
  printf "\r\033[2K"
  if [[ -n "$hunter_out" ]]; then
    info "Likely email format:"
    echo "$hunter_out" | while IFS= read -r l; do result "  $l"; done
  fi

  # Generate likely email formats from harvested names
  if [[ -f "${OUT_DIR}/emails/emails.txt" ]]; then
    local email_count; email_count=$(wc -l < "${OUT_DIR}/emails/emails.txt" | tr -d ' ')
    info "Known emails: $email_count - see ${OUT_DIR}/emails/emails.txt"
    info "Tip: use these to guess format (firstname.lastname@$DOMAIN etc)"
  fi

  # ── Shodan/Censys org search ──
  info "Social intel - manual research links:"
  result "  LinkedIn: https://www.linkedin.com/search/results/people/?keywords=${apex}"
  result "  Hunter.io: https://hunter.io/domain-search/${DOMAIN}"
  result "  Crunchbase: https://www.crunchbase.com/search/organizations/field/organizations/name/${apex}"
}

# ================================================================
#  MODULE: CLOUD STORAGE ENUMERATION (S3/GCS/Azure)
# ================================================================

run_cloud_enum() {
  module_enabled "cloud" || return
  [[ -z "$DOMAIN" ]] && return

  section "Cloud Storage Enumeration"

  local apex; apex=$(get_apex_domain "$DOMAIN" | awk -F. '{print $1}')
  # Expanded variant list — hyphenated, no-hyphen, and common suffixes
  local variants=(
    "$apex"
    "${apex}-dev"       "${apex}-prod"      "${apex}-staging"   "${apex}-backup"
    "${apex}-assets"    "${apex}-static"    "${apex}-media"     "${apex}-data"
    "${apex}-uploads"   "${apex}-files"     "${apex}-logs"      "${apex}-api"
    "${apex}-cdn"       "${apex}-images"    "${apex}-public"    "${apex}-www"
    "${apex}-store"     "${apex}-storage"   "${apex}-archive"   "${apex}-web"
    "${apex}assets"     "${apex}static"     "${apex}media"      "${apex}cdn"
    "${apex}images"     "${apex}public"     "${apex}uploads"    "${apex}files"
  )

  local _total_variants=${#variants[@]}
  local _done=0
  local _cl_start; _cl_start=$(date +%s)
  local found=0
  local private_found=0
  info "Checking ${_total_variants} cloud storage name variants..."
  printf "  \033[0;36m[→]\033[0m Cloud enum"

  for name in "${variants[@]}"; do
    _done=$((_done + 1))
    local _cl_elapsed=$(( $(date +%s) - _cl_start ))
    printf "\r  \033[0;36m[→]\033[0m Cloud enum \033[2m%d/%d — %ds\033[0m\033[K" \
      "$_done" "$_total_variants" "$_cl_elapsed"

    # ── S3 virtual-hosted style ──
    local s3_url="https://${name}.s3.amazonaws.com"
    local s3_status; s3_status=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$s3_url" 2>/dev/null || echo "000")
    if [[ "$s3_status" == "200" ]]; then
      printf "\r\033[2K"
      warn "S3 bucket PUBLIC: $s3_url"
      # Try to list bucket contents
      local s3_contents
      s3_contents=$(curl -sk --max-time 8 "$s3_url" 2>/dev/null         | grep -oE '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g' | head -10 || true)
      if [[ -n "$s3_contents" ]]; then
        warn "  Bucket contents (first 10 files):"
        echo "$s3_contents" | while read -r f; do result "    $f"; done
      fi
      ((found++))
    elif [[ "$s3_status" == "403" ]]; then
      printf "\r\033[2K"; info "S3 bucket exists (private): $s3_url"
      ((private_found++))
    fi

    # ── S3 path style ──
    local s3p_url="https://s3.amazonaws.com/${name}"
    local s3p_status; s3p_status=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$s3p_url" 2>/dev/null || echo "000")
    if [[ "$s3p_status" == "200" ]]; then
      printf "\r\033[2K"
      warn "S3 bucket PUBLIC (path-style): $s3p_url"
      local s3p_contents
      s3p_contents=$(curl -sk --max-time 8 "$s3p_url" 2>/dev/null         | grep -oE '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g' | head -10 || true)
      if [[ -n "$s3p_contents" ]]; then
        warn "  Bucket contents (first 10 files):"
        echo "$s3p_contents" | while read -r f; do result "    $f"; done
      fi
      ((found++))
    elif [[ "$s3p_status" == "403" ]]; then
      printf "\r\033[2K"; info "S3 bucket exists (private, path-style): $s3p_url"
      ((private_found++))
    fi

    # ── GCS ──
    local gcs_url="https://storage.googleapis.com/${name}"
    local gcs_status; gcs_status=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$gcs_url" 2>/dev/null || echo "000")
    if [[ "$gcs_status" == "200" ]]; then
      printf "\r\033[2K"
      warn "GCS bucket PUBLIC: $gcs_url"
      local gcs_contents
      gcs_contents=$(curl -sk --max-time 8 "$gcs_url" 2>/dev/null         | grep -oE '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g' | head -10 || true)
      if [[ -n "$gcs_contents" ]]; then
        warn "  Bucket contents (first 10 files):"
        echo "$gcs_contents" | while read -r f; do result "    $f"; done
      fi
      ((found++))
    elif [[ "$gcs_status" == "403" ]]; then
      printf "\r\033[2K"; info "GCS bucket exists (private): $gcs_url"
      ((private_found++))
    fi

    # ── Azure Blob — only report 200, skip 400 (false positive) ──
    local az_url="https://${name}.blob.core.windows.net"
    local az_status; az_status=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$az_url" 2>/dev/null || echo "000")
    if [[ "$az_status" == "200" ]]; then
      printf "\r\033[2K"; warn "Azure blob PUBLIC: $az_url"
      ((found++))
    fi

    # ── DigitalOcean Spaces ──
    # ── DigitalOcean Spaces — check all regions in parallel ──
    local _do_result=""
    local _do_pids=()
    local _do_tmp; _do_tmp=$(mktemp -d)
    for do_region in nyc3 ams3 sgp1 fra1 sfo2 sfo3 tor1 blr1; do
      local do_url="https://${name}.${do_region}.digitaloceanspaces.com"
      ( status=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$do_url" 2>/dev/null || echo "000")
        echo "$status $do_url $do_region" > "$_do_tmp/$do_region" ) &
      _do_pids+=($!)
    done
    for _pid in "${_do_pids[@]}"; do wait "$_pid" 2>/dev/null || true; done
    for do_region in nyc3 ams3 sgp1 fra1 sfo2 sfo3 tor1 blr1; do
      [[ -f "$_do_tmp/$do_region" ]] || continue
      local _do_line; _do_line=$(cat "$_do_tmp/$do_region")
      local _do_st="${_do_line%% *}"
      local _do_url="${_do_line#* }"; _do_url="${_do_url% *}"
      if [[ "$_do_st" == "200" ]]; then
        printf "\r\033[2K"; warn "DigitalOcean Space PUBLIC: $_do_url"
        ((found++)); break
      elif [[ "$_do_st" == "403" ]]; then
        printf "\r\033[2K"; info "DigitalOcean Space exists (private): $_do_url"
        ((private_found++)); break
      fi
    done
    rm -rf "$_do_tmp"
  done
  printf "\033[2K\r"

  # Summary of private buckets found
  local private_count=0
  [[ -f "${OUT_DIR}/js/cloud_storage.txt" ]] &&     private_count=$(grep -c "private" "${OUT_DIR}/js/cloud_storage.txt" 2>/dev/null | tr -d ' ' || echo 0)

  # Also check URLs found by gau/waybackurls
  if [[ -f "${OUT_DIR}/js/cloud_storage.txt" ]] && [[ -s "${OUT_DIR}/js/cloud_storage.txt" ]]; then
    local cloud_count; cloud_count=$(wc -l < "${OUT_DIR}/js/cloud_storage.txt" | tr -d ' ')
    warn "Cloud storage URLs from URL discovery: $cloud_count (see report)"
    head -10 "${OUT_DIR}/js/cloud_storage.txt" | while IFS= read -r l; do result "  $l"; done
    found=$((found + cloud_count))
  fi

  if [[ "$found" -gt 0 && "$private_found" -gt 0 ]]; then
    warn "Cloud storage: $found public + $private_found private bucket(s) found"
  elif [[ "$found" -gt 0 ]]; then
    warn "Cloud storage: $found public bucket(s) found (see report)"
  elif [[ "$private_found" -gt 0 ]]; then
    info "Cloud storage: no public buckets — $private_found private bucket(s) identified"
  else
    info "Cloud storage: no buckets found"
  fi
}

# ================================================================
#  MODULE: GOOGLE DORKING
# ================================================================

run_google_dorks() {
  module_enabled "dorks" || return
  [[ -z "$DOMAIN" ]] && return

  section "Google Dorks"
  mkdir -p "${OUT_DIR}/dorks"

  # Generate dork queries - print them for manual use
  # Also try via curl to Google (rate-limited, best effort)
  local dorks=(
    "site:$DOMAIN filetype:pdf"
    "site:$DOMAIN filetype:xls OR filetype:xlsx OR filetype:csv"
    "site:$DOMAIN filetype:sql OR filetype:db OR filetype:bak"
    "site:$DOMAIN inurl:admin OR inurl:login OR inurl:dashboard"
    "site:$DOMAIN intitle:\"index of\""
    "site:$DOMAIN inurl:config OR inurl:env OR inurl:backup"
    "site:$DOMAIN inurl:api OR inurl:v1 OR inurl:v2"
    "site:$DOMAIN \"password\" OR \"credentials\" OR \"secret\""
    "\"@$DOMAIN\" email"
    "site:pastebin.com \"$DOMAIN\""
    "site:github.com \"$DOMAIN\" password OR secret OR token"
    "site:trello.com \"$DOMAIN\""
  )

  info "Generated ${#dorks[@]} Google dork queries"
  info "Copy and search manually at https://google.com or https://dorks.fyi"
  echo "" > "${OUT_DIR}/dorks/dorks.txt"

  for dork in "${dorks[@]}"; do
    result "  $dork"
    echo "$dork" >> "${OUT_DIR}/dorks/dorks.txt"
  done

  # Try automated search via Google (best effort, often blocked)
  local google_hits=0
  info "Attempting automated dork queries (may be blocked by Google)..."
  for dork in "${dorks[@]:0:4}"; do  # Only try first 4 to avoid rate limiting
    local encoded_dork; encoded_dork=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$dork'))" 2>/dev/null)
    local results
    results=$(curl -s --max-time 10 \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "https://www.google.com/search?q=${encoded_dork}&num=10" 2>/dev/null \
      | grep -oE 'href="https?://[^"]*'"$DOMAIN"'[^"]*"' \
      | sed 's/href="//; s/"//' \
      | grep -v "google\|webcache" \
      | sort -u | head -5 || true)
    if [[ -n "$results" ]]; then
      warn "Dork results for: $dork"
      echo "$results" | while IFS= read -r r; do result "  $r"; done

      ((google_hits++))
    fi
    sleep 2  # Avoid Google rate limiting
  done

  if [[ "$google_hits" -eq 0 ]]; then
    info "Automated queries blocked - use dorks.txt for manual searching"
  fi

  info "Dork queries generated - included in report"
}
