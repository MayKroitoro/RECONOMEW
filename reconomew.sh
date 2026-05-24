#!/usr/bin/env bash
# RECONOMEW v1.0 — Professional Reconnaissance Framework
# For authorised testing only

# ── Bash version check ──
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "ERROR: RECONOMEW requires bash 4.0 or higher (you have bash ${BASH_VERSION})"
  echo "Install: sudo apt install bash  OR  brew install bash"
  exit 1
fi

# Ensure Go binaries are in PATH
export PATH="$PATH:$HOME/go/bin:/home/kali/go/bin:/root/go/bin:/usr/local/go/bin"
# Prevent any single command failure from killing the script
trap '' ERR

set -uo pipefail
IFS=$'\n\t'

# ── Resolve the directory this script lives in (works with symlinks) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Source all modules ──
source "${SCRIPT_DIR}/modules/utils.sh"
source "${SCRIPT_DIR}/modules/passive_recon.sh"
source "${SCRIPT_DIR}/modules/asn_email.sh"
source "${SCRIPT_DIR}/modules/web_recon.sh"
source "${SCRIPT_DIR}/modules/osint.sh"
source "${SCRIPT_DIR}/modules/active_scan.sh"
source "${SCRIPT_DIR}/modules/report.sh"

# ── Entry point ──
main() {
  # Parse CLI args
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain)   DOMAIN="${2//[[:space:]]/}";       shift 2 ;;
      -i|--ip)       IP="${2//[[:space:]]/}";           shift 2 ;;
      --no-active)   ACTIVE=false;      shift   ;;
      --quick)       QUICK=true; ACTIVE=false; shift ;;
      --only)        ONLY_MODULES="$2"; shift 2 ;;
      --threads)     THREADS="$2";      shift 2 ;;
      --wordlist)    WORDLIST_DIRS="$2";shift 2 ;;
      --output)      OUT_DIR="$2";      shift 2 ;;
      --version)
        echo "RECONOMEW v1.0"
        exit 0
        ;;
      -h|--help)
        echo ""
        echo "  RECONOMEW v1.0 — Professional Reconnaissance Framework"
        echo "  Usage: bash RECONOMEW_1_0.sh [options]"
        echo ""
        echo "  Options:"
        echo "    -d <domain>      Target domain"
        echo "    -i <ip>          Target IP address"
        echo "    --quick          Quick mode (~2 min) — WHOIS, DNS, TLS, headers only"
        echo "    --no-active      Passive only — no nmap, dirsearch, wpscan"
        echo "    --only <mods>    Run specific modules (comma separated)"
        echo "    --threads <n>    Thread count (default: 50)"
        echo "    --wordlist <f>   Custom directory wordlist"
        echo "    --output <dir>   Custom output directory"
        echo "    --version        Show version"
        echo "    --help           Show this help"
        echo ""
        echo "  Examples:"
        echo "    bash RECONOMEW_1_0.sh -d example.com"
        echo "    bash RECONOMEW_1_0.sh -d example.com --quick"
        echo "    bash RECONOMEW_1_0.sh -d example.com --no-active"
        echo "    bash RECONOMEW_1_0.sh -d example.com --only whois,dns,tls"
        echo "    bash RECONOMEW_1_0.sh -d example.com --only nmap,dirsearch"
        echo ""
        echo "  Available modules:"
        echo "    whois, dns, tls, web-headers, ct, subdomains, httpx,"
        echo "    takeover, asn, email-security, shodan, securitytrails,"
        echo "    email-harvest, social, js-discovery, cloud, leaks,"
        echo "    dorks, nmap, dirsearch, wpscan"

        echo ""
        exit 0 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$DOMAIN" && -z "$IP" ]]; then
    interactive_input
  else
    banner
    check_dependencies
    if [[ -n "$DOMAIN" && -z "$IP" ]]; then
      IP=$(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
      [[ -n "$IP" ]] && info "Auto-resolved IP: ${W}$IP${NC}"
    fi
  fi

  setup_output

  # ── IP -> Domain resolution ──
  # If only IP given, try multiple methods to find the real hostname.
  # If found, use it as DOMAIN so ALL domain-based tools activate.
  if [[ -n "$IP" && -z "$DOMAIN" ]]; then
    info "IP-only mode - attempting to resolve hostname from IP..."

    # Method 1: reverse DNS (PTR record)
    local resolved_domain=""
    resolved_domain=$(dig +short -x "$IP" @1.1.1.1 2>/dev/null       | grep -vE "^;;|communications error|timed out|NXDOMAIN|no servers"       | grep -E "^[a-zA-Z0-9]"       | sed 's/\.$//' | head -1 || true)

    # Method 2: SSL certificate CN/SAN (most reliable for CDN-fronted IPs)
    if [[ -z "$resolved_domain" ]]; then
      resolved_domain=$(echo | timeout 8 openssl s_client \
        -connect "$IP:443" -quiet 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | grep -oE "CN\s*=\s*[^,/]+" | head -1 | sed 's/CN\s*=\s*//' | sed 's/^\*//' | sed 's/^\.//' || true)
    fi

    # Method 3: HTTP Host header response - check what the server calls itself
    if [[ -z "$resolved_domain" ]]; then
      resolved_domain=$(curl -sI --max-time 8 "http://$IP" 2>/dev/null \
        | grep -i "^location:\|^x-redirect-to:\|^x-canonical" \
        | grep -oE "https?://[^/]+" | sed 's|https\?://||' | head -1 || true)
    fi

    # Method 4: ipinfo.io hostname field
    if [[ -z "$resolved_domain" ]]; then
      resolved_domain=$(curl -s --max-time 8 "https://ipinfo.io/$IP/json" 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('hostname',''))" 2>/dev/null || true)
    fi

    # Clean up - strip trailing dot, wildcard prefix, leading dot
    resolved_domain=$(echo "$resolved_domain" | sed 's/^\*\.//' | sed 's/^\.//' | sed 's/\.$//' | tr -d ' ' || true)

    if [[ -n "$resolved_domain" ]] && [[ "$resolved_domain" != *"in-addr.arpa"* ]] && [[ "$resolved_domain" != *";;"* ]] && [[ "$resolved_domain" =~ ^[a-zA-Z0-9] ]]; then
      warn "Resolved IP $IP -> hostname: ${W}$resolved_domain${NC}"
      info "Activating domain-based modules with: ${W}$resolved_domain${NC}"
      DOMAIN="$resolved_domain"
      DOMAIN_AUTO_RESOLVED=true
      # Verify it resolves back to the same IP (confirm it's the right domain)
      local verify_ip
      verify_ip=$(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
      if [[ -n "$verify_ip" ]]; then
        info "Verified: $DOMAIN -> $verify_ip"
      else
        warn "Could not verify reverse resolution - domain-based results may be inaccurate"
      fi
    else
      warn "Could not resolve hostname from IP - running in IP-only mode"
      info "Active modules  : nmap, nuclei, feroxbuster, ffuf, whatweb, wafw00f, web headers"
      info "Skipped modules : DNS enum, subdomain brute-force, crt.sh, SPF/DKIM/DMARC, email harvest, leak search"
      info "Tip: use ${W}-d <domain> -i <ip>${NC} together for full coverage"
    fi
  fi

  # ── Final state summary after resolution attempt ──
  if [[ -n "$DOMAIN" && -n "$IP" ]]; then
    if $DOMAIN_AUTO_RESOLVED; then
      info "Target: ${W}$DOMAIN${NC} (${W}$IP${NC}) - hostname resolved from IP"
    else
      info "Target: ${W}$DOMAIN${NC} (${W}$IP${NC})"
    fi
  elif [[ -n "$DOMAIN" ]]; then
    info "Target: ${W}$DOMAIN${NC}"
  else
    info "Target: ${W}$IP${NC} - IP-only scan (hostname resolution failed)"
  fi

  # ── Derive a working web URL — try HTTP and HTTPS, pick best ──
  if [[ -n "$DOMAIN" ]]; then
    local _https_code _http_code
    # Try domain first, then IP fallback immediately if needed
    _https_code=$(curl -skL --max-time 12 -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null || echo 000)
    _https_code=$(echo "$_https_code" | tr -d "\n" | grep -oE "[0-9]{3}$" || echo 000)
    # If HTTPS domain failed and we have IP, try via IP with SNI immediately
    if [[ ! "$_https_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]] && [[ -n "$IP" ]]; then
      _https_code=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
        -H "Host: $DOMAIN" "https://$IP" 2>/dev/null || echo 000)
      _https_code=$(echo "$_https_code" | tr -d "\n" | grep -oE "[0-9]{3}$" || echo 000)
    fi
    _http_code=$(curl -sk --max-time 12 -o /dev/null -w "%{http_code}" "http://$DOMAIN" 2>/dev/null || echo 000)
    _http_code=$(echo "$_http_code" | tr -d "\n" | grep -oE "[0-9]{3}$" || echo 000)

    if [[ "$_https_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]]; then
      TARGET_URL="https://$DOMAIN"
    elif [[ "$_http_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]]; then
      TARGET_URL="http://$DOMAIN"
      info "HTTPS not available — using HTTP for web tools"
    else
      # Both failed — try IP directly if available
      if [[ -z "$IP" && -n "$DOMAIN" ]]; then
        IP=$(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
      fi
      if [[ -n "$IP" ]]; then
        local _ip_https_code _ip_http_code
        _ip_https_code=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" "https://$IP" 2>/dev/null || echo 000)
        _ip_https_code=$(echo "$_ip_https_code" | grep -oE '[0-9]{3}$' || echo 000)
        _ip_http_code=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" "http://$IP" 2>/dev/null || echo 000)
        _ip_http_code=$(echo "$_ip_http_code" | grep -oE '[0-9]{3}$' || echo 000)
        if [[ "$_ip_https_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]]; then
          TARGET_URL="https://$DOMAIN"
          info "Domain probe used IP fallback — HTTPS confirmed via $IP"
        elif [[ "$_ip_http_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]]; then
          TARGET_URL="http://$DOMAIN"
          info "Domain probe used IP fallback — HTTP confirmed via $IP"
        else
          TARGET_URL="https://$DOMAIN"
        fi
      else
        TARGET_URL="https://$DOMAIN"
      fi
    fi
    # Final fallback: try www. if bare domain is unreachable
    local _bare_final _www_scheme _www_code
    _bare_final=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null || echo 000)
    _bare_final=$(echo "$_bare_final" | grep -oE "[0-9]{3}$" || echo 000)
    if [[ ! "$_bare_final" =~ ^[1-5][0-9][0-9]$ ]]; then
      for _www_scheme in https http; do
        _www_code=$(curl -skL --max-time 8 -o /dev/null -w "%{http_code}" "${_www_scheme}://www.$DOMAIN" 2>/dev/null || echo 000)
        _www_code=$(echo "$_www_code" | grep -oE "[0-9]{3}$" || echo 000)
        if [[ "$_www_code" =~ ^(200|201|301|302|303|307|308|401|403)$ ]]; then
          TARGET_URL="${_www_scheme}://www.$DOMAIN"
          info "Using www.${DOMAIN} as base URL — bare domain unreachable"
          break
        fi
      done
    fi
  elif [[ -n "$IP" ]]; then
    TARGET_URL="http://$IP"
    info "IP-only mode - using ${W}${TARGET_URL}${NC} for web tools"
  fi

  # Quick mode
  if $QUICK; then
    info "Quick mode - DNS, WHOIS, TLS, headers only"
    run_whois
    run_dns
    run_tls
    run_web_headers
  else

  # ── Phase 1: Passive recon ──
  run_whois
  run_dns
  run_tls
  run_web_headers      # WAF detection happens here - must run before subdomain enum
  # Parse WAF result immediately so run_sensitive_paths can use it
  if [[ -f "${OUT_DIR}/wafw00f.txt" ]]; then
    local _waf_early
    _waf_early=$(sed 's/\033\[[0-9;]*m//g' "${OUT_DIR}/wafw00f.txt" 2>/dev/null || cat "${OUT_DIR}/wafw00f.txt")
    if echo "$_waf_early" | grep -qi "cloudflare"; then
      WAF_DETECTED=true; WAF_IS_CLOUDFLARE=true
    elif echo "$_waf_early" | grep -qi "is behind\|seems to be behind\|Wordfence\|Sucuri\|Squarespace\|Fastly\|Akamai\|Imperva\|Incapsula\|Barracuda"; then
      # Only set WAF_DETECTED for real WAF findings, not connection-level blocking
      if ! echo "$_waf_early" | grep -qi "connection/packet level\|packet level blocking"; then
        WAF_DETECTED=true
      fi
    fi
  fi
  run_sensitive_paths
  run_ct
  run_subdomains
  run_httpx
  run_takeover
  run_asn
  run_email_security

  echo ""
  run_shodan

  echo ""
  run_securitytrails
  run_param_discovery
  run_email_harvest
  run_social_intel
  run_js_discovery
  run_cloud_enum
  run_leak_search
  run_google_dorks
  run_screenshots

  # ── Phase 2: Active scanning ──
  if $ACTIVE; then

    rate_limit_check() {
      local code
      code=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "https://${DOMAIN:-$IP}" 2>/dev/null || echo 0)
      [[ "$code" == "429" ]] && return 0 || return 1
    }

    # WAF / rate-limit awareness — must run BEFORE dirsearch and nmap
    local THREADS_ACTIVE=$THREADS
    local SCAN_DELAY=""
    local EXTRA_AGENT="--random-agent"

    # Check wafw00f result - strip ANSI codes first, then grep
    if [[ -f "${OUT_DIR}/wafw00f.txt" ]]; then
      local _waf_clean
      _waf_clean=$(sed 's/\033\[[0-9;]*m//g' "${OUT_DIR}/wafw00f.txt" 2>/dev/null || cat "${OUT_DIR}/wafw00f.txt")
      if echo "$_waf_clean" | grep -qi "cloudflare"; then
        WAF_DETECTED=true
        WAF_IS_CLOUDFLARE=true
      elif echo "$_waf_clean" | grep -qi "is behind\|seems to be behind\|Wordfence\|Sucuri\|Squarespace\|Fastly\|Akamai\|Imperva\|Incapsula\|Barracuda"; then
        if ! echo "$_waf_clean" | grep -qi "connection/packet level\|packet level blocking"; then
          WAF_DETECTED=true
        fi
      fi
    fi

    # Also check headers for WAF indicators - but only set WAF_DETECTED not WAF_IS_CLOUDFLARE
    # (WAF type comes from wafw00f only to avoid false positives)
    if [[ -f "${OUT_DIR}/web_headers.txt" ]]; then
      grep -qiE "^cf-ray:|^x-sucuri-id:|^x-fw-protection:|^x-waf-event-id:" "${OUT_DIR}/web_headers.txt" 2>/dev/null && WAF_DETECTED=true
      # Only confirm Cloudflare from headers if wafw00f also said Cloudflare
      if ! $WAF_IS_CLOUDFLARE; then
        grep -qi "cf-ray" "${OUT_DIR}/web_headers.txt" 2>/dev/null && WAF_IS_CLOUDFLARE=true
      fi
    fi

    if $WAF_IS_CLOUDFLARE; then
      THREADS_ACTIVE=5
      SCAN_DELAY="2"
    elif $WAF_DETECTED; then
      THREADS_ACTIVE=10
      SCAN_DELAY="1"
    fi

    run_nmap
    run_dirsearch

    # Rate limit check on top of WAF
    if rate_limit_check; then
      THREADS_ACTIVE=5
      sleep 10
    fi

    echo ""
    run_wpscan

  fi  # end ACTIVE block

  fi  # end else (Quick vs Full/Passive)

  generate_report

  # Get local IP
  local local_ip
  local_ip=$(ip -4 addr show scope global 2>/dev/null \
    | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "YOUR_IP")

  # ── Dynamic-width summary box ──
  # Plain strings for width calculation (no colour codes)
  local p_out="  Output dir : ${OUT_DIR}/"
  local p_rep="  HTML report: ${OUT_DIR}/report.html"
  local p_log="  Raw log    : ${LOG_FILE}"
  local p_cd="  cd ${OUT_DIR}"
  local p_py="  python3 -m http.server 8080"
  local p_loc="  Local  : http://localhost:8080/report.html"
  local p_net="  Network: http://${local_ip}:8080/report.html"

  local box_w=62
  for _l in "$p_out" "$p_rep" "$p_log" "$p_cd" "$p_py" "$p_loc" "$p_net"; do
    [[ ${#_l} -gt $box_w ]] && box_w=$(( ${#_l} + 2 ))
  done
  # Cap to terminal width - try multiple methods, sudo-safe
  local term_w=120
  if [[ -n "${COLUMNS:-}" ]]; then
    term_w=$COLUMNS
  elif command -v tput &>/dev/null; then
    term_w=$(tput cols 2>/dev/null || echo 120)
  elif [[ -n "${TERM:-}" ]]; then
    term_w=$(stty size 2>/dev/null | awk '{print $2}' || echo 120)
  fi
  [[ "$term_w" -lt 60 ]] && term_w=60  # minimum sensible width
  [[ $box_w -gt $((term_w - 2)) ]] && box_w=$((term_w - 2))

  # Truncate plain strings to fit inside box (max content = box_w - 3)
  local max_content=$(( box_w - 3 ))
  [[ ${#p_out} -gt $max_content ]] && p_out="${p_out:0:$((max_content-3))}..."
  [[ ${#p_rep} -gt $max_content ]] && p_rep="${p_rep:0:$((max_content-3))}..."
  [[ ${#p_log} -gt $max_content ]] && p_log="${p_log:0:$((max_content-3))}..."
  [[ ${#p_cd}  -gt $max_content ]] && p_cd="${p_cd:0:$((max_content-3))}..."

  local _hr
  _hr=$(printf '═%.0s' $(seq 1 $box_w))

  # _row: $1 = plain text for width calc, $2 = coloured display text
  # box_w passed as $3 to avoid nested function scoping issues
  _row() {
    local plain="$1"
    local display="${2:-$1}"
    local bw="${3:-$box_w}"
    # Truncate if plain text exceeds box width
    if [[ ${#plain} -gt $((bw - 1)) ]]; then
      plain="${plain:0:$((bw - 4))}..."
      display="${plain}"
    fi
    local pad=$(( bw - ${#plain} - 1 ))
    [[ $pad -lt 0 ]] && pad=0
    printf "${B}║${NC}"
    printf "%b" "$display"
    printf "\n"
  }

  printf "\n"
  printf "${B}╔%s╗${NC}\n" "$_hr"
  _row "  Scan Complete!"          "  \033[0;32m\033[1mScan Complete!\033[0m"  "$box_w"
  printf "${B}╠%s╣${NC}\n" "$_hr"
  _row "$p_out"  "  Output dir : \033[1;37m${OUT_DIR}/\033[0m"  "$box_w"
  _row "$p_rep"  "  HTML report: \033[1;37m${OUT_DIR}/report.html\033[0m"  "$box_w"
  _row "$p_log"  "  Raw log    : \033[1;37m${LOG_FILE}\033[0m"  "$box_w"
  printf "${B}╠%s╣${NC}\n" "$_hr"
  _row "  View report in browser:"  "  \033[0;36m\033[1mView report in browser:\033[0m"  "$box_w"
  _row ""  ""  "$box_w"
  _row "$p_cd"  "  \033[1;37m${p_cd:2}\033[0m"  "$box_w"
  _row "$p_py"  "  \033[1;37m${p_py:2}\033[0m"  "$box_w"
  _row ""  ""  "$box_w"
  _row "$p_loc"  "  Local  : \033[0;32mhttp://localhost:8080/report.html\033[0m"  "$box_w"
  _row "$p_net"  "  Network: \033[0;32mhttp://${local_ip}:8080/report.html\033[0m"  "$box_w"
  printf "${B}╚%s╝${NC}\n" "$_hr"
  printf "\n"
}

main "$@"
