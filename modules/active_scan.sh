#!/usr/bin/env bash
# RECONOMEW — active_scan.sh
# Modules: Dirsearch, Param Discovery, Screenshots, Nmap, WPScan, Nuclei

# ================================================================
#  MODULE: DIRECTORY BRUTE-FORCE (dirsearch)
# ================================================================

run_dirsearch() {
  $ACTIVE || return
  module_enabled "dirsearch" || return
  [[ -z "$DOMAIN" ]] && return

  section "Directory Brute-Force"

  local ds_bin
  ds_bin=$(command -v dirsearch 2>/dev/null || echo "")
  if [[ -z "$ds_bin" ]]; then
    skip "dirsearch (not installed — pip3 install dirsearch)"
    return
  fi

  local target_url="https://${DOMAIN}"
  local ds_out="${OUT_DIR}/dirsearch/dirsearch.txt"
  local ds_err="${OUT_DIR}/dirsearch/dirsearch_err.txt"
  mkdir -p "${OUT_DIR}/dirsearch"

  # ── WAF-aware rate limiting ──
  local ds_threads=20 ds_delay=0 ds_timeout=10

  if $waf_blocked; then
    warn "WAF block detected — dirsearch skipped (results would be unreliable)"
    warn "Try again from a different IP or after WAF cooldown"
    return
  elif $WAF_IS_CLOUDFLARE; then
    ds_threads=3; ds_delay=2000; ds_timeout=15
    info "Cloudflare WAF — running dirsearch at low rate (3 threads, 2s delay)"
  elif $WAF_DETECTED; then
    ds_threads=5; ds_delay=1000; ds_timeout=12
    info "WAF detected — running dirsearch at reduced rate (5 threads, 1s delay)"
  else
    info "No WAF detected — running dirsearch ($ds_threads threads)"
  fi

  # Find wordlist
  local ds_wordlist=""
  for _wl in \
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt" \
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt" \
    "/usr/share/dirsearch/db/dicc.txt"; do
    [[ -f "$_wl" ]] && ds_wordlist="$_wl" && break
  done
  if [[ -z "$ds_wordlist" ]]; then
    warn "No wordlist found — install seclists: sudo apt install seclists"
    return
  fi
  info "Wordlist: $ds_wordlist"

  # Detect wildcard responses before scanning
  local ds_wildcard_403=false ds_wildcard_status=""
  local _rand_path="reconomew_rand_$(date +%s)"
  local _rand_code
  _rand_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${target_url}/${_rand_path}" 2>/dev/null || echo 000)
  _rand_code=$(echo "$_rand_code" | grep -oE "[0-9]{3}$" || echo 000)
  if [[ "$_rand_code" == "403" ]]; then
    ds_wildcard_403=true
    warn "Wildcard 403 detected — all 403 responses will be filtered (server returns 403 for any path)"
  fi

  local ds_start; ds_start=$(date +%s)
  timeout 200 "$ds_bin" \
    -u "$target_url" \
    -w "$ds_wordlist" \
    -t "$ds_threads" \
    --delay="$ds_delay" \
    --timeout="$ds_timeout" \
    -x 400,404,429,500,502,503 \
    --follow-redirects \
    --random-agent \
    -q \
    -o "$ds_out" \
    --format plain \
    2>"$ds_err" >/dev/null &
  local ds_pid=$!

  local ds_tick=0
  while kill -0 "$ds_pid" 2>/dev/null; do
    sleep 5; ds_tick=$((ds_tick + 5))
    local ds_live=0
    [[ -f "$ds_out" ]] && ds_live=$(grep -c "." "$ds_out" 2>/dev/null | head -1 | tr -d ' ' || echo 0)
    ds_live=${ds_live//[^0-9]/}; ds_live=${ds_live:-0}
    kill -0 "$ds_pid" 2>/dev/null && \
      printf "\r  \033[0;36m[→]\033[0m dirsearch %ds | found: %d\033[K" "$ds_tick" "$ds_live"
  done
  wait "$ds_pid" 2>/dev/null || true
  printf "\r\033[2K"
  local ds_elapsed=$(( $(date +%s) - ds_start ))

  if [[ ! -f "$ds_out" ]] || [[ ! -s "$ds_out" ]]; then
    if grep -qi "403\|blocked\|rate.limit\|too many" "$ds_err" 2>/dev/null; then
      warn "dirsearch: blocked by WAF/rate-limiting (${ds_elapsed}s)"
    else
      info "dirsearch: no results found (${ds_elapsed}s)"
    fi
    return
  fi

  local ds_count=0 ds_interesting=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Skip comment lines and non-result lines (e.g. [#] plain header)
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    local ds_status ds_url
    ds_status=$(echo "$line" | awk '{print $1}')
    ds_url=$(echo "$line" | awk '{print $NF}')
    # Skip if status is not a valid HTTP code
    [[ "$ds_status" =~ ^[0-9]{3}$ ]] || continue
    [[ -z "$ds_url" ]] && continue
    ds_count=$((ds_count + 1))
    # Skip 403 if wildcard 403 detected
    [[ "$ds_wildcard_403" == "true" && "$ds_status" == "403" ]] && continue
    case "$ds_status" in
      200|201) warn "[$ds_status] $ds_url" ; ds_interesting=$((ds_interesting + 1)) ;;
      *)       result "[$ds_status] $ds_url" ;;
    esac
  done < <(sort -u "$ds_out" | head -50)

  local total_lines
  total_lines=$(wc -l < "$ds_out" | tr -d ' ')
  [[ "$total_lines" -gt 50 ]] && result "... and $((total_lines - 50)) more (see $ds_out)"

  if [[ "$ds_count" -gt 0 ]]; then
    info "dirsearch done: $ds_count path(s) found ($ds_interesting with 200) in ${ds_elapsed}s"
  else
    info "dirsearch done: nothing found in ${ds_elapsed}s"
  fi
}


# ================================================================
#  MODULE: PARAMETER DISCOVERY (arjun)
# ================================================================

run_param_discovery() {
  : # arjun removed - parameter discovery not available
}


# ================================================================
#  MODULE: SCREENSHOTS
# ================================================================

run_screenshots() {
  : # gowitness removed - screenshots not available
}




# ================================================================
#  MODULE: NMAP
# ================================================================

run_nmap() {
  $ACTIVE || return
  module_enabled "nmap" || return
  [[ -z "$DOMAIN" && -z "$IP" ]] && return
  tool_ok "nmap" || { skip "nmap (not installed - sudo apt install nmap)"; return; }

  section "Nmap Port Scanning"
  local target="${IP:-$DOMAIN}"
  local nmap_timing="-T4"
  local nmap_delay=""
  [[ -n "${SCAN_DELAY:-}" ]] && nmap_delay="--scan-delay ${SCAN_DELAY}s"

  # Use -sT (connect scan) for phase 1 — most reliable across all network types
  # -sS (SYN) can miss ports when combined with -sV; version detection in phase 3 only
  local nmap_scan_type="-sT"
  # Upgrade to SYN scan for phase 3 scripts if root
  local nmap_is_root=false
  [[ $EUID -eq 0 ]] || sudo -n true &>/dev/null 2>&1 && nmap_is_root=true

  # ── CDN detection — warn if scanning a CDN edge node ──
  local _scan_ip
  _scan_ip=$(dig +short A "$target" @1.1.1.1 2>/dev/null | grep -E '^[0-9]' | head -1 || true)
  [[ -z "$_scan_ip" ]] && _scan_ip="$target"
  local _cdn_asn
  _cdn_asn=$(curl -s --max-time 5 "https://ipinfo.io/${_scan_ip}/org" 2>/dev/null || true)
  local _cdn_name=""
  case "${_cdn_asn,,}" in
    *cloudflare*)  _cdn_name="Cloudflare"     ;;
    *fastly*)      _cdn_name="Fastly"         ;;
    *akamai*)      _cdn_name="Akamai"         ;;
    *amazon*)
      local _cf_ptr; _cf_ptr=$(dig +short -x "$_scan_ip" @1.1.1.1 2>/dev/null | head -1 || true)
      [[ "$_cf_ptr" == *cloudfront* ]] && _cdn_name="AWS CloudFront"
      ;;
  esac
  if [[ -n "$_cdn_name" ]]; then
    warn "Target is behind $_cdn_name — nmap scans CDN edge, not origin server"

    # ── Try to find origin IP ──
    local _origin_ip=""
    info "Attempting to find origin IP..."

    # Method 1: direct DNS for subdomains that bypass CDN (mail, ftp, cpanel etc)
    for _sub in mail ftp cpanel webmail direct origin smtp; do
      local _sub_ip
      _sub_ip=$(dig +short A "${_sub}.${DOMAIN}" @1.1.1.1 2>/dev/null         | grep -E '^[0-9]{1,3}\.[0-9]{1,3}' | head -1 || true)
      if [[ -n "$_sub_ip" ]]; then
        # Check if this IP is also behind the CDN
        local _sub_asn
        _sub_asn=$(curl -s --max-time 3 "https://ipinfo.io/${_sub_ip}/org" 2>/dev/null || true)
        if ! echo "${_sub_asn,,}" | grep -qE "cloudflare|akamai|fastly|cloudfront"; then
          _origin_ip="$_sub_ip"
          info "Possible origin IP via ${_sub}.${DOMAIN}: $_origin_ip"
          break
        fi
      fi
    done

    # Method 2: check historical IPs from SecurityTrails output file
    if [[ -z "$_origin_ip" && -f "${OUT_DIR}/securitytrails.txt" ]]; then
      local _hist_ip
      _hist_ip=$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'         "${OUT_DIR}/securitytrails.txt" 2>/dev/null | head -1 || true)
      if [[ -n "$_hist_ip" ]]; then
        local _hist_asn
        _hist_asn=$(curl -s --max-time 3 "https://ipinfo.io/${_hist_ip}/org" 2>/dev/null || true)
        if ! echo "${_hist_asn,,}" | grep -qE "cloudflare|akamai|fastly|cloudfront"; then
          _origin_ip="$_hist_ip"
          info "Possible origin IP from historical DNS: $_origin_ip"
        fi
      fi
    fi

    # Method 3: TLS certificate — sometimes reveals origin hostname/IP
    if [[ -z "$_origin_ip" ]]; then
      local _cert_cn
      _cert_cn=$(echo | timeout 5 openssl s_client -connect "${_scan_ip}:443"         -servername "$DOMAIN" -quiet 2>/dev/null         | openssl x509 -noout -subject 2>/dev/null         | grep -oE 'CN=[^,/]+' | sed 's/CN=//' || true)
      [[ -n "$_cert_cn" && "$_cert_cn" != "$DOMAIN" && "$_cert_cn" != *"*"* ]] &&         info "TLS cert CN: $_cert_cn (may reveal origin)"
    fi

    if [[ -n "$_origin_ip" ]]; then
      warn "Scanning origin IP $_origin_ip with Host: $DOMAIN header"
      target="$_origin_ip"
      nmap_delay="${nmap_delay} --script-args http.host=$DOMAIN"
    else
      warn "Could not find origin IP — scanning CDN edge (results will be limited)"
      warn "Tip: check Shodan/SecurityTrails manually for historical IPs"
    fi
  fi

  # Phase 1: comprehensive TCP port list
  local tcp_ports="21,22,23,25,53,79,80,88,110,111,135,139,143,389,443,445,465,587,631,993,995,1080,1433,1521,2049,2222,2375,2376,2379,2380,3000,3306,3389,4443,4848,5432,5601,5900,5984,6379,6443,7001,7443,8000,8080,8081,8443,8888,9000,9090,9092,9200,9300,10250,11211,27017,28017,50070"
  run_timed "Nmap phase 1: TCP ports + version detection" 600 nmap \
    $nmap_scan_type $nmap_timing \
    $nmap_delay \
    --host-timeout 120s \
    -p "$tcp_ports" \
    -oN "${OUT_DIR}/nmap/common.txt" \
    "$target"
  sleep 1  # ensure nmap finishes writing output file

  local tcp_found=0
  if [[ -f "${OUT_DIR}/nmap/common.txt" ]] && [[ -s "${OUT_DIR}/nmap/common.txt" ]]; then
    tcp_found=$(grep -c "open" "${OUT_DIR}/nmap/common.txt" 2>/dev/null) || tcp_found=0
    tcp_found=${tcp_found//[^0-9]/}; tcp_found=${tcp_found:-0}
    grep -E "^[0-9]+/.*open" "${OUT_DIR}/nmap/common.txt" 2>/dev/null       | while read -r l; do result "$l"; done || true
  fi
  info "Phase 1 done: $tcp_found open TCP port(s) found"

  # Phase 2: UDP top 50 ports (requires root)
  if [[ $EUID -eq 0 ]]; then
    run_timed "Nmap phase 2: UDP top 50 ports" 600 nmap       -sU --top-ports 50 -T4       -oN "${OUT_DIR}/nmap/udp.txt" "$target"
    grep -E "^[0-9]+/.*open" "${OUT_DIR}/nmap/udp.txt" 2>/dev/null       | while read -r l; do result "$l"; done || true
  elif sudo -n true &>/dev/null 2>&1; then
    run_timed "Nmap phase 2: UDP top 50 ports" 600       sudo nmap -sU --top-ports 50 -T4 -oN "${OUT_DIR}/nmap/udp.txt" "$target"
    grep -E "^[0-9]+/.*open" "${OUT_DIR}/nmap/udp.txt" 2>/dev/null       | while read -r l; do result "$l"; done || true
  else
    info "Phase 2: UDP scan skipped — run as root to enable UDP scanning"
  fi

  # Phase 3: targeted scripts based on detected services (not blanket vuln sweep)
  local open_ports
  open_ports=$(grep -E "^[0-9]+/.*open" "${OUT_DIR}/nmap/common.txt" 2>/dev/null     | awk -F/ '{print $1}' | sort -un | tr '
' ',' | sed 's/,$//' || true)

  if [[ -n "$open_ports" ]]; then
    # Build targeted script list based on what services were found
    local scripts="banner,http-title,http-headers,http-methods,http-auth-finder"

    # Add service-specific scripts if those ports are open
    grep -qE "^(21|2121)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",ftp-anon,ftp-bounce"
    grep -qE "^(22)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",ssh-auth-methods"
    grep -qE "^(25|465|587)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",smtp-open-relay,smtp-commands"
    grep -qE "^(53)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",dns-zone-transfer"
    grep -qE "^(139|445)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb2-security-mode"
    grep -qE "^(3306)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",mysql-empty-password,mysql-info"
    grep -qE "^(5432)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",pgsql-brute"
    grep -qE "^(6379)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",redis-info"
    grep -qE "^(27017)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",mongodb-info"
    grep -qE "^(9200|9300)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",http-elasticsearch-info"
    grep -qE "^(2375|2376)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",docker-info" 2>/dev/null || true
    grep -qE "^(389|636)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",ldap-rootdse"
    grep -qE "^(8080|8443|8888|9090)/" "${OUT_DIR}/nmap/common.txt" 2>/dev/null &&       scripts+=",http-robots.txt,http-shellshock"

    run_timed "Nmap phase 3: targeted service scripts" 600 nmap \
      -sT -sV \
      -p "$open_ports" \
      --script-timeout 10s \
      --script="$scripts" \
      -oN "${OUT_DIR}/nmap/vulns.txt" "$target"

    # Show critical findings
    local vuln_count=0
    if [[ -f "${OUT_DIR}/nmap/vulns.txt" ]]; then
      grep -E "VULNERABLE|CVE-|CRITICAL|HIGH|anonymous.*login|open relay"         "${OUT_DIR}/nmap/vulns.txt" 2>/dev/null         | while read -r l; do warn "$l"; done || true
      vuln_count=$(grep -cE "VULNERABLE|CVE-" "${OUT_DIR}/nmap/vulns.txt" 2>/dev/null | tr -d ' '); vuln_count=${vuln_count:-0}
    fi
    [[ "$vuln_count" -gt 0 ]] && warn "Phase 3: $vuln_count potential vulnerability/CVE finding(s) — see ${OUT_DIR}/nmap/vulns.txt"       || info "Phase 3: no critical vulnerabilities found"
  else
    info "Phase 3: skipped — no open ports found in phase 1"
  fi

}


# ================================================================
#  MODULE: FEROXBUSTER
# ================================================================


# ================================================================
#  MODULE: WPSCAN
# ================================================================

run_wpscan() {
  $ACTIVE || return
  [[ -z "$DOMAIN" ]] && return
  tool_ok "wpscan" || { skip "wpscan (not installed - gem install wpscan)"; return; }

  # Only run if WordPress detected
  local wp_detected=false
  grep -qi "wp-json\|wp-content\|wp-admin\|wordpress\|woocommerce\|xmlrpc" "${OUT_DIR}/web_headers.txt" 2>/dev/null && wp_detected=true
  grep -qi "wordpress\|wp-content" "${OUT_DIR}/whatweb.txt" 2>/dev/null && wp_detected=true
  # Also check JS/URL discovery results for WordPress indicators
  grep -qiE "wp-content|wp-json|wp-admin|xmlrpc\.php" "${OUT_DIR}/all_urls.txt" 2>/dev/null && wp_detected=true
  grep -qiE "wp-content|wp-json|wp-admin" "${OUT_DIR}/httpx_results.txt" 2>/dev/null && wp_detected=true

  if ! $wp_detected; then
    skip "wpscan (WordPress not detected)"
    return
  fi

  section "WPScan - WordPress Analysis"
  info "WordPress detected - running full WPScan"

  local wp_url="https://$DOMAIN"
  # Try www subdomain too
  local www_status
  www_status=$(curl -o /dev/null -sIL --max-time 5 -w "%{http_code}" "https://www.$DOMAIN" 2>/dev/null || echo "000")
  [[ "$www_status" =~ ^(200|301|302)$ ]] && wp_url="https://www.$DOMAIN"

  run_timed "WPScan WordPress analysis" 300 wpscan \
    --url "$wp_url" --no-banner --disable-tls-checks \
    --random-user-agent --enumerate u,vp,vt \
    --format cli-no-color \
    ${WPSCAN_API_TOKEN:+--api-token "$WPSCAN_API_TOKEN"} \
    -o "${OUT_DIR}/wpscan.txt"

  # FIX: safe integer count - avoid arithmetic syntax error
  local wp_count=0
  if [[ -f "${OUT_DIR}/wpscan.txt" ]]; then
    wp_count=$(grep -c "\[" "${OUT_DIR}/wpscan.txt" 2>/dev/null | tr -d '[:space:]\n' | grep -oE '^[0-9]+' || echo 0)
    wp_count=${wp_count:-0}
  fi
  info "WPScan: $wp_count findings - see ${OUT_DIR}/wpscan.txt"

  # Show important findings - filter out wpscan noise/contradictions
  grep -E "\[!\]|\[\+\] WordPress version|Vulnerability|CVE-|vulnerable" "${OUT_DIR}/wpscan.txt" 2>/dev/null     | grep -v "API Token"     | grep -v "You can get a free API token"     | grep -v "out of date, the latest version is"     | head -20 | while read -r l; do result "$l"; done || true

  # Prompt for WPScan API token if missing
  if [[ -f "${OUT_DIR}/wpscan.txt" ]] && grep -q "No WPScan API Token" "${OUT_DIR}/wpscan.txt" 2>/dev/null; then
    warn "WPScan API token missing - vulnerability data not shown"
    warn "Free token (25 req/day): ${W}https://wpscan.com/register${NC}"
    warn "Set it: ${W}export WPSCAN_API_TOKEN=your_token${NC}"
  fi
}

# ================================================================
#  MODULE: NUCLEI
# ================================================================

run_nuclei() {
  : # nuclei removed
}


# ================================================================
#  GENERATE HTML REPORT
# ================================================================

