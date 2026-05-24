#!/usr/bin/env bash
# RECONOMEW — web_recon.sh
# Modules: Web Headers, Sensitive Paths, HTTPX, Subdomain Takeover

run_web_headers() {
  module_enabled "web-headers" || return
  [[ -z "$DOMAIN" && -z "$IP" ]] && return
  local wh_target="${DOMAIN:-$IP}"
  # Prefer HTTPS + domain over HTTP + IP
  local wh_url="${TARGET_URL:-https://$wh_target}"
  section "Web Headers & Technology Detection"

  local UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

  for scheme in https http; do
    info "$scheme://$wh_target headers"
    local hdr_out
    # Try HEAD first, fall back to GET if HEAD fails (some servers block HEAD)
    hdr_out=$(curl -sI -L --max-time 15 \
      -H "User-Agent: $UA" \
      "$scheme://$wh_target" 2>/dev/null || true)
    if [[ -z "$hdr_out" ]]; then
      hdr_out=$(curl -s -L --max-time 15 -o /dev/null -D - \
        -H "User-Agent: $UA" \
        "$scheme://$wh_target" 2>/dev/null || true)
    fi
    if [[ -n "$hdr_out" ]]; then
      # Filter HTTP/103 early hints - not a real response
      echo "$hdr_out" | grep -v "^$" | grep -v "^HTTP/[0-9.]* 103" | while IFS= read -r l; do
        # Strip leading whitespace
        l="${l#"${l%%[![:space:]]*}"}"
        local lkey
        lkey=$(echo "$l" | cut -d: -f1 | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        case "$lkey" in
          set-cookie)
            local cname; cname=$(echo "$l" | grep -oE "^set-cookie:[[:space:]]*[a-zA-Z0-9_-]+" | grep -oE "[a-zA-Z0-9_-]+$")
            result "  set-cookie: $cname=... (truncated)"
            ;;
          content-security-policy|permissions-policy)
            result "  ${l:0:100}..."
            ;;
          *)
            if [[ ${#l} -gt 120 ]]; then
              result "  ${l:0:117}..."
            else
              result "  $l"
            fi
            ;;
        esac
      done
    else
      result "No response"
    fi
    echo "$hdr_out" >> "${OUT_DIR}/web_headers.txt"
  done

  # Extract version info from headers for CVE lookup
  local php_ver
  php_ver=$(grep -oiE "PHP/[0-9.]+" "${OUT_DIR}/web_headers.txt" 2>/dev/null | head -1 || true)
  [[ -n "$php_ver" ]] && warn "PHP version exposed in headers: $php_ver"

  info "robots.txt"
  local robots_out="" robots_status
  # Use -L to follow redirects, get final status code
  robots_status=$(curl -sL --max-time 10 \
    -H "User-Agent: $UA" \
    -o /dev/null -w "%{http_code}" \
    "${wh_url}/robots.txt" 2>/dev/null || echo "000")
  robots_status=$(echo "$robots_status" | grep -oE "[0-9]{3}$" || echo "000")
  robots_status=${robots_status:-000}
  # Fallback to HTTPS if HTTP failed
  if [[ "$robots_status" == "000" && "$wh_url" == http://* ]]; then
    local _https_robots="${wh_url/http:\/\//https:\/\/}"
    robots_status=$(curl -sL --max-time 10 \
      -H "User-Agent: $UA" \
      -o /dev/null -w "%{http_code}" \
      "${_https_robots}/robots.txt" 2>/dev/null || echo "000")
    robots_status=$(echo "$robots_status" | grep -oE "[0-9]{3}$" || echo "000")
    [[ "$robots_status" != "000" ]] && wh_url="$_https_robots"
  fi
  if [[ "$robots_status" == "200" ]]; then
    robots_out=$(curl -sL --max-time 10 \
      -H "User-Agent: $UA" \
      "${wh_url}/robots.txt" 2>/dev/null | head -30 || true)
    if [[ -n "$robots_out" ]] && ! echo "$robots_out" | grep -qiE "<html|<body|access denied|403 forbidden"; then
      echo "$robots_out" | while read -r l; do result "$l"; done
      echo "$robots_out" > "${OUT_DIR}/robots.txt"
    else
      result "robots.txt: blocked or HTML response"
    fi
  elif [[ "$robots_status" == "403" ]]; then
    result "robots.txt: exists but access denied [403]"
  elif [[ "$robots_status" == "000" ]]; then
    result "robots.txt: could not connect to host"
  else
    result "robots.txt: not found [$robots_status]"
  fi

  echo ""
  # Check sitemap - try robots.txt directive first, then common paths on both http+https
  local sitemap_url=""
  # 1. Pull URL from robots.txt in memory
  if [[ -n "$robots_out" ]]; then
    sitemap_url=$(echo "$robots_out" | grep -i "^Sitemap:" | head -1 \
      | sed 's/^[Ss]itemap:[[:space:]]*//' | tr -d '\r' || true)
  fi
  # 2. Pull from saved robots.txt file
  if [[ -z "$sitemap_url" && -f "${OUT_DIR}/robots.txt" ]]; then
    sitemap_url=$(grep -i "^Sitemap:" "${OUT_DIR}/robots.txt" | head -1 \
      | sed 's/^[Ss]itemap:[[:space:]]*//' | tr -d '\r' || true)
  fi

  # Build candidate list - always try https:// first, then whatever wh_url is
  local _smap_candidates=()
  [[ -n "$sitemap_url" ]] && _smap_candidates+=("$sitemap_url")
  local _base_https="https://${DOMAIN:-$IP}"
  local _base_http="http://${DOMAIN:-$IP}"
  _smap_candidates+=(
    "${_base_https}/sitemap.xml"
    "${_base_https}/sitemap_index.xml"
    "${_base_https}/sitemap-index.xml"
    "${_base_https}/sitemaps/sitemap.xml"
    "${_base_https}/sitemap.xml.gz"
    "${_base_http}/sitemap.xml"
    "${_base_http}/sitemap_index.xml"
  )

  local sitemap_found=false
  for _smap_url in "${_smap_candidates[@]}"; do
    [[ -z "$_smap_url" ]] && continue
    local sitemap_out sitemap_status
    sitemap_status=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" -L "$_smap_url" 2>/dev/null || true)
    sitemap_status="${sitemap_status: -3}"
    [[ "$sitemap_status" != "200" ]] && continue
    sitemap_out=$(curl -sL --max-time 10 "$_smap_url" 2>/dev/null || true)
    if echo "$sitemap_out" | grep -qE "<loc>|<sitemap>|<urlset"; then
      local url_count
      local url_count=0
      url_count=$(echo "$sitemap_out" | grep -c "<loc>" 2>/dev/null) || url_count=0
      url_count=${url_count//[^0-9]/}; url_count=${url_count:-0}
      info "sitemap.xml found: $_smap_url ($url_count URLs)"
      echo "$sitemap_out" | grep -o '<loc>[^<]*</loc>' | sed 's/<[^>]*>//g' | head -10 \
        | while read -r l; do result "$l"; done
      [[ "$url_count" -gt 10 ]] && result "... and $((url_count - 10)) more"
      echo "$sitemap_out" > "${OUT_DIR}/sitemap.txt"
      sitemap_found=true
      break
    fi
  done
  $sitemap_found || info "sitemap.xml - not found"

  echo ""
  # WhatWeb
  if tool_ok "whatweb"; then
    info "WhatWeb technology fingerprint"
    local ww_out
    # WhatWeb - try multiple targets and aggression levels
    local ww_raw
    # First try with -a 1 (stealthy) to avoid WAF blocks
    ww_raw=$(timeout 60 whatweb -a 1 --follow-redirect=always --user-agent "$UA"       --color=never "$wh_url" 2>/dev/null || true)
    # If empty, try www. prefix
    if [[ -z "$ww_raw" ]] || echo "$ww_raw" | grep -q "ERROR\|refused\|No response"; then
      ww_raw=$(timeout 60 whatweb -a 1 --follow-redirect=always --user-agent "$UA"         --color=never "https://www.${wh_target}" 2>/dev/null || true)
    fi
    # Final fallback to http://
    if [[ -z "$ww_raw" ]] || echo "$ww_raw" | grep -q "ERROR\|refused\|No response"; then
      ww_raw=$(timeout 60 whatweb -a 1 --follow-redirect=always --user-agent "$UA"         --color=never "http://${wh_target}" 2>/dev/null || true)
    fi
    if [[ -n "$ww_raw" ]]; then
      echo "$ww_raw" > "${OUT_DIR}/whatweb.txt"
      # Parse cleanly - URL+status first, then each [Field] on own line
      echo "$ww_raw" | sed 's/\x1b\[[0-9;]*m//g; s/\[[0-9;]*m//g' | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        url_part=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
        status_part=$(echo "$line" | grep -oE '\[[0-9]{3}[^]]*\]' | head -1)
        [[ -n "$url_part" ]] && result "$url_part $status_part"
        echo "$line" | grep -oE '[A-Za-z][A-Za-z0-9_-]+\[[^]]{1,80}\]' \
          | grep -vE "^\[|^[0-9]" \
          | while read -r field; do
              # Clean Email fields: decode HTML entities, strip placeholders
              if echo "$field" | grep -q "^Email\["; then
                field=$(echo "$field" \
                  | sed 's/u003e//g; s/u003c//g; s/u0026//g; s/&gt;//g; s/&lt;//g' \
                  | sed 's/Email\[//; s/\]$//' \
                  | tr ',' '\n' \
                  | grep -vE "^email@|@domain\.|@example\.|@test\.|placeholder|noreply@example|your@|name@|user@" \
                  | grep -E "@" \
                  | tr '\n' ',' | sed 's/,$//' )
                [[ -n "$field" ]] && result "  Email[$field]"
              else
                result "  $field"
              fi
            done
      done
    else
      warn "WhatWeb: no fingerprint returned"
    fi
  else
    skip "whatweb"
  fi

  echo ""
  # wafw00f — retry once if output is empty or incomplete
  if tool_ok "wafw00f"; then
    local _waf_attempts=0
    while [[ $_waf_attempts -lt 2 ]]; do
      _waf_attempts=$((_waf_attempts + 1))
      > "${OUT_DIR}/wafw00f.txt"
      run_timed "WAF detection" 120 bash -c "wafw00f -a '$wh_url' > '${OUT_DIR}/wafw00f.txt' 2>/dev/null || wafw00f '$wh_url' > '${OUT_DIR}/wafw00f.txt' 2>/dev/null"
      sleep 2  # allow file write to flush
      # Check if we got a real final result — not just the [*] Checking line
      if grep -qE "is behind|not found|No WAF|Number of requests" "${OUT_DIR}/wafw00f.txt" 2>/dev/null; then
        break
      fi
      [[ $_waf_attempts -lt 2 ]] && info "WAF detection incomplete — retrying..."
    done
    if [[ -s "${OUT_DIR}/wafw00f.txt" ]]; then
      cat "${OUT_DIR}/wafw00f.txt" | while IFS= read -r l; do result "$l"; done
      if ! grep -qE "is behind|not found|No WAF|Number of requests" "${OUT_DIR}/wafw00f.txt" 2>/dev/null; then
        warn "wafw00f did not return a result — WAF detection inconclusive — skipping sensitive path scan"
        WAF_DETECTED=true
        # Also check headers for more specific WAF identification
        if grep -qiE "^x-cdn:|^x-iinfo:|server.*cloudflare|server.*imperva|server.*incapsula|server.*bigip|server.*akamai" "${OUT_DIR}/web_headers.txt" 2>/dev/null; then
          warn "WAF confirmed via response headers"
        fi
      fi
    fi
  else
    skip "wafw00f"
  fi
}

# ================================================================
#  MODULE: SENSITIVE PATH SCANNING
# ================================================================

run_sensitive_paths() {
  module_enabled "web-headers" || return
  [[ -z "$DOMAIN" && -z "$IP" ]] && return
  local wh_target="${DOMAIN:-$IP}"
  local wh_url="${TARGET_URL:-https://$wh_target}"
  local UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

  echo ""
  # Skip sensitive path scan if WAF detected — too many false positives and blocks
  if $WAF_DETECTED || $WAF_IS_CLOUDFLARE; then
    info "Sensitive path scanning"
    local _waf_name="WAF"
    $WAF_IS_CLOUDFLARE && _waf_name="Cloudflare"
    info "WAF detected ($_waf_name) — skipping sensitive path scan to avoid false positives and IP blocks"
    return
  fi
  info "Sensitive path scanning"
  local sensitive_paths=(
    # WordPress
    "/wp-login.php" "/wp-admin/" "/xmlrpc.php" "/wp-json/wp/v2/users"
    "/wp-config.php" "/wp-config.php.bak" "/wp-config.php~"
    # Environment & secrets
    "/.env" "/.env.local" "/.env.backup" "/.env.production" "/.env.staging"
    # Git & version control
    "/.git/config" "/.git/HEAD" "/.git/COMMIT_EDITMSG" "/.svn/entries"
    # Config files
    "/config.php" "/config.yaml" "/config.yml" "/config.json"
    "/settings.py" "/settings.php" "/web.config" "/app.config"
    "/database.yml" "/database.php" "/db.php"
    # Admin panels
    "/admin/" "/administrator/" "/admin/login" "/admin/dashboard"
    "/login" "/console" "/cpanel" "/plesk" "/phpmyadmin/"
    # API & docs
    "/api/" "/v1/" "/v2/" "/v3/"
    "/swagger/" "/swagger-ui.html" "/swagger.json" "/openapi.json"
    "/api-docs" "/graphql"
    # Server info
    "/server-status" "/server-info" "/.htaccess" "/phpinfo.php"
    "/info.php" "/test.php" "/debug.php"
    # Logs
    "/debug.log" "/error.log" "/access.log" "/app.log"
    "/logs/error.log" "/logs/debug.log" "/storage/logs/laravel.log"
    # Backups
    "/backup.zip" "/backup.tar.gz" "/backup.sql" "/backup.sql.gz"
    "/database.sql" "/db.sql" "/dump.sql" "/site.zip"
    "/backup/" "/backups/" "/old/" "/archive/"
    # Framework & build files
    "/composer.json" "/composer.lock" "/package.json" "/package-lock.json"
    "/Dockerfile" "/.dockerenv" "/docker-compose.yml"
    "/Gemfile" "/requirements.txt" "/yarn.lock"
    # Spring Boot actuator
    "/actuator" "/actuator/health" "/actuator/env" "/actuator/mappings"
    "/actuator/beans" "/actuator/metrics"
    # macOS & misc
    "/.DS_Store" "/thumbs.db" "/.bash_history" "/.ssh/id_rsa"
    "/robots.txt~" "/sitemap.xml.gz"
  )
  local _sp_total=${#sensitive_paths[@]}
  if $WAF_IS_CLOUDFLARE; then
    info "Cloudflare WAF active — only showing 200/401 findings (403s are WAF blocks)"
  elif $WAF_DETECTED; then
    info "WAF active — 403 responses may be WAF blocks, not real exposures"
  fi
  local sens_hits=0
  local cdn_catchall_count=0
  # Follow redirect to find the real base URL (e.g. apex -> www.)
  local check_url="${TARGET_URL:-https://$DOMAIN}"
  local final_url
  local _curl_out
  _curl_out=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
    -o /dev/null -w "%{url_effective}" -L "${check_url}/" 2>/dev/null)
  final_url=$(echo "$_curl_out" | tr -d '\r\n' | grep -oE 'https?://[^/ ]+' | head -1)
  final_url="${final_url:-$check_url}"
  [[ -n "$final_url" && "$final_url" != "$check_url" ]] && \
    info "Sensitive paths — following redirect to $final_url"
  check_url="$final_url"

  # Fetch baseline homepage — size used for catch-all detection, body used for WAF block detection
  local baseline_size baseline_body waf_block_size=0
  waf_blocked=false  # global — used by dirsearch and other active modules

  # Detect wildcard 403 — probe a random path; if it returns 403, server blocks everything
  local _sp_rand_code
  _sp_rand_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    "${check_url}/reconomew_probe_$(date +%s)" 2>/dev/null || echo 000)
  _sp_rand_code=$(echo "$_sp_rand_code" | grep -oE "[0-9]{3}$" || echo 000)
  if [[ "$_sp_rand_code" == "403" ]]; then
    warn "Wildcard 403 detected — server returns 403 for all paths, sensitive path scan skipped"
    return
  fi
  baseline_size=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
    -o /dev/null -w "%{size_download}" "${check_url}/" 2>/dev/null || echo 0)
  baseline_size=${baseline_size//[^0-9]/}; baseline_size=${baseline_size:-0}

  # If baseline is 0, try with -L to follow redirects, then try www. prefix
  if [[ "$baseline_size" -eq 0 ]]; then
    baseline_size=$(curl -skL --max-time 8 -H "User-Agent: $UA" \
      -o /dev/null -w "%{size_download}" "${check_url}/" 2>/dev/null || echo 0)
    baseline_size=${baseline_size//[^0-9]/}; baseline_size=${baseline_size:-0}
  fi
  # Fallback 1: try HTTP if HTTPS failed
  if [[ "$baseline_size" -eq 0 && "$check_url" == https://* ]]; then
    local http_url="http://${check_url#https://}"
    local http_size
    http_size=$(curl -skL --max-time 8 -H "User-Agent: $UA" \
      -o /dev/null -w "%{size_download}" "${http_url}/" 2>/dev/null || echo 0)
    http_size=${http_size//[^0-9]/}; http_size=${http_size:-0}
    if [[ "$http_size" -gt 0 ]]; then
      baseline_size="$http_size"
      check_url="$http_url"
      info "Sensitive paths — using HTTP (no HTTPS): $check_url"
    fi
  fi
  # Fallback 2: try www. if bare domain failed
  if [[ "$baseline_size" -eq 0 && -n "$DOMAIN" && "$check_url" != *"www."* ]]; then
    for _www_scheme in https http; do
      local www_url="${_www_scheme}://www.${DOMAIN}"
      local www_size
      www_size=$(curl -skL --max-time 8 -H "User-Agent: $UA" \
        -o /dev/null -w "%{size_download}" "${www_url}/" 2>/dev/null || echo 0)
      www_size=${www_size//[^0-9]/}; www_size=${www_size:-0}
      if [[ "$www_size" -gt 0 ]]; then
        baseline_size="$www_size"
        check_url="$www_url"
        info "Sensitive paths — using ${_www_scheme}://www. baseline: $check_url"
        break
      fi
    done
  fi

  local baseline_body_size="$baseline_size"

  # Also fetch body content to detect WAF block pages mid-scan
  baseline_body=$(curl -sk --max-time 8 -H "User-Agent: $UA" -L "${check_url}/" 2>/dev/null | head -c 2000 || true)

  if [[ "$baseline_size" -eq 0 ]]; then
    warn "Baseline fetch failed for ${check_url}/ — catch-all detection disabled"
    # Baseline failure often means WAF is blocking — treat as WAF detected
    WAF_DETECTED=true
  fi

  # Fetch a known-nonexistent path to establish WAF block fingerprint
  local waf_test_body waf_test_size
  waf_test_body=$(curl -sk --max-time 8 -H "User-Agent: $UA" -L \
    "${check_url}/reconomew-definitely-does-not-exist-$(date +%s)" 2>/dev/null | head -c 2000 || true)
  waf_test_size=$(echo "$waf_test_body" | wc -c | tr -d ' ')

  # Detect WAF block fingerprints in the 404 response
  if echo "$waf_test_body" | grep -qiE "unauthorized activity|case number|blocked|your ip|access denied|security policy|ray id|cloudflare|you have been blocked"; then
    waf_blocked=true
    waf_block_size="$waf_test_size"
    warn "WAF block page detected — scan results will be unreliable"
    warn "The WAF is returning block pages for all requests from this IP"
    warn "Try again from a different IP or use a proxy"
  fi

  local _sp_done=0 waf_block_hits=0
  local _sp_start; _sp_start=$(date +%s)
  for path in "${sensitive_paths[@]}"; do
    _sp_done=$((_sp_done + 1))
    local _sp_elapsed=$(( $(date +%s) - _sp_start ))
    printf "\r  \033[0;36m[→]\033[0m Sensitive paths — %d/%d — %ds\033[K" \
      "$_sp_done" "$_sp_total" "$_sp_elapsed"
    local status body_size
    local full_url="${check_url}${path}"
    # Helper: clear arrow line, print finding permanently, arrow redraws on next loop tick
    _sp_print() {
      printf "\r\033[2K"
      "$@"
    }

    # Get status WITHOUT following redirects first
    local resp
    resp=$(curl -sk --max-time 8 \
      -H "User-Agent: $UA" \
      -w "\n__STATUS__%{http_code}__SIZE__%{size_download}" \
      -o /dev/null \
      "$full_url" 2>/dev/null || echo "__STATUS__000__SIZE__0")
    status=$(echo "$resp" | grep -o '__STATUS__[0-9]*' | sed 's/__STATUS__//')
    body_size=$(echo "$resp" | grep -o '__SIZE__[0-9]*' | sed 's/__SIZE__//')

    if [[ "$status" == "200" ]]; then
      body_size=${body_size//[^0-9]/}; body_size=${body_size:-0}

      # Skip if WAF is blocking — body size matches known WAF block page size
      if $waf_blocked; then
        local waf_diff=$(( body_size - waf_block_size ))
        [[ $waf_diff -lt 0 ]] && waf_diff=$(( -waf_diff ))
        if [[ $waf_diff -lt 200 ]]; then
          ((waf_block_hits++))
          continue  # silent skip — we already warned about WAF blocking
        fi
      fi

      # Skip if body size matches homepage baseline (CDN catch-all false positive)
      local size_diff=$(( body_size - baseline_size ))
      [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))
      if [[ $size_diff -lt 500 && "$baseline_size" -gt 100 ]]; then
        ((cdn_catchall_count++))
        result "  [skip] $path — same size as homepage (catch-all)"
        continue
      fi
      _sp_print warn "[$status] $full_url"
      ((sens_hits++))

    elif [[ "$status" == "401" ]]; then
      _sp_print warn "[$status] $full_url"
      ((sens_hits++))

    elif [[ "$status" == "403" ]]; then
      # Behind a WAF, 403 means the WAF blocked the request — not a real finding
      if $WAF_DETECTED || $WAF_IS_CLOUDFLARE; then
        continue  # skip 403s behind WAF — they are WAF blocks, not real exposures
      fi
      _sp_print warn "[$status] $full_url"
      ((sens_hits++))

    elif [[ "$status" =~ ^(301|302)$ ]]; then
      # Follow the redirect and check where it actually goes
      local redirect_dest final_status final_body_size
      redirect_dest=$(curl -sk --max-time 8 -H "User-Agent: $UA" \
        -o /dev/null -w "%{redirect_url}" "$full_url" 2>/dev/null || true)
      # Get the final response after following all redirects
      local final_resp
      final_resp=$(curl -skL --max-time 8 \
        -H "User-Agent: $UA" \
        -w "\n__STATUS__%{http_code}__SIZE__%{size_download}" \
        -o /dev/null \
        "$full_url" 2>/dev/null || echo "__STATUS__000__SIZE__0")
      final_status=$(echo "$final_resp" | grep -o '__STATUS__[0-9]*' | sed 's/__STATUS__//')
      final_body_size=$(echo "$final_resp" | grep -o '__SIZE__[0-9]*' | sed 's/__SIZE__//')

      # If redirect lands on a page same size as homepage - catch-all, skip
      final_body_size=${final_body_size//[^0-9]/}; final_body_size=${final_body_size:-0}
      local final_diff=$(( final_body_size - baseline_body_size ))
      [[ $final_diff -lt 0 ]] && final_diff=$(( -final_diff ))
      if [[ $final_diff -lt 500 && "$baseline_body_size" -gt 100 ]]; then
        ((cdn_catchall_count++))
        result "  [skip] $path — redirect lands on same-size page (catch-all)"
        continue
      fi

      # Skip trailing-slash redirects (e.g. /server-status -> /server-status/)
      local redirect_path
      redirect_path=$(echo "$redirect_dest" | sed 's|https\?://[^/]*||' || true)
      local original_path_slash="${path%/}/"
      if [[ "$redirect_path" == "$original_path_slash" || "$redirect_path" == "$path" ]]; then
        ((cdn_catchall_count++))
        continue
      fi

      # Skip same-host http->https redirect (not a finding)
      local redirect_host
      redirect_host=$(echo "$redirect_dest" | grep -oE 'https?://[^/]+' || true)
      local redirect_scheme="${redirect_host%%://*}"
      local check_scheme="${check_url%%://*}"
      local redirect_hostname="${redirect_host#*://}"
      local check_hostname="${check_url#*://}"
      if [[ "$redirect_hostname" == "$check_hostname" && "$redirect_scheme" == "https" && "$check_scheme" == "http" ]]; then
        ((cdn_catchall_count++))
        continue
      fi

      # Different host redirect — only report if final status is interesting
      if [[ -n "$redirect_host" && "$redirect_host" != "$check_url" ]]; then
        if [[ "$final_status" =~ ^(200|401)$ ]]; then
          _sp_print result "[$status→$final_status] $full_url → $redirect_dest"
          ((sens_hits++))
        elif [[ "$final_status" == "403" ]] && ! $WAF_DETECTED && ! $WAF_IS_CLOUDFLARE; then
          _sp_print result "[$status→$final_status] $full_url → $redirect_dest"
          ((sens_hits++))
        fi
        continue
      fi

      # Same-host redirect to a real page — worth reporting
      if [[ "$final_status" =~ ^(200|401)$ ]]; then
        _sp_print result "[$status→$final_status] $full_url"
        ((sens_hits++))
      elif [[ "$final_status" == "403" ]] && ! $WAF_DETECTED && ! $WAF_IS_CLOUDFLARE; then
        _sp_print result "[$status→$final_status] $full_url"
        ((sens_hits++))
      fi
    fi
  done
  printf "\r\033[2K"
  if $waf_blocked && [[ "$waf_block_hits" -gt 0 ]]; then
    warn "Sensitive path scan: WAF blocked $waf_block_hits requests — results unreliable"
  fi
  if [[ "$sens_hits" -gt 0 ]]; then
    info "Sensitive path scan done: $sens_hits finding(s)"
  elif [[ "$cdn_catchall_count" -gt 0 ]]; then
    info "Sensitive path scan done: no real findings ($cdn_catchall_count catch-all skipped)"
  else
    info "Sensitive path scan done: nothing found"
  fi
}

