#!/usr/bin/env bash
# RECONOMEW — asn_email.sh
# Modules: ASN Enumeration, Email Security (SPF/DKIM/DMARC)

# ================================================================
#  MODULE: ASN / IP OWNERSHIP
# ================================================================

run_asn() {
  module_enabled "asn" || return
  section "IP / ASN Ownership"

  # Collect unique IPs from $IP and resolved IPs of $DOMAIN
  declare -A seen_ips
  local ips=()
  if [[ -n "$IP" ]]; then
    ips+=("$IP")
    seen_ips["$IP"]=1
  fi
  if [[ -n "$DOMAIN" ]]; then
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || continue
      [[ -z "${seen_ips[$ip]:-}" ]] && ips+=("$ip") && seen_ips["$ip"]=1
    done < <(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null || true)
  fi

  local asn_out=""
  declare -A seen_asns

  for ip in "${ips[@]}"; do
    printf "  \033[0;36m[→]\033[0m ASN lookup: $ip\r"

    # ── 1. cymru BGP lookup ──
    local cymru_out asn_num asn_name cymru_prefix cymru_cc
    cymru_out=$(timeout 10 whois -h whois.cymru.com " -v $ip" 2>/dev/null \
      | grep -vE "^$|^#|^Bulk" || true)

    # Parse cymru data row: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    asn_num=$(echo "$cymru_out"    | awk 'NR==2{print $1}' | tr -d ' ' | grep -E '^[0-9]+$' || true)
    cymru_prefix=$(echo "$cymru_out" | awk 'NR==2{print $3}' | tr -d ' ' || true)
    cymru_cc=$(echo "$cymru_out" | awk 'NR==2{print $4}' | tr -d ' |' | grep -E '^[A-Z]{2}$' || true)
    asn_name=$(echo "$cymru_out"   | awk 'NR==2{$1=$2=$3=$4=$5=$6=""; gsub(/^[[:space:]]+/,"",$0); print}' | sed 's/, .*$//' || true)

    # Deduplicate by ASN
    if [[ -n "$asn_num" && -n "${seen_asns[$asn_num]:-}" ]]; then
      printf "\r\033[2K"
      info "ASN lookup: $ip — same AS${asn_num} (duplicate, skipped)"
      continue
    fi
    [[ -n "$asn_num" ]] && seen_asns["$asn_num"]=1

    # ── 2. ipinfo.io enrichment ──
    local ipinfo="" ipinfo_org="" ipinfo_city="" ipinfo_country="" ipinfo_hostname="" ipinfo_region=""
    ipinfo=$(curl -s --max-time 10 "https://ipinfo.io/$ip/json" 2>/dev/null || true)
    if [[ -n "$ipinfo" ]] && echo "$ipinfo" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d.get('org') else 1)" 2>/dev/null; then
      ipinfo_org=$(echo "$ipinfo"      | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('org',''))"      2>/dev/null || true)
      ipinfo_city=$(echo "$ipinfo"     | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('city',''))"     2>/dev/null || true)
      ipinfo_country=$(echo "$ipinfo"  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('country',''))"  2>/dev/null || true)
      ipinfo_region=$(echo "$ipinfo"   | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('region',''))"   2>/dev/null || true)
      ipinfo_hostname=$(echo "$ipinfo" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('hostname',''))" 2>/dev/null || true)
    else
      # Fallback: ip-api.com (free, no key needed)
      local ipapi
      ipapi=$(curl -s --max-time 8 "http://ip-api.com/json/$ip?fields=status,org,city,regionName,country,countryCode" 2>/dev/null || true)
      if [[ -n "$ipapi" ]]; then
        ipinfo_org=$(echo "$ipapi"     | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('org',''))"         2>/dev/null || true)
        ipinfo_city=$(echo "$ipapi"    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('city',''))"        2>/dev/null || true)
        ipinfo_region=$(echo "$ipapi"  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('regionName',''))"  2>/dev/null || true)
        ipinfo_country=$(echo "$ipapi" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('countryCode',''))" 2>/dev/null || true)
      fi
    fi

    # Extract ASN from ipinfo org if cymru missed it (e.g. Cloudflare IPs)
    if [[ -z "$asn_num" && -n "$ipinfo_org" ]]; then
      asn_num=$(echo "$ipinfo_org" | grep -oE '^AS[0-9]+' | tr -d 'AS' || true)
      asn_name=$(echo "$ipinfo_org" | sed 's/^AS[0-9]* //' || true)
      # Still deduplicate
      if [[ -n "$asn_num" && -n "${seen_asns[$asn_num]:-}" ]]; then
        printf "\r\033[2K"
        info "ASN lookup: $ip — same AS${asn_num} (duplicate, skipped)"
        continue
      fi
      [[ -n "$asn_num" ]] && seen_asns["$asn_num"]=1
    fi

    printf "\r\033[2K"
    info "ASN lookup: $ip"

    # ── Display: structured and consistent ──
    [[ -n "$asn_num"       ]] && result "ASN      : AS${asn_num}${asn_name:+ — $asn_name}"
    [[ -n "$cymru_prefix"  ]] && result "Prefix   : $cymru_prefix"
    [[ -n "$ipinfo_org" && -z "$asn_num" ]] && result "Org      : $ipinfo_org"
    [[ -n "$ipinfo_hostname" ]] && result "Hostname : $ipinfo_hostname"
    local location=""
    [[ -n "$ipinfo_city"    ]] && location+="$ipinfo_city"
    [[ -n "$ipinfo_region"  ]] && location+=", $ipinfo_region"
    [[ -n "$ipinfo_country" ]] && location+=" ($ipinfo_country)"
    [[ -n "$location"       ]] && result "Location : $location"
    [[ -n "$cymru_cc" && -z "$ipinfo_country" ]] && result "Country  : $cymru_cc"
    # If nothing resolved, show failure message
    if [[ -z "$asn_num" && -z "$ipinfo_org" && -z "$ipinfo_city" ]]; then
      result "(ASN lookup failed — check connectivity to ipinfo.io and whois.cymru.com)"
    fi

    asn_out+="=== $ip ===
ASN: ${asn_num:-N/A} $asn_name
Prefix: ${cymru_prefix:-N/A}
Org: ${ipinfo_org:-N/A}
Hostname: ${ipinfo_hostname:-N/A}
Location: ${ipinfo_city:-N/A}, ${ipinfo_country:-N/A}
"
  done
  echo "$asn_out" > "${OUT_DIR}/asn.txt"
}

# ================================================================
#  MODULE: EMAIL SECURITY
# ================================================================

run_email_security() {
  module_enabled "email-security" || return
  [[ -z "$DOMAIN" ]] && return
  section "Email Security (SPF / DKIM / DMARC)"

  # Use apex domain — SPF/DMARC/DKIM are set on apex, not subdomains
  local email_domain
  email_domain=$(get_apex_domain "$DOMAIN")
  [[ "$email_domain" != "$DOMAIN" ]] && info "Using apex domain for email checks: $email_domain"

  info "SPF record"
  local spf
  spf=$(dig +short TXT "$email_domain" @1.1.1.1 2>/dev/null \
    | grep -i "v=spf1" | head -1 || true)
  if [[ -n "$spf" ]]; then
    result "$spf"
    if echo "$spf" | grep -q "~all"; then
      warn "SPF uses ~all (softfail) - consider -all for stricter enforcement"
    elif echo "$spf" | grep -q "+all"; then
      warn "SPF uses +all - dangerous, allows any server to send as this domain"
    else
      result "SPF policy looks good"
    fi
  else
    warn "No SPF record found - email spoofing may be possible"
  fi

  info "DMARC record"
  local dmarc
  dmarc=$(dig +short TXT "_dmarc.$email_domain" @1.1.1.1 2>/dev/null \
    | grep -i "v=dmarc1" | head -1 || true)
  if [[ -n "$dmarc" ]]; then
    result "$dmarc"
    if echo "$dmarc" | grep -qi "p=none"; then
      warn "DMARC policy is p=none - monitor only, no enforcement"
    elif echo "$dmarc" | grep -qi "p=quarantine"; then
      result "DMARC: quarantine policy (good)"
    elif echo "$dmarc" | grep -qi "p=reject"; then
      result "DMARC: reject policy (best)"
    fi
  else
    warn "No DMARC record - email spoofing protection missing"
  fi

  info "DKIM selectors (common)"
  local dkim_found=0
  for sel in default google mail dkim selector1 selector2 k1 s1 s2 smtp; do
    local r
    r=$(dig +short TXT "$sel._domainkey.$email_domain" @1.1.1.1 2>/dev/null \
      | grep -ivE "communications error|timed out|no servers|^;;" \
      | grep -iE "DKIM|p=" || true)
    if [[ -n "$r" ]]; then
      result "$sel: $r"
      dkim_found=$((dkim_found+1))
    fi
  done
  [[ "$dkim_found" -eq 0 ]] && warn "No DKIM selectors found - email authentication incomplete"
}

# ================================================================
#  MODULE: WEB HEADERS / TECH DETECTION
# ================================================================

