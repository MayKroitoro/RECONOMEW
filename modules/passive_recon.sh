#!/usr/bin/env bash
# RECONOMEW — passive_recon.sh
# Modules: WHOIS, DNS, TLS, Certificate Transparency, Subdomain Enumeration

# ================================================================
#  MODULE: WHOIS
# ================================================================


# Get the true registrable domain (handles .co.uk, .com.au, .org.uk etc)
get_apex_domain() {
  local domain="$1"
  local two_part_tlds="co.uk com.au org.uk net.uk org.au net.au co.nz org.nz net.nz co.za org.za co.in org.in net.in com.br org.br net.br co.jp or.jp ne.jp com.mx co.kr or.kr co.il org.il co.th com.sg com.hk co.id com.my com.ph com.tr gov.uk ac.uk me.uk"
  local parts
  IFS='.' read -ra parts <<< "$domain"
  local n=${#parts[@]}
  if [[ $n -lt 2 ]]; then
    echo "$domain"; return
  fi
  # Check if last two parts form a known 2-part TLD
  local last2="${parts[$((n-2))]}.${parts[$((n-1))]}"
  if echo "$two_part_tlds" | grep -qw "$last2"; then
    # Need at least 3 parts for a real domain under 2-part TLD
    if [[ $n -ge 3 ]]; then
      echo "${parts[$((n-3))]}.$last2"
    else
      echo "$domain"
    fi
  else
    # Standard TLD - apex is last 2 parts
    echo "${parts[$((n-2))]}.${parts[$((n-1))]}"
  fi
}

run_whois() {
  module_enabled "whois" || return
  section "WHOIS Lookup"

  # Extract apex domain for WHOIS - handles .co.uk, .com.au etc
  local target="${DOMAIN:-$IP}"
  if [[ -n "$DOMAIN" ]]; then
    local apex; apex=$(get_apex_domain "$DOMAIN")
    target="$apex"
  fi

  printf "  \033[0;36m[→]\033[0m WHOIS querying: $target\r"
  local whois_out

  # Try standard whois first, then explicit servers for new TLDs
  whois_out=$(timeout 30 whois "$target" 2>/dev/null || true)

  # New TLDs (.shop, .io, .app etc) often need explicit WHOIS server
  if [[ -z "$whois_out" || ${#whois_out} -lt 100 ]]; then
    local tld="${target##*.}"
    local whois_server=""
    case "$tld" in
      shop)   whois_server="whois.nic.shop" ;;
      io)     whois_server="whois.nic.io" ;;
      app)    whois_server="whois.nic.google" ;;
      dev)    whois_server="whois.nic.google" ;;
      co)     whois_server="whois.nic.co" ;;
      me)     whois_server="whois.nic.me" ;;
      info)   whois_server="whois.afilias.net" ;;
      biz)    whois_server="whois.biz" ;;
      online) whois_server="whois.nic.online" ;;
      store)  whois_server="whois.nic.store" ;;
      site)   whois_server="whois.nic.site" ;;
    esac
    if [[ -n "$whois_server" ]]; then
      whois_out=$(timeout 30 whois -h "$whois_server" "$target" 2>/dev/null || true)
    fi
    # Last resort: try IANA whois
    if [[ -z "$whois_out" || ${#whois_out} -lt 100 ]]; then
      whois_out=$(timeout 30 whois -h "whois.iana.org" "$target" 2>/dev/null || true)
    fi
  fi

  # For auto-resolved domains (IP->hostname), also try the IP directly
  if $DOMAIN_AUTO_RESOLVED && [[ -n "$IP" ]]; then
    local ip_whois
    ip_whois=$(timeout 30 whois "$IP" 2>/dev/null || true)
    [[ -z "$whois_out" || "$whois_out" == *"Malformed"* ]] && whois_out="$ip_whois"
  fi

  printf "\r\033[2K"
  # Save full raw output
  echo "$whois_out" > "${OUT_DIR}/whois.txt"
  log_raw "$whois_out"

  if [[ -z "$whois_out" ]]; then
    printf "\r\033[2K"
    warn "WHOIS returned no data — trying RDAP fallback..."
    local rdap_out
    rdap_out=$(curl -s --max-time 15 \
      -H "Accept: application/rdap+json" \
      "https://rdap.org/domain/$target" 2>/dev/null || true)
    if [[ -n "$rdap_out" ]]; then
      echo "$rdap_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    for e in d.get('events',[]):
        act = e.get('eventAction',''); dt = e.get('eventDate','')[:10]
        if act == 'registration': print('Created   :', dt)
        if act == 'expiration':   print('Expires   :', dt)
        if act == 'last changed': print('Updated   :', dt)
    for ent in d.get('entities',[]):
        if 'registrar' in ent.get('roles',[]):
            vc = ent.get('vcardArray',[None,[]])[1]
            nm = next((v[3] for v in vc if isinstance(v,list) and v[0]=='fn'),'')
            if nm: print('Registrar :', nm)
        for role in ['registrant','administrative','technical']:
            if role in ent.get('roles',[]):
                vc = ent.get('vcardArray',[None,[]])[1]
                nm  = next((v[3] for v in vc if isinstance(v,list) and v[0]=='fn'),'')
                org = next((v[3] for v in vc if isinstance(v,list) and v[0]=='org'),'')
                em  = next((v[3] for v in vc if isinstance(v,list) and v[0]=='email'),'')
                if nm:  print(role.title()+' Name  :', nm)
                if org: print(role.title()+' Org   :', org)
                if em:  print(role.title()+' Email :', em)
    for ns in d.get('nameservers',[]): print('Name Server:', ns.get('ldhName',''))
    status = d.get('status',[])
    if status: print('Status     :', ', '.join(status))
except: pass
" 2>/dev/null | while IFS= read -r line; do result "$line"; done
      echo "$rdap_out" > "${OUT_DIR}/whois.txt"
      info "RDAP data retrieved for $target"
    else
      warn "WHOIS and RDAP both returned no data for $target"
    fi
    return
  fi

  info "WHOIS data retrieved: $target"
  # ── Domain query: extract all useful structured fields ──
  if [[ -n "$DOMAIN" ]]; then
    local fields whois_section
    # If output has multiple WHOIS sections (TLD registry + registrar), use last section
    # Split on blank lines between sections and take the last meaningful one
    if echo "$whois_out" | grep -qiE "^Domain Name:|^domain:[[:space:]]*[a-zA-Z0-9]"; then
      # Find the last block containing "Domain Name:" (registrar data)
      whois_section=$(echo "$whois_out" | awk '
        /^[[:space:]]*$/ { if(block ~ /Domain Name:|domain:/) last=block; block=""; next }
        { block = block "\n" $0 }
        END { if(block ~ /Domain Name:|domain:/) last=block; print last }
      ')
      [[ -n "$whois_section" ]] && whois_out="$whois_section"
    fi
    # Broad extraction — any "Key: Value" line that looks useful
    fields=$(echo "$whois_out" \
      | grep -E "^[[:space:]]*[A-Za-z ]+:[[:space:]]*[^[:space:]]" \
      | grep -ivE ">>|WHOIS|http|ftp|query|abuse|iana|url|notice|terms|please|refer|last.update|for more|registrar.*id|registrar.*iana|billing|allow|enable|otherwise|transmission|mass|unsolicited|commercial|advertising" \
      | grep -vE "^[[:space:]]*(to|by|of|in|or|and|the|you|this|such|any|our|your|its)[[:space:]]" \
      | sed 's/^[[:space:]]*//' \
      | grep -v ":[[:space:]]*$" \
      | awk -F": " '{key=tolower($1); gsub(/[[:space:]]+/,"",key); if(!seen[key]++) print}' \
      | head -30 || true)
    [[ -n "$fields" ]] && echo "$fields" | while IFS= read -r line; do result "$line"; done

  # ── IP query: show compact network block info only ──
  else
    echo "$whois_out" \
      | grep -iE "^(NetRange|CIDR|NetName|Organization|OrgName|Country|RegDate|Updated|City):" \
      | sed 's/^[[:space:]]*//' \
      | head -12 \
      | while IFS= read -r line; do result "$line"; done
  fi

  # Extract key summary fields - only print if NOT already shown above
  local created updated expires registrar
  created=$(echo   "$whois_out" | grep -iE "creat" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1 || true)
  updated=$(echo   "$whois_out" | grep -iE "updat" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1 || true)
  expires=$(echo   "$whois_out" | grep -iE "expir" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1 || true)
  registrar=$(echo "$whois_out" | grep -iE "^[[:space:]]*Registrar:" \
    | grep -ivE "url|abuse|iana|whois server" \
    | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '\r' | cut -c1-80 || true)

  # Only show summary block for IP whois (domain already shows full fields above)
  if [[ -z "$DOMAIN" ]]; then
    [[ -n "$registrar" ]] && info "Registrar : ${W}$registrar${NC}"
    [[ -n "$created"   ]] && info "Created   : ${W}$created${NC}"
    [[ -n "$updated"   ]] && info "Updated   : ${W}$updated${NC}"
    [[ -n "$expires"   ]] && info "Expires   : ${W}$expires${NC}"
  fi

  # RDAP - silent fallback only when zero data extracted
  if [[ -z "$created" && -z "$registrar" && -z "$expires" ]] && [[ -n "$DOMAIN" ]]; then
    local rdap_out
    rdap_out=$(curl -s --max-time 15 \
      -H "Accept: application/rdap+json" \
      "https://rdap.org/domain/$DOMAIN" 2>/dev/null || true)
    if [[ -n "$rdap_out" ]]; then
      echo "$rdap_out" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    for e in d.get('events',[]):
        act = e.get('eventAction',''); dt = e.get('eventDate','')[:10]
        if act == 'registration': print('Created   :', dt)
        if act == 'expiration':   print('Expires   :', dt)
        if act == 'last changed': print('Updated   :', dt)
    for ent in d.get('entities',[]):
        if 'registrar' in ent.get('roles',[]):
            vc = ent.get('vcardArray',[None,[]])[1]
            nm = next((v[3] for v in vc if isinstance(v,list) and v[0]=='fn'),'')
            if nm: print('Registrar :', nm)
    for ns in d.get('nameservers',[]): print('Name Server:', ns.get('ldhName',''))
except: pass
" 2>/dev/null | while IFS= read -r line; do result "$line"; done
      echo "$rdap_out" >> "${OUT_DIR}/whois.txt"
    fi
  fi
}

run_dns() {
  module_enabled "dns" || return
  [[ -z "$DOMAIN" ]] && return
  section "DNS Enumeration"

  # Helper: get clean DNS records using +short, with type-specific output filtering
  # Helper: get clean DNS records
  # Uses +noall +answer to get ONLY the authoritative answer for the requested type
  # This prevents CNAME chain hops bleeding into A/MX/TXT/SOA/CAA results
  dig_clean() {
    local rtype="$1" domain="$2"
    local raw
    # +noall +answer gives only the answer section records
    # We filter by the exact record type in column 4
    raw=$(dig +noall +answer +time=5 "$rtype" "$domain" @1.1.1.1 2>/dev/null || true)
    [[ -z "$raw" ]] && return
    case "$rtype" in
      A)
        local _a_out
        _a_out=$(echo "$raw" | awk '$4=="A" {print $5}' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | sort -u)
        # Fallback: use +short if +noall +answer returned nothing (Cloudflare/CDN CNAME chains)
        if [[ -z "$_a_out" ]]; then
          _a_out=$(dig +short A "$domain" @1.1.1.1 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | sort -u || true)
        fi
        echo "$_a_out"
        ;;
      AAAA)
        local _aaaa_out
        _aaaa_out=$(echo "$raw" | awk '$4=="AAAA" {print $5}' | grep -E '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$' | sort -u)
        if [[ -z "$_aaaa_out" ]]; then
          _aaaa_out=$(dig +short AAAA "$domain" @1.1.1.1 2>/dev/null | grep -E '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$' | sort -u || true)
        fi
        echo "$_aaaa_out"
        ;;
      CNAME)
        echo "$raw" | awk '$4=="CNAME"{print $5}' | sed 's/\.$//' | sort -u
        ;;
      MX)
        echo "$raw" | awk '$4=="MX"   {print $5, $6}' | sed 's/\.$//' | sort -u
        ;;
      TXT)
        echo "$raw" | awk '$4=="TXT"  {$1=$2=$3=$4=""; gsub(/^[[:space:]]+/,"",$0); print}' | sort -u
        ;;
      SOA)
        echo "$raw" | awk '$4=="SOA"  {$1=$2=$3=$4=""; gsub(/^[[:space:]]+/,"",$0); print}' | sed 's/\.\( \|$\)/\1/g'
        ;;
      CAA)
        echo "$raw" | awk '$4=="CAA"  {$1=$2=$3=$4=""; gsub(/^[[:space:]]+/,"",$0); print}' | sort -u
        ;;
      NS)
        echo "$raw" | awk '$4=="NS"   {print $5}' | sed 's/\.$//' | sort -u
        ;;
    esac
  }
  # NS fallback: if dig_clean NS returns empty, try +short (some zones only expose NS at registrar level)
  get_ns_list() {
    local domain="$1"
    local ns_out
    ns_out=$(dig_clean NS "$domain")
    if [[ -z "$ns_out" ]]; then
      # Try authority section (non-recursive) which shows delegation NS
      ns_out=$(dig +noall +authority +time=5 NS "$domain" @1.1.1.1 2>/dev/null         | awk '$4=="NS" {print $5}' | sed 's/\.$//' | sort -u || true)
    fi
    if [[ -z "$ns_out" ]]; then
      # Last resort: extract NS from SOA primary nameserver field
      ns_out=$(dig_clean SOA "$domain" | awk '{print $1}' | sed 's/\.$//' || true)
    fi
    echo "$ns_out"
  }
  # For A/AAAA: also follow CNAME chain to get final IPs (used for PTR lookups)
  dig_follow() {
    local rtype="$1" domain="$2"
    dig +short "$rtype" "$domain" @1.1.1.1 2>/dev/null       | grep -vE "^;;|communications error|timed out|no servers"       | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'       | sort -u || true
  }

  local found_rtypes=()
  printf "  \033[0;36m[→]\033[0m Fetching DNS records...\r"
  for rtype in A AAAA CNAME MX TXT SOA; do
    local out
    out=$(dig_clean "$rtype" "$DOMAIN")
    printf "\r\033[2K"
    if [[ -n "$out" ]]; then
      found_rtypes+=("$rtype")
      info "${C}[$rtype]${NC}"
      echo "$out" | while read -r l; do result "$l"; done
      # Flag BOM or garbage bytes in TXT records
      if [[ "$rtype" == "TXT" ]] && echo "$out" | grep -qE '\\[0-9]{3}'; then
        warn "TXT record contains garbage/BOM bytes — DNS record may be corrupted"
      fi
    else
      info "${C}[$rtype]${NC} — not found"
    fi
  done
  if [[ ${#found_rtypes[@]} -gt 0 ]]; then
    local IFS=' '; info "Records found: ${found_rtypes[*]}"
  else
    warn "No DNS records found"
  fi

  info "Name Servers + their IPs"
  local NS_LIST
  NS_LIST=$(get_ns_list "$DOMAIN")
  if [[ -z "$NS_LIST" ]]; then
    result "No nameservers found"
  else
    while IFS= read -r ns; do
      [[ -z "$ns" ]] && continue
      result "NS: $ns"
      dig +short A    "$ns" @1.1.1.1 2>/dev/null | grep -E '^[0-9]'         | while read -r l; do result "    A:    $l"; done
      dig +short AAAA "$ns" @1.1.1.1 2>/dev/null | grep -E '^[0-9a-fA-F:]' | while read -r l; do result "    AAAA: $l"; done
    done <<< "$NS_LIST"
  fi

  info "Reverse DNS (PTR)"
  # Only do PTR on actual IPs — extract from A/AAAA answer sections
  local ips
  local _ptr_tmp; _ptr_tmp=$(mktemp)
  { dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null; dig +short AAAA "$DOMAIN" @1.1.1.1 2>/dev/null; } \
    | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$' \
    | sort -u > "$_ptr_tmp" 2>/dev/null
  if [[ ! -s "$_ptr_tmp" ]]; then
    result "No IPs resolved for PTR lookup"
  else
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      local ptr
      ptr=$(dig +short -x "$ip" @1.1.1.1 2>/dev/null \
        | grep -vE "^;;|communications error|timed out|NXDOMAIN|no servers" \
        | grep -E "^[a-zA-Z0-9]" | sed 's/\.$//' | head -1 || true)
      if [[ -n "$ptr" ]]; then
        result "$ip -> $ptr"
      else
        result "$ip -> (no PTR record)"
      fi
    done < "$_ptr_tmp"
  fi
  rm -f "$_ptr_tmp" 2>/dev/null

  info "Zone Transfer Attempt (AXFR)"
  if [[ -z "$NS_LIST" ]]; then
    result "No nameservers found - skipping AXFR"
  else
    while IFS= read -r ns; do
      [[ -z "$ns" ]] && continue
      local axfr
      axfr=$(dig axfr "$DOMAIN" @"$ns" +time=3 +tries=1 2>/dev/null || true)
      local clean_axfr
      clean_axfr=$(echo "$axfr" | grep -vE "communications error|end of file|timed out|network unreachable|no servers could be reached|;;" || true)
      local record_count
      record_count=$(echo "$clean_axfr" | grep -cE "^\S+\s+[0-9]+\s+IN\s+" 2>/dev/null | head -1 | tr -d '[:space:]' || echo 0)
      record_count=${record_count//[^0-9]/}
      record_count=${record_count:-0}
      if [[ "$record_count" -gt 3 ]]; then
        warn "AXFR SUCCESS on $ns - zone transfer possible! ($record_count records)"
        echo "$clean_axfr" | head -30 | while read -r l; do result "$l"; done
      else
        result "$ns -> AXFR refused (expected)"
      fi
    done <<< "$NS_LIST"
  fi

  # ── CAA records ──
  info "CAA records (certificate authority authorization)"
  local caa_out
  caa_out=$(dig_clean "CAA" "$DOMAIN")
  if [[ -n "$caa_out" ]]; then
    echo "$caa_out" | while read -r l; do result "$l"; done
  else
    result "No CAA records found — any CA can issue certs for this domain"
  fi

  # ── SRV records ──
  info "SRV records"
  local srv_found=0
  for srv in _http._tcp _https._tcp _ftp._tcp _ssh._tcp _smtp._tcp              _imap._tcp _imaps._tcp _pop3._tcp _pop3s._tcp              _xmpp-client._tcp _xmpp-server._tcp _sip._tcp _sip._udp              _sipfederationtls._tcp _autodiscover._tcp _ldap._tcp              _kerberos._tcp _caldav._tcp _carddav._tcp; do
    local srv_out
    srv_out=$(dig +short SRV "${srv}.${DOMAIN}" @1.1.1.1 2>/dev/null       | grep -vE "^;;|communications error|timed out|no servers|^$" || true)
    if [[ -n "$srv_out" ]]; then
      srv_out=$(echo "$srv_out" | sed 's/\.$//')
      result "${srv}.${DOMAIN} -> $srv_out"
      srv_found=$((srv_found + 1))
    fi
  done
  [[ "$srv_found" -eq 0 ]] && result "No SRV records found"

  # ── NS mismatch check (zone NS vs registrar NS) ──
  info "NS consistency check"
  local zone_ns registrar_ns
  zone_ns=$(get_ns_list "$DOMAIN")
  local tld_server
  # Get the TLD (.com, .net, .org etc) nameserver to check registrar delegation
  # Extract TLD from domain: seriouspizza.com -> com, sub.example.co.uk -> co.uk
  local _tld; _tld=$(echo "$DOMAIN" | rev | cut -d. -f1-2 | rev)
  # For simple TLDs like .com/.net, just use the last part
  local _dot_count; _dot_count=$(echo "$DOMAIN" | tr -cd '.' | wc -c)
  [[ "$_dot_count" -eq 1 ]] && _tld=$(echo "$DOMAIN" | rev | cut -d. -f1 | rev)
  tld_server=$(dig +short NS "$_tld" @1.1.1.1 2>/dev/null     | grep -E "^[a-zA-Z0-9]" | sed 's/\.$//' | head -1 || true)
  if [[ -n "$tld_server" ]]; then
    registrar_ns=$(dig +noall +answer +time=5 NS "$DOMAIN" @"$tld_server" 2>/dev/null \
      | awk '$4=="NS"{print $5}' | sed 's/\.$//' | sort || true)
    if [[ -n "$zone_ns" && -n "$registrar_ns" ]]; then
      if [[ "$zone_ns" == "$registrar_ns" ]]; then
        result "NS records consistent (zone matches registrar)"
      else
        warn "NS MISMATCH — zone and registrar report different nameservers"
        warn "  Zone NS      : $(echo "$zone_ns" | tr '\n' ' ')"
        warn "  Registrar NS : $(echo "$registrar_ns" | tr '\n' ' ')"
      fi
    else
      result "NS consistency: could not query parent zone"
    fi
  else
    result "NS consistency: parent zone server not found"
  fi

  # ── Dangling CNAME check ──
  info "Dangling CNAME check"
  local cname_out dangling=0
  cname_out=$(dig_clean "CNAME" "$DOMAIN")
  local www_cname
  www_cname=$(dig_clean "CNAME" "www.$DOMAIN")
  local _cname_src="$DOMAIN"
  for cname_target in $cname_out $www_cname; do
    [[ -z "$cname_target" ]] && continue
    local cname_resolves
    cname_resolves=$(dig +short A "$cname_target" @1.1.1.1 2>/dev/null       | grep -E "^[0-9]" | head -1 || true)
    if [[ -z "$cname_resolves" ]]; then
      warn "Dangling CNAME: ${_cname_src} → ${cname_target} (does not resolve) — potential takeover"
      dangling=$((dangling + 1))
    else
      result "CNAME -> $cname_target ($cname_resolves) — resolves ok"
    fi
  done
  [[ "$dangling" -eq 0 && -z "$cname_out" && -z "$www_cname" ]] && result "No CNAMEs found"

  # ── MX validation ──
  info "MX host validation"
  local mx_out mx_valid=0 mx_invalid=0
  mx_out=$(dig +short MX "$DOMAIN" @1.1.1.1 2>/dev/null \
    | grep -vE "^;;|communications error|timed out|no servers" \
    | grep -E "^[0-9]" | sort -u || true)
  if [[ -z "$mx_out" ]]; then
    result "No MX records found"
  else
    while IFS= read -r mx_line; do
      [[ -z "$mx_line" ]] && continue
      local mx_host
      # Handle "priority hostname" format — extract hostname only
      mx_host=$(echo "$mx_line" | awk '{print $NF}' | sed 's/\.$//' || true)
      [[ -z "$mx_host" ]] && continue
      local mx_resolves
      mx_resolves=$(dig +short A "$mx_host" @1.1.1.1 2>/dev/null \
        | grep -E "^[0-9]" | head -1 || true)
      if [[ -n "$mx_resolves" ]]; then
        result "$mx_host -> $mx_resolves (ok)"
        mx_valid=$((mx_valid + 1))
      else
        warn "MX host does not resolve: $mx_host — mail delivery broken"
        mx_invalid=$((mx_invalid + 1))
      fi
    done <<< "$mx_out"
    [[ "$mx_invalid" -gt 0 ]] && warn "$mx_invalid MX host(s) do not resolve"
    [[ "$mx_invalid" -eq 0 ]] && result "All $mx_valid MX host(s) resolve correctly"
  fi
}

# ================================================================
#  MODULE: TLS CERTIFICATE
# ================================================================

run_tls() {
  module_enabled "tls" || return
  [[ -z "$DOMAIN" && -z "$IP" ]] && return
  section "TLS Certificate Analysis"

  # Use domain if available, fall back to IP for connect target
  # Always use DOMAIN for connect target when available (CDN/Cloudflare needs SNI)
  local tls_host="${DOMAIN:-$IP}"
  local tls_connect="${DOMAIN:-$IP}"
  local tls_sni=""
  [[ -n "$DOMAIN" ]] && tls_sni="-servername $DOMAIN" && tls_connect="$DOMAIN"
  # If domain does not connect directly, fall back to IP with SNI
  if [[ -n "$DOMAIN" && -n "$IP" ]]; then
    local _tls_test=0
    local _tls_probe
    _tls_probe=$(echo | timeout 5 openssl s_client $tls_sni -connect "${tls_connect}:443" 2>&1 || true)
    if ! echo "$_tls_probe" | grep -qE "CONNECTED|New, TLSv|SSL-Session:"; then
      _tls_test=0
    else
      _tls_test=1
    fi
    if [[ "$_tls_test" -eq 0 ]]; then
      tls_connect="$IP"
      # Also try curl as secondary check
      local _curl_tls
      _curl_tls=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
        -H "Host: $DOMAIN" "https://$IP/" 2>/dev/null || echo 000)
      _curl_tls=$(echo "$_curl_tls" | grep -oE "[0-9]{3}$" || echo 000)
      [[ "$_curl_tls" == "000" ]] && tls_connect="$DOMAIN"  # both failed, keep domain
    fi
  fi

  printf "  \033[0;36m[→]\033[0m TLS certificate — fetching...\r"
  local cert_out
  cert_out=$(echo | timeout 15 openssl s_client \
    $tls_sni \
    -connect "${tls_connect}:443" \
    -quiet 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true)

  # Fallback 1: try www. prefix
  if [[ -z "$cert_out" && -n "$DOMAIN" ]]; then
    cert_out=$(echo | timeout 15 openssl s_client \
      -servername "www.$DOMAIN" \
      -connect "www.$DOMAIN:443" \
      -quiet 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true)
  fi

  # Fallback 2: try direct IP with SNI
  if [[ -z "$cert_out" && -n "$IP" && -n "$DOMAIN" ]]; then
    cert_out=$(echo | timeout 15 openssl s_client \
      -servername "$DOMAIN" \
      -connect "$IP:443" \
      -quiet 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true)
  fi
  printf "\r\033[2K"
  info "Certificate details (${tls_host})"

  # Fallback 3: use curl -vI and parse cleanly into Subject/Issuer/Expiry
  if [[ -z "$cert_out" && -n "$DOMAIN" ]]; then
    local curl_verbose
    curl_verbose=$(curl -svI --max-time 10 "https://$DOMAIN" 2>&1 || true)
    local subj issuer expiry alts
    subj=$(echo "$curl_verbose"    | grep -i "^\* \+subject:"   | sed 's/.*subject:[[:space:]]*//' | tr -d '\r' | head -1)
    issuer=$(echo "$curl_verbose"  | grep -i "^\* \+issuer:"    | sed 's/.*issuer:[[:space:]]*//'  | tr -d '\r' | head -1)
    expiry=$(echo "$curl_verbose"  | grep -i "expire date"      | sed 's/.*expire date:[[:space:]]*//' | tr -d '\r' | head -1)
    alts=$(echo "$curl_verbose"    | grep -i "subjectAltName\|DNS:" | sed 's/.*DNS://g' | tr ',' '\n' | grep -oE '[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}' | head -10 | tr '\n' ' ')
    if [[ -n "$subj" || -n "$issuer" ]]; then
      cert_out=""
      [[ -n "$subj"   ]] && cert_out+="Subject : $subj"$'\n'
      [[ -n "$issuer" ]] && cert_out+="Issuer  : $issuer"$'\n'
      [[ -n "$expiry" ]] && cert_out+="Expires : $expiry"$'\n'
      [[ -n "$alts"   ]] && cert_out+="Alt Names: $alts"
    fi
  fi

  if [[ -n "$cert_out" ]]; then
    # Clean and format cert output — deduplicate Alt Names, strip raw extension header
    echo "$cert_out" | python3 -c "
import sys, re
lines = sys.stdin.read().splitlines()
seen_alts = set()
for line in lines:
    # Parse subjectAltName extension — extract DNS names only
    if re.match(r'X509v3 Subject Alternative Name', line, re.I): continue
    if 'DNS:' in line:
        names = re.findall(r'DNS:([^\s,]+)', line)
        unique = [n for n in names if n not in seen_alts and not seen_alts.add(n)]
        if unique:
            print('Alt Names: ' + '  '.join(unique))
        continue
    # Print other lines as-is (Subject, Issuer, Expires)
    line = line.strip()
    if line: print(line)
" | while read -r l; do result "$l"; done
    echo "$cert_out" > "${OUT_DIR}/cert.txt"
  else
    warn "Could not retrieve TLS certificate (port 443 may be closed or behind CDN)"
  fi

  echo ""
  info "Protocol support"
  local tls_out=""
  # Use openssl s_client for version detection — more reliable than curl --tls-max
  for proto in "tls1_0" "tls1_1" "tls1_2" "tls1_3"; do
    local label ossl_flag curl_min curl_max
    case "$proto" in
      tls1_0) label="TLS 1.0"; ossl_flag="-tls1";   curl_min="--tlsv1.0"; curl_max="--tls-max 1.0" ;;
      tls1_1) label="TLS 1.1"; ossl_flag="-tls1_1"; curl_min="--tlsv1.1"; curl_max="--tls-max 1.1" ;;
      tls1_2) label="TLS 1.2"; ossl_flag="-tls1_2"; curl_min="--tlsv1.2"; curl_max="--tls-max 1.2" ;;
      tls1_3) label="TLS 1.3"; ossl_flag="-tls1_3"; curl_min="--tlsv1.3"; curl_max="" ;;
    esac
    local supported=false

    # Primary: try openssl s_client with specific version flag
    # Check for SSL-Session: which only appears on a successful TLS handshake
    local connected=0
    local _ossl_out
    _ossl_out=$(echo | timeout 6 openssl s_client \
      $tls_sni $ossl_flag \
      -connect "${tls_connect}:443" \
      2>&1 || true)
    # Check for successful handshake — different openssl versions use different output
    if echo "$_ossl_out" | grep -qE "SSL-Session:|New, TLSv[0-9]|Protocol.*TLS"; then
      supported=true
    fi

    # Fallback: curl version negotiation (handles OpenSSL builds that disable old flags)
    if ! $supported; then
      local curl_code curl_args
      curl_args="$curl_min"
      [[ -n "$curl_max" ]] && curl_args="$curl_args $curl_max"
      local _host_hdr=""
      [[ "$tls_connect" != "$DOMAIN" && -n "$DOMAIN" ]] && _host_hdr="-H \"Host: $DOMAIN\""
      curl_code=$(eval curl -sk --max-time 6 $curl_args \
        -o /dev/null -w "%{http_code}" \
        $_host_hdr \
        "https://${tls_connect}/" 2>/dev/null || echo "000")
      curl_code=$(echo "$curl_code" | tr -d '[:space:]\n' | grep -oE '[0-9]{3}$' || echo "000")
      curl_code=${curl_code:-000}
      [[ "$curl_code" =~ ^[1-5][0-9][0-9]$ ]] && supported=true
    fi

    if $supported; then
      result "$label: supported"
      tls_out+="$label: supported"$'\n'
    else
      result "$label: not supported"
    fi
  done
  echo "$tls_out" > "${OUT_DIR}/tls.txt"
}

# ================================================================
#  MODULE: CERTIFICATE TRANSPARENCY
# ================================================================

run_ct() {
  module_enabled "ct" || return
  [[ -z "$DOMAIN" ]] && return
  section "Certificate Transparency (crt.sh)"

  # Get apex domain for wide query (finds sibling subdomains too)
  local apex; apex=$(get_apex_domain "$DOMAIN")

  local ct_raw ct_raw_apex ct_out
  ct_raw=""; ct_raw_apex=""

  # Query 1: target domain wildcard (e.g. %.chocolateshops.sees.com)
  printf "  \033[0;36m[→]\033[0m Querying crt.sh for $DOMAIN..."
  for _attempt in 1 2 3; do
    ct_raw=$(curl -s --max-time 90 \
      -H "Accept: application/json" \
      -H "User-Agent: Mozilla/5.0" \
      "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null || true)
    [[ -n "$ct_raw" && "$ct_raw" != "[]" ]] && break
    if [[ -z "$ct_raw" || "$ct_raw" == "[]" ]]; then
      ct_raw=$(curl -s --max-time 90 \
        -H "Accept: application/json" \
        -H "User-Agent: Mozilla/5.0" \
        "https://crt.sh/?q=$DOMAIN&output=json" 2>/dev/null || true)
      [[ -n "$ct_raw" && "$ct_raw" != "[]" ]] && break
    fi
    [[ $_attempt -lt 3 ]] && sleep 5
  done
  printf "\r\033[2K"

  # Query 2: apex domain wildcard — always run to find sibling subdomains
  # (even when DOMAIN == apex, this finds all certs issued to *.apex)
  printf "  \033[0;36m[→]\033[0m Querying crt.sh for apex: $apex..."
  for _attempt in 1 2 3; do
    ct_raw_apex=$(curl -s --max-time 90 \
      -H "Accept: application/json" \
      -H "User-Agent: Mozilla/5.0" \
      "https://crt.sh/?q=%25.$apex&output=json" 2>/dev/null || true)
    [[ -n "$ct_raw_apex" && "$ct_raw_apex" != "[]" ]] && break
    # Fallback: try exact apex match
    if [[ -z "$ct_raw_apex" || "$ct_raw_apex" == "[]" ]]; then
      ct_raw_apex=$(curl -s --max-time 90 \
        -H "Accept: application/json" \
        -H "User-Agent: Mozilla/5.0" \
        "https://crt.sh/?q=$apex&output=json" 2>/dev/null || true)
      [[ -n "$ct_raw_apex" && "$ct_raw_apex" != "[]" ]] && break
    fi
    [[ $_attempt -lt 3 ]] && sleep 5
  done
  printf "\r\033[2K"

  # Check if we got any data from either query
  local ct_raw_empty=false ct_apex_empty=false
  { [[ -z "$ct_raw" || "$ct_raw" == "[]" ]]; } && ct_raw_empty=true
  { [[ -z "$ct_raw_apex" || "$ct_raw_apex" == "[]" ]]; } && ct_apex_empty=true
  if $ct_raw_empty && $ct_apex_empty; then
    warn "crt.sh: no data returned (timeout or no results for $DOMAIN or $apex)"
    return
  fi

  # Parse both responses — use temp files to avoid printf shell quoting issues
  local _ct_tmp1 _ct_tmp2
  _ct_tmp1=$(mktemp /tmp/ct_raw_XXXXXX.json)
  _ct_tmp2=$(mktemp /tmp/ct_apex_XXXXXX.json)
  echo "$ct_raw"      > "$_ct_tmp1"
  echo "$ct_raw_apex" > "$_ct_tmp2"

  ct_out=$(python3 - "$_ct_tmp1" "$_ct_tmp2" << 'PYEOF_CT'
import json, sys

names = set()
for fpath in sys.argv[1:]:
    try:
        raw = open(fpath).read().strip()
        if not raw or raw == "[]":
            continue
        data = json.loads(raw)
        for e in data:
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lstrip("*.").strip().lower()
                # Strip markdown link format [domain](url) -> domain
                import re as _re
                n = _re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", n)
                n = n.strip()
                if not n or n.startswith(".") or " " in n:
                    continue
                if all(c.isalnum() or c in "-._" for c in n):
                    names.add(n)
    except Exception:
        continue

print("\n".join(sorted(names)))
PYEOF_CT
)
  rm -f "$_ct_tmp1" "$_ct_tmp2"

  local count
  count=$(echo "$ct_out" | grep -c '[^[:space:]]' 2>/dev/null | head -1 | tr -d '[:space:]' || true)
  count=${count//[^0-9]/}; count=${count:-0}

  if [[ "$count" -eq 0 ]]; then
    info "crt.sh: no entries found"
  else
    # Split into: directly related to DOMAIN vs sibling subdomains of apex
    local domain_entries sibling_entries domain_count sibling_count
    domain_entries=$(echo "$ct_out" | grep -E "(^|\.)${DOMAIN}$" | sort -u || true)
    sibling_entries=$(echo "$ct_out" | grep -v -E "(^|\.)${DOMAIN}$" | sort -u || true)
    domain_count=$(echo "$domain_entries" | grep -c '[^[:space:]]' | head -1 | tr -d '[:space:]'); domain_count=${domain_count//[^0-9]/}; domain_count=${domain_count:-0}
    sibling_count=$(echo "$sibling_entries" | grep -c '[^[:space:]]' | head -1 | tr -d '[:space:]'); sibling_count=${sibling_count//[^0-9]/}; sibling_count=${sibling_count:-0}

    info "crt.sh: $count unique entries ($domain_count for $DOMAIN, $sibling_count sibling subdomains of $apex)"

    if [[ "$domain_count" -gt 0 ]]; then
      info "${C}[Certificates for $DOMAIN]${NC}"
      echo "$domain_entries" | head -10 | while read -r l; do [[ -n "$l" ]] && result "$l"; done
      [[ "$domain_count" -gt 10 ]] && result "... and $((domain_count-10)) more (see report)"
    fi

    if [[ "$sibling_count" -gt 0 ]]; then
      info "${C}[Sibling subdomains of $apex]${NC}"
      echo "$sibling_entries" | head -10 | while read -r l; do [[ -n "$l" ]] && result "$l"; done
      [[ "$sibling_count" -gt 10 ]] && result "... and $((sibling_count-10)) more (see report)"
    fi
  fi

  echo "$ct_out" > "${OUT_DIR}/ct_subdomains.txt"
}

# ================================================================
#  MODULE: SUBDOMAIN ENUMERATION
# ================================================================

run_subdomains() {
  module_enabled "subdomains" || return
  [[ -z "$DOMAIN" ]] && return
  section "Subdomain Enumeration"

  info "Checking for wildcard DNS..."
  local wildcard_test wildcard_ips=""
  # Query two different random hostnames - if both resolve to same IP(s) it's a wildcard
  local rand1 rand2
  rand1=$(dig +short "reconomew-wctest1-$(date +%s).$DOMAIN" @1.1.1.1 2>/dev/null \
    | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | sort | tr '\n' ',' | sed 's/,$//' || true)
  sleep 0.5
  rand2=$(dig +short "reconomew-wctest2-$(date +%s).$DOMAIN" @1.1.1.1 2>/dev/null \
    | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | sort | tr '\n' ',' | sed 's/,$//' || true)

  # Only flag wildcard if BOTH random queries return the same IP(s)
  if [[ -n "$rand1" && -n "$rand2" && "$rand1" == "$rand2" ]]; then
    wildcard_ips="$rand1"
    warn "Wildcard DNS detected (*.${DOMAIN} -> ${wildcard_ips})"
    warn "False positives will be filtered - only subdomains with DIFFERENT IPs will be reported"
    echo "$wildcard_ips" > "${OUT_DIR}/wildcard.txt"
  else
    result "No wildcard DNS detected - brute-force results are reliable"
  fi

  # Export wildcard IPs for use in brute-force filtering
  WILDCARD_IPS="$wildcard_ips"

  # subfinder
  if tool_ok "subfinder"; then
    local sf_out="${OUT_DIR}/subfinder.txt"
    run_timed "subfinder" 600 subfinder -d "$DOMAIN" -silent -all -recursive -o "$sf_out"
    # Clean output immediately — strip markdown [text](url), URLs, whitespace
    if [[ -f "$sf_out" ]]; then
      python3 -c "
import re, sys
lines = open('$sf_out').readlines()
clean = []
for l in lines:
    l = l.strip()
    # Strip markdown link format [domain](url) -> domain
    l = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', l)
    # Strip bare URLs
    l = re.sub(r'https?://', '', l)
    # Strip any path after domain
    l = re.sub(r'/.*$', '', l)
    l = l.strip()
    if l and re.match(r'^[a-zA-Z0-9]', l):
        clean.append(l)
# Deduplicate and filter to only subdomains of target
domain = '$DOMAIN'
seen = set()
for l in sorted(clean):
    if (l.endswith('.' + domain) or l == domain) and l not in seen:
        seen.add(l)
        print(l)
" > "${sf_out}.clean" 2>/dev/null && mv "${sf_out}.clean" "$sf_out" || true
    fi
    local count
    count=0
    if [[ -f "$sf_out" ]]; then
      count=$(grep -cE '^[a-zA-Z0-9].' "$sf_out" 2>/dev/null) || count=0
    fi
    count=${count//[^0-9]/}; count=${count:-0}
    info "subfinder: $count subdomains found"
    head -10 "$sf_out" 2>/dev/null | while read -r l; do result "$l"; done
    [[ "$count" -gt 10 ]] && result "... and $((count-10)) more (see report)"
    # Append clean subfinder results to subdomains_found.txt — filter wildcards
    local sf_real=0
    if [[ -f "$sf_out" ]] && [[ -s "$sf_out" ]]; then
      while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        # Wildcard filter: skip if sub resolves to a wildcard IP
        if [[ -n "$WILDCARD_IPS" ]]; then
          local sub_ip
          sub_ip=$(dig +short A "$sub" @1.1.1.1 2>/dev/null | grep -E '^[0-9]+\.' | head -1 || true)
          [[ -n "$sub_ip" ]] && echo "$WILDCARD_IPS" | grep -qF "$sub_ip" && continue
        fi
        grep -qxF "$sub" "${OUT_DIR}/subdomains_found.txt" 2>/dev/null || echo "$sub" >> "${OUT_DIR}/subdomains_found.txt"
        sf_real=$((sf_real + 1))
      done < "$sf_out"
    fi
    [[ -n "$WILDCARD_IPS" && "$sf_real" -lt "$count" ]] && \
      info "subfinder: $sf_real real subdomains after wildcard filtering ($(( count - sf_real )) false positives removed)" 
  else
    skip "subfinder (not installed - go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
  fi

  # Built-in common subdomain check
  echo ""
  local subs=(www mail dev staging admin api vpn test portal ftp smtp pop cdn app
              auth login dashboard status beta internal corp git jenkins ci monitoring
              kibana grafana jira confluence wiki support helpdesk mx mx1 mx2 ns1 ns2)
  info "Common subdomain check (${#subs[@]} names)"
  local cspin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local cspin_idx=0
  local common_idx=0
  local common_total=${#subs[@]}
  local common_found=0
  for sub in "${subs[@]}"; do
    ((common_idx++))
    local cspin_char="${cspin_chars:$((cspin_idx % ${#cspin_chars})):1}"
    ((cspin_idx++))
    printf "  \033[0;36m[→]\033[0m \033[0;36m%s\033[0m Checking common... [%d/%d] %-40s\033[2K\r" \
      "$cspin_char" "$common_idx" "$common_total" "$sub.$DOMAIN"
    local r
    r=$(dig +short A "$sub.$DOMAIN" @1.1.1.1 +time=3 +tries=1 2>/dev/null \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    if [[ -n "$r" ]]; then
      # Filter wildcard false positives
      if [[ -n "$WILDCARD_IPS" ]] && echo "$WILDCARD_IPS" | grep -qF "$r" 2>/dev/null; then
        continue  # Same IP as wildcard - false positive, skip
      fi
      printf "\033[2K\r"
      if ! grep -qxF "$sub.$DOMAIN" "${OUT_DIR}/subdomains_found.txt" 2>/dev/null; then
        info "FOUND: $sub.$DOMAIN -> $r"
        echo "$sub.$DOMAIN" >> "${OUT_DIR}/subdomains_found.txt"
        ((common_found++))
      fi
    fi
  done
  printf "\033[2K\r"
  if [[ "$common_found" -gt 0 ]]; then
    info "Common check done: $common_found subdomain(s) found"
  else
    info "Common check done: no subdomains found"
  fi


  # Wordlist brute-force
  if [[ -f "$WORDLIST_SUB" ]]; then
    local total_words
    total_words=$(wc -l < "$WORDLIST_SUB" 2>/dev/null | tr -d ' ' || echo '?')

    # ── Fast path: dnsx parallel DNS resolver (100x faster than sequential dig) ──
    if command -v dnsx &>/dev/null; then
      echo ""
      info "dnsx wordlist brute-force: $WORDLIST_SUB ($total_words words)"

      local dnsx_out="${OUT_DIR}/dnsx_brute.txt"
      local fqdn_list="${OUT_DIR}/fqdn_tmp.txt"

      # Build FQDN list
      sed "s/$/.${DOMAIN}/" "$WORDLIST_SUB" > "$fqdn_list"

      stdbuf -oL timeout 600 dnsx \
        -l "$fqdn_list" \
        -r 1.1.1.1,8.8.8.8,9.9.9.9 \
        -t 150 \
        -timeout 3 \
        -a \
        -resp \
        -silent \
        2>/dev/null > "$dnsx_out" &
      local dnsx_pid=$!
      local elapsed=0
      while kill -0 "$dnsx_pid" 2>/dev/null; do
        sleep 5; elapsed=$((elapsed + 5))
        [[ $elapsed -ge 600 ]] && kill "$dnsx_pid" 2>/dev/null && break
        # Show live found count from output file
        # Count unique hostnames, not raw lines (dnsx -resp outputs multiple lines per host)
        local live_found=0
        [[ -f "$dnsx_out" ]] && live_found=$(awk '{print $1}' "$dnsx_out" 2>/dev/null | sort -u | wc -l | tr -d ' ')
        live_found=${live_found:-0}
        kill -0 "$dnsx_pid" 2>/dev/null && \
          { if [[ -n "$WILDCARD_IPS" ]]; then
            printf "\r  \033[0;36m[→]\033[0m dnsx brute-force \033[2m%ds | found: %d (filtering wildcards...)\033[0m\033[K" "$elapsed" "$live_found"
          else
            printf "\r  \033[0;36m[→]\033[0m dnsx brute-force \033[2m%ds | found: %d\033[0m\033[K" "$elapsed" "$live_found"
          fi; }
      done
      wait "$dnsx_pid" 2>/dev/null || true
      printf "\r\033[2K"
      rm -f "$fqdn_list"

      # Parse and display results
      local found=0
      if [[ -f "$dnsx_out" ]]; then
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          local sub_host ip_part
          sub_host=$(echo "$line" | awk '{print $1}')
          ip_part=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
          if [[ -n "$sub_host" && -n "$ip_part" ]]; then
            if [[ -n "$WILDCARD_IPS" ]] && echo "$WILDCARD_IPS" | grep -qF "$ip_part" 2>/dev/null; then
              continue
            fi
            if ! grep -qxF "$sub_host" "${OUT_DIR}/subdomains_found.txt" 2>/dev/null; then
              info "FOUND: $sub_host -> $ip_part"
              echo "$sub_host" >> "${OUT_DIR}/subdomains_found.txt"
              ((found++))
            fi
          fi
        done < "$dnsx_out"
      fi
      if [[ "$found" -gt 0 ]]; then
        info "dnsx brute-force done: $found subdomains found (${elapsed}s)"
      else
        info "dnsx brute-force done: no subdomains found (${elapsed}s)"
      fi

    else
      # ── Slow path: sequential dig fallback ──
      local estimated_mins=$(( (total_words + 59) / 60 ))
      warn "dnsx not installed — falling back to sequential dig (~1 query/s)"
      warn "Estimated time: ~${estimated_mins} min for $total_words words (install dnsx for 100x speed)"
      warn "Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

      local found=0
      local checked=0
      local start_time
      start_time=$(date +%s)
      local spinner_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
      local spinner_idx=0

      while IFS= read -r sub; do
        local now elapsed_s
        now=$(date +%s)
        elapsed_s=$((now - start_time))
        [[ $elapsed_s -gt 600 ]] && printf "\033[2K\r" && warn "Subdomain brute-force time limit reached (600s)" && break
        [[ -z "$sub" ]] && continue
        ((checked++))
        local spin_char="${spinner_chars:$((spinner_idx % ${#spinner_chars})):1}"
        ((spinner_idx++))
        printf "  \033[0;36m[→]\033[0m \033[0;36m%s\033[0m Subdomain brute-force | tested: %d/%s | found: %d | %ds / 600s\033[2K\r" \
          "$spin_char" "$checked" "$total_words" "$found" "$elapsed_s"
        local r
        r=$(dig +short A "$sub.$DOMAIN" @1.1.1.1 +time=2 +tries=1 2>/dev/null \
          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
        if [[ -n "$r" ]]; then
          if [[ -n "$WILDCARD_IPS" ]] && echo "$WILDCARD_IPS" | grep -qF "$r" 2>/dev/null; then
            continue
          fi
          printf "\033[2K\r"
          info "FOUND: $sub.$DOMAIN -> $r"
          echo "$sub.$DOMAIN" >> "${OUT_DIR}/subdomains_found.txt"
          ((found++))
        fi
      done < "$WORDLIST_SUB"
      printf "\033[2K\r"
      if [[ "$found" -gt 0 ]]; then
        info "Brute-force done: $found subdomains found ($checked tested in ${elapsed_s}s)"
      else
        info "Brute-force done: no subdomains found ($checked tested in ${elapsed_s}s)"
      fi
    fi
  else
    warn "Subdomain wordlist not found: $WORDLIST_SUB"
  fi

  # ── Subdomain permutation - smart context-aware engine ──
  if [[ -f "${OUT_DIR}/subdomains_found.txt" ]] && [[ -s "${OUT_DIR}/subdomains_found.txt" ]]; then
    local perms_file="${OUT_DIR}/subdomains_permutations.txt"
    local perms_found="${OUT_DIR}/subdomains_permutations_resolved.txt"

    echo ""
    info "Running smart permutation engine..."
    DOMAIN="$DOMAIN" OUT_DIR="$OUT_DIR" python3 - << 'PYEOF_PERMS'
import os, itertools

domain  = os.environ.get('DOMAIN', '')
out_dir = os.environ.get('OUT_DIR', '')
subs_file  = os.path.join(out_dir, 'subdomains_found.txt')
perms_file = os.path.join(out_dir, 'subdomains_permutations.txt')

try:
    found = [l.strip().replace('.' + domain, '')
             for l in open(subs_file)
             if l.strip() and domain in l]
except:
    found = []

if not found:
    exit()

ENVS      = ['dev', 'prod', 'staging', 'test', 'qa', 'uat', 'sandbox', 'demo',
             'preprod', 'preview', 'dr', 'backup', 'hot', 'cold']
VERSIONS  = ['v1', 'v2', 'v3', 'v4', 'old', 'new', 'legacy', 'next',
             'beta', 'alpha', 'rc', 'stable']
FUNCTIONS = ['api', 'admin', 'auth', 'login', 'dashboard', 'portal', 'internal',
             'backend', 'gateway', 'proxy', 'cdn', 'static', 'assets', 'media',
             'upload', 'download', 'webhook', 'callback', 'oauth', 'sso', 'vpn',
             'remote', 'mgmt', 'management', 'console', 'panel']
INFRA     = ['db', 'database', 'mysql', 'postgres', 'redis', 'elastic', 'kibana',
             'grafana', 'jenkins', 'gitlab', 'jira', 'confluence', 'vault',
             'consul', 'k8s', 'docker', 'prometheus', 'alertmanager', 'minio',
             'rabbitmq', 'kafka', 'zookeeper', 'mongo', 'influx']
REGIONS   = ['us', 'eu', 'uk', 'ap', 'us-east', 'us-west', 'eu-west',
             'ap-southeast', 'us-east-1', 'eu-central']

perms = set()

for sub in found:
    sub_lower = sub.lower()
    for env in ENVS:
        perms.add(f'{sub}-{env}.{domain}')
        perms.add(f'{env}-{sub}.{domain}')
        perms.add(f'{env}.{sub}.{domain}')
    for ver in VERSIONS:
        perms.add(f'{sub}-{ver}.{domain}')
        perms.add(f'{ver}.{sub}.{domain}')
    if any(x in sub_lower for x in ['api', 'gateway', 'service', 'rest', 'graphql']):
        for ver in ['v1', 'v2', 'v3', 'v4']:
            perms.add(f'{sub}-{ver}.{domain}')
            perms.add(f'{ver}.{sub}.{domain}')
            perms.add(f'{ver}-{sub}.{domain}')
    if any(x in sub_lower for x in ['admin', 'internal', 'corp', 'intranet', 'mgmt']):
        for func in ['dashboard', 'portal', 'login', 'panel', 'console', 'backend']:
            perms.add(f'{sub}-{func}.{domain}')
            perms.add(f'{func}.{sub}.{domain}')
    if any(x in sub_lower for x in ['api', 'prod', 'app', 'gateway']):
        for region in REGIONS:
            perms.add(f'{sub}-{region}.{domain}')
            perms.add(f'{region}-{sub}.{domain}')

for func in FUNCTIONS:
    perms.add(f'{func}.{domain}')
    for env in ['dev', 'staging', 'test', 'prod']:
        perms.add(f'{func}-{env}.{domain}')
        perms.add(f'{env}-{func}.{domain}')

for infra in INFRA:
    perms.add(f'{infra}.{domain}')
    perms.add(f'{infra}-dev.{domain}')
    perms.add(f'{infra}-prod.{domain}')

smart_combos = list(itertools.product(
    ['api', 'auth', 'admin', 'internal', 'legacy', 'portal', 'backend'],
    ['v1', 'v2', 'v3', 'old', 'new', 'beta', 'prod', 'dev']
))
for a, b in smart_combos:
    perms.add(f'{a}-{b}.{domain}')
    perms.add(f'{b}-{a}.{domain}')

known = set()
if os.path.exists(subs_file):
    known = set(open(subs_file).read().splitlines())
perms -= known

with open(perms_file, 'w') as f:
    f.write('\n'.join(sorted(perms)) + '\n')

print(f'  [+] {len(perms)} smart permutations generated')
PYEOF_PERMS

    local perm_count
    perm_count=$(grep -c '.' "$perms_file" 2>/dev/null | head -1 | tr -d '[:space:]' || echo 0)
    perm_count=${perm_count//[^0-9]/}; perm_count=${perm_count:-0}
    info "Subdomain permutations: $perm_count variants generated"

    if [[ "$perm_count" -gt 0 ]] && tool_ok "dnsx"; then
      local _perm_resolved="${perms_file}.resolved"
      > "$_perm_resolved"
      local _perm_raw="${perms_file}.raw"
      > "$_perm_raw"
      run_timed "Subdomain permutations" 300 bash -c \
        "dnsx -l '$perms_file' -silent -a -r 1.1.1.1,8.8.8.8,9.9.9.9 -t 150 -timeout 3 -resp 2>/dev/null > '$_perm_raw'"
      # Sort and deduplicate after dnsx finishes
      awk '{print $1}' "$_perm_raw" 2>/dev/null | sort -u > "$_perm_resolved" || true
      local resolved_count
      resolved_count=$(wc -l < "$_perm_resolved" 2>/dev/null | tr -d ' '); resolved_count=${resolved_count:-0}

      # Filter wildcard false positives if wildcard IPs are known
      if [[ -n "$WILDCARD_IPS" && "$resolved_count" -gt 0 ]]; then
        local _perm_filtered="${_perm_resolved}.filtered"
        > "$_perm_filtered"
        while IFS= read -r sub; do
          [[ -z "$sub" ]] && continue
          local sub_ip
          sub_ip=$(dig +short A "$sub" @1.1.1.1 2>/dev/null | grep -E '^[0-9]' | head -1 || true)
          if [[ -n "$sub_ip" ]] && echo "$WILDCARD_IPS" | grep -qF "$sub_ip" 2>/dev/null; then
            continue  # wildcard false positive
          fi
          echo "$sub" >> "$_perm_filtered"
        done < "$_perm_resolved"
        mv "$_perm_filtered" "$_perm_resolved"
        resolved_count=$(wc -l < "$_perm_resolved" 2>/dev/null | tr -d ' '); resolved_count=${resolved_count:-0}
      fi
      if [[ "$resolved_count" -gt 0 ]]; then
        warn "Permutation subdomains resolved: $resolved_count new subdomains!"
        cat "$_perm_resolved" > "$perms_found"
        head -20 "$perms_found" | while read -r l; do warn "  $l"; done
        # Add to main subdomain list
        cat "$perms_found" >> "${OUT_DIR}/subdomains_found.txt"
        sort -u "${OUT_DIR}/subdomains_found.txt" -o "${OUT_DIR}/subdomains_found.txt"
      else
        info "Permutation subdomains: none resolved"
      fi
    fi
  fi
}

