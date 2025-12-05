#!/usr/bin/env bash

# -----------------------------------------
# Censor-check script
# Автор модификации Nikola Tesla ©, по багам, вопросам пишите в ТГ https://t.me/tracerlab 
# -----------------------------------------

TIMEOUT=4
RETRIES=2
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
IP_VERSION=4
PROXY=""
VERBOSE=false

if [[ "$1" == "-v" ]]; then
  VERBOSE=true
fi

DOMAINS=(
  "youtube.com"
  "instagram.com"
  "facebook.com"
  "x.com"
  "patreon.com"
  "linkedin.com"
  "signal.org"
  "tiktok.com"
  "web.telegram.org"
  "web.whatsapp.com"
  "discord.com"
  "viber.com"
  "chatgpt.com"
  "grok.com"
  "reddit.com"
  "twitch.tv"
  "netflix.com"
#  "onlyfans.com"
  "rutracker.org"
  "nnmclub.to"
  "digitalocean.com"
  "api.cloudflare.com"
  "aws.amazon.com"
  "ntc.party"
  "amnezia.org"
  "torproject.org"
)

AI_DOMAINS=(
  "chatgpt.com"
  "grok.com"
  "netflix.com"
)

RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"
ITALIC="\033[3m"
RED_ITALIC="\033[31;3m"
GREEN_ITALIC="\033[32;3m"
YELLOW_ITALIC="\033[33;3m"
BLUE_ITALIC="\033[34;3m"

DOMAIN_WIDTH=20

# Инстал зависимостей
install_missing_deps() {
  local deps=("curl" "nslookup" "nc" "openssl" "date" "awk")
  local missing=()

  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null; then
      missing+=("$dep")
    fi
  done

  if [ ${#missing[@]} -eq 0 ]; then
    return 0
  fi

  echo "Missing dependencies: ${missing[*]}. Installing automatically..."

  local prefix=""
  if [ "$(id -u)" -eq 0 ]; then
    prefix=""
  elif command -v sudo >/dev/null 2>&1; then
    prefix="sudo "
  else
    echo "You are not root, and sudo is not available."
    echo "Please run as root or install sudo first, or install dependencies manually:"
    case "$(uname -s)" in
      Linux*)
        if grep -qi "arch" /etc/os-release 2>/dev/null; then
          echo "  pacman -S --needed curl bind openbsd-netcat openssl coreutils gawk"
        elif [ -f /etc/debian_version ] || grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
          echo "  apt update && apt install -y curl dnsutils netcat-openbsd openssl coreutils gawk"
        elif [ -f /etc/fedora-release ] || grep -qi "fedora" /etc/os-release 2>/dev/null; then
          echo "  dnf install -y curl bind-utils nc openssl coreutils gawk"
        elif [ -f /etc/centos-release ] || grep -qi "centos\|rhel" /etc/os-release 2>/dev/null; then
          echo "  dnf install -y curl bind-utils nc openssl coreutils gawk  # or yum if dnf not available"
        fi
        ;;
      *)
        echo "  Install: curl, dnsutils/bind-utils (for nslookup), netcat/nc (for nc), openssl, coreutils (for date), gawk (for awk)"
        ;;
    esac
    exit 1
  fi

  local pkg_mgr=""
  local update_cmd=""
  local quiet_update_cmd=""
  local install_cmd=""
  local quiet_install_cmd=""
  local pkg_names=()

  if [ -f /etc/debian_version ] || grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
    pkg_mgr="apt"
    update_cmd="apt update -y"
    quiet_update_cmd="apt update -y -q"
    install_cmd="apt install -y"
    quiet_install_cmd="apt install -y -q"
    # Debian/Ubuntu
    for dep in "${missing[@]}"; do
      case "$dep" in
        curl) pkg_names+=("curl") ;;
        nslookup) pkg_names+=("dnsutils") ;;
        nc) pkg_names+=("netcat-openbsd") ;;  # or netcat-traditional
        openssl) pkg_names+=("openssl") ;;
        date) pkg_names+=("coreutils") ;;
        awk) pkg_names+=("gawk") ;;
      esac
    done
  elif [ -f /etc/fedora-release ] || grep -qi "fedora" /etc/os-release 2>/dev/null; then
    pkg_mgr="dnf"
    update_cmd="dnf check-update -y"
    quiet_update_cmd="dnf check-update -y --quiet"
    install_cmd="dnf install -y"
    quiet_install_cmd="dnf install -y --quiet"
    # Fedora
    for dep in "${missing[@]}"; do
      case "$dep" in
        curl) pkg_names+=("curl") ;;
        nslookup) pkg_names+=("bind-utils") ;;
        nc) pkg_names+=("nc") ;;
        openssl) pkg_names+=("openssl") ;;
        date) pkg_names+=("coreutils") ;;
        awk) pkg_names+=("gawk") ;;
      esac
    done
  elif [ -f /etc/centos-release ] || grep -qi "centos\|rhel" /etc/os-release 2>/dev/null; then
    if command -v dnf >/dev/null; then
      pkg_mgr="dnf"
      update_cmd="dnf check-update -y"
      quiet_update_cmd="dnf check-update -y --quiet"
      install_cmd="dnf install -y"
      quiet_install_cmd="dnf install -y --quiet"
    else
      pkg_mgr="yum"
      update_cmd="yum check-update -y"
      quiet_update_cmd="yum check-update -y --quiet"
      install_cmd="yum install -y"
      quiet_install_cmd="yum install -y --quiet"
    fi
    # CentOS/RHEL
    for dep in "${missing[@]}"; do
      case "$dep" in
        curl) pkg_names+=("curl") ;;
        nslookup) pkg_names+=("bind-utils") ;;
        nc) pkg_names+=("nc") ;;
        openssl) pkg_names+=("openssl") ;;
        date) pkg_names+=("coreutils") ;;
        awk) pkg_names+=("gawk") ;;
      esac
    done
  elif [ -f /etc/arch-release ] || grep -qi "arch" /etc/os-release 2>/dev/null; then
    pkg_mgr="pacman"
    update_cmd="pacman -Sy --noconfirm"
    quiet_update_cmd="pacman -Sy --noconfirm -qq"
    install_cmd="pacman -S --noconfirm"
    quiet_install_cmd="pacman -S --noconfirm -qq"
    # Arch Linux
    for dep in "${missing[@]}"; do
      case "$dep" in
        curl) pkg_names+=("curl") ;;
        nslookup) pkg_names+=("bind") ;;
        nc) pkg_names+=("openbsd-netcat") ;;
        openssl) pkg_names+=("openssl") ;;
        date) pkg_names+=("coreutils") ;;
        awk) pkg_names+=("gawk") ;;
      esac
    done
  else
    echo "Unsupported distribution. Please install dependencies manually."
    exit 1
  fi

  ${prefix}${quiet_update_cmd} || { echo "Update failed."; exit 1; }

  for pkg in "${pkg_names[@]}"; do
    echo "install $pkg"
    ${prefix}${quiet_install_cmd} "$pkg" || { echo "Installation of $pkg failed."; exit 1; }
  done
}

install_missing_deps

fetch_code() {
  local proxy_opt=""
  if [[ -n "$PROXY" ]]; then
    if [[ "$PROXY" == http://* ]]; then
      proxy_opt="--proxy $PROXY"
    else
      proxy_opt="--proxy socks5://$PROXY"
    fi
  fi

  curl -s -o /dev/null \
       --retry "$RETRIES" \
       --connect-timeout "$TIMEOUT" \
       --max-time "$TIMEOUT" \
       -$IP_VERSION \
       -A "$USER_AGENT" \
       $proxy_opt \
       -w "%{http_code}" \
       "$1"
}

check_keyword_blocking() {
  local domain="$1"
  local test_url="https://$domain"
  
  local dpi_response
  dpi_response=$(curl -s -A "Suspicious-Agent TLS/1.3" --connect-timeout "$TIMEOUT" "$test_url" 2>/dev/null)
  
  if echo "$dpi_response" | grep -qi "blocked\|forbidden\|access.denied\|roscomnadzor\|rkn\|firewall\|censorship\|prohibited\|restricted"; then
    return 0  
  fi
  
  # Test IP 
  local sni_code
  sni_code=$(curl -s -o /dev/null --connect-timeout "$TIMEOUT" --resolve "$domain:443:192.0.2.1" "$test_url" -w "%{http_code}" 2>/dev/null)
  
  if [[ "$sni_code" =~ [45][0-9][0-9] || "$sni_code" == "000" ]]; then
    return 0 
  fi
  
  return 1 
}

# Check TLS/SSL
check_certificate() {
  local domain="$1"
  local cert_info
  cert_info=$(timeout "$TIMEOUT" openssl s_client -connect "$domain:443" -servername "$domain" -CApath /etc/ssl/certs -verify 5 < /dev/null 2>&1)
  
  if echo "$cert_info" | grep -q "Verification error:" || ! echo "$cert_info" | grep -q "Verification: OK"; then
    $VERBOSE && echo "TLS verification failed for $domain"
    return 1
  fi
  
  local not_after=$(echo "$cert_info" | openssl x509 -noout -dates 2>/dev/null | grep "notAfter" | cut -d= -f2)
  if [[ -n "$not_after" ]]; then
    local expire_epoch=$(date -d "$not_after" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    if [[ $expire_epoch -lt $current_epoch ]]; then
      $VERBOSE && echo "Certificate expired for $domain"
      return 1
    fi
    return 0
  fi
  return 1
}

check_domain() {
  local domain="$1"
  local block_type="UNKNOWN"
  local status_color=$RED
  local status_text="BLOCKED"

  # DNS
  local ips
  ips=$(nslookup "$domain" 2>/dev/null | awk '/^Address: / && !/#/ {print $2}')
  
  if [[ -z "$ips" ]]; then
    block_type="DNS"
    printf "%-${DOMAIN_WIDTH}s  ${RED_ITALIC}%s${RESET} (${YELLOW}%s${RESET})\n" "$domain" "$status_text" "$block_type"
    return
  fi

  local ip_ok=false
  local port_443_ok=false
  local port_80_ok=false
  
  for ip in $ips; do
    if nc -z -w "$TIMEOUT" "$ip" 443 2>/dev/null; then
      ip_ok=true
      port_443_ok=true
      break
    fi
  done
  
  if ! $port_443_ok; then
    for ip in $ips; do
      if nc -z -w "$TIMEOUT" "$ip" 80 2>/dev/null; then
        port_80_ok=true
        ip_ok=true
        break
      fi
    done
  fi

  if ! $ip_ok; then
    block_type="IP/TCP"
    printf "%-${DOMAIN_WIDTH}s  ${RED_ITALIC}%s${RESET} (${YELLOW}%s${RESET})\n" "$domain" "$status_text" "$block_type"
    return
  fi

  local cert_status=""
  if check_certificate "$domain"; then
    cert_status="✓TLS"
  else
    cert_status="✗TLS"
    block_type="TLS/SSL"
  fi

  # HTTP/HTTPS check
  http_code=$(fetch_code "http://$domain")
  https_code=$(fetch_code "https://$domain")

  # HTTP redirects
  if [[ "$http_code" =~ 3[0-9][0-9] ]]; then
    $VERBOSE && echo "HTTP redirect detected for $domain, falling back to HTTPS"
    http_code="$https_code"  
  fi

  if [[ "$http_code" == "000" && "$https_code" == "000" ]]; then
    if $ip_ok; then
      block_type="HTTP(S)"
    else
      block_type="IP/HTTP"
    fi
  elif [[ "$http_code" =~ [45][0-9][0-9] && "$https_code" =~ [45][0-9][0-9] ]]; then
    block_type="HTTP-RESPONSE"
  fi

  if check_keyword_blocking "$domain"; then
    if [[ "$block_type" != "UNKNOWN" ]]; then
      block_type="$block_type/DPI"
    else
      block_type="DPI/KEYWORD"
    fi
  fi

  # AI domains regional blocks
  if [[ " ${AI_DOMAINS[*]} " =~ " ${domain} " ]]; then
    local ai_response
    ai_response=$(curl -s -A "$USER_AGENT" \
      -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
      -H "Accept-Language: en-US,en;q=0.5" \
      -H "Upgrade-Insecure-Requests: 1" \
      -H "Sec-Fetch-Dest: document" \
      -H "Sec-Fetch-Mode: navigate" \
      -H "Sec-Fetch-Site: none" \
      -H "Sec-Fetch-User: ?1" \
      -H "Connection: keep-alive" \
      --compressed \
      --connect-timeout "$TIMEOUT" "https://$domain" 2>/dev/null)
    if echo "$ai_response" | grep -qi "sorry, you have been blocked\|you are unable to access\|not available in your region\|restricted in your country\|access denied due to location\|blocked in your area\|unable to load site\|if you are using a vpn\|Not Available"; then
      block_type="REGIONAL"
      http_code="000"  # Force BLOCKED status
      https_code="000"
    elif echo "$ai_response" | grep -qi "just a moment\|enable javascript and cookies"; then
      block_type=""  # Clear block type
      http_code="200"  # Force OK status
      https_code="200"
    fi
  fi

  # Final status
  if [[ "$http_code" == "000" && "$https_code" == "000" ]]; then
    printf "%-${DOMAIN_WIDTH}s  ${RED_ITALIC}%s${RESET} (${YELLOW}%s${RESET}) ${cert_status}\n" "$domain" "$status_text" "$block_type"
  elif [[ "$http_code" =~ [23][0-9][0-9] || "$https_code" =~ [23][0-9][0-9] ]]; then
    printf "%-${DOMAIN_WIDTH}s  ${GREEN_ITALIC}%s${RESET} ${cert_status}\n" "$domain" "OK"
  else
    printf "%-${DOMAIN_WIDTH}s  ${YELLOW_ITALIC}%s${RESET} (${BLUE}%s${RESET}) ${cert_status}\n" "$domain" "PARTIAL" "$block_type"
  fi
}

clear
echo "--- Network Censorship Checker by Nikola Tesla ---"
echo
echo "Domain                Status    Block Type"
echo "--------------------------------------------------"

start_time=$(date +%s)

for d in "${DOMAINS[@]}"; do
  check_domain "$d"
done

end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
elapsed_minutes=$((elapsed_time / 60))

echo "--------------------------------------------------"
echo "Test completed in $elapsed_minutes minutes."
echo -e "Follow: $(tput setaf 6)https://t.me/tracerlab$(tput sgr0)"