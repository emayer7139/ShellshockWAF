#!/usr/bin/env bash
#
# deploy-wsl-waf.sh — One-step Apache + Shellshock WAF deployment & test for Ubuntu WSL
#
# This script installs Apache, updates Bash, configures a basic UFW, iptables, and Fail2Ban,
# deploys header-filter WAF rules for Apache and NGINX if present, and then runs
# automated tests including Shellshock payload tests with verbose output.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "must run with sudo"
    exit 1
fi

echo "===> 1. Patching Bash to close Shellshock CVEs"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y bash

echo "===> 2. Installing Apache, UFW, and Fail2Ban"
apt-get install -y apache2 ufw fail2ban

echo "===> 3. Configuring UFW (deny incoming, allow SSH/HTTP/HTTPS)"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

echo "===> 4. Adding iptables DROP for Shellshock pattern '() {'"
iptables -I INPUT  -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP || true
ip6tables -I INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP || true

echo "===> 5. Configuring Fail2Ban jails for Shellshock"
# Apache filter
cat >/etc/fail2ban/filter.d/apache-shellshock.conf <<'EOF'
[Definition]
failregex = ^.*bash: warning: HTTP_[A-Z_]+: ignoring function definition attempt$
            ^.*bash: error importing function definition for `HTTP_[A-Z_]+'.$
EOF
# NGINX filter
cat >/etc/fail2ban/filter.d/nginx-shellshock.conf <<'EOF'
[Definition]
failregex = <HOST> - - \[.*\] ".*\(\)\s*\{.*\}.*"
EOF
# Jails
cat >/etc/fail2ban/jail.local <<'EOF'
[shellshock-apache]
enabled  = true
filter   = apache-shellshock
logpath  = /var/log/apache2/error.log
maxretry = 1
bantime  = 86400
action   = ufw[name=HTTP, port="http,https", protocol=tcp]

[shellshock-nginx]
enabled  = true
filter   = nginx-shellshock
logpath  = /var/log/nginx/access.log
maxretry = 1
bantime  = 86400
action   = ufw[name=HTTP, port="http,https", protocol=tcp]
EOF
systemctl restart fail2ban

echo "===> 6. Deploying Apache WAF header filters"
a2enmod setenvif || true
cat >/etc/apache2/conf-available/shellshock-wsl.conf <<'EOF'
# Shellshock WAF: block requests with '() {'
SetEnvIfNoCase User-Agent "\(\)\s*\{" BlockAttack
SetEnvIfNoCase Referer    "\(\)\s*\{" BlockAttack
SetEnvIfNoCase Cookie     "\(\)\s*\{" BlockAttack

<If "%{env:BlockAttack} == 1">
    Require all denied
</If>
EOF
a2enconf shellshock-wsl
systemctl reload apache2

# 7. If NGINX is installed, deploy WAF there as well
if command -v nginx >/dev/null 2>&1; then
  echo "===> Detected NGINX: deploying header filters"
  cat >/etc/nginx/conf.d/shellshock-wsl.conf <<'EOF'
# Shellshock WAF for NGINX
map \$http_user_agent \$block_shock {
  default 0;
  ~*\(\)\s*\{    1;
  ~*(wget|curl|/bin/|shellshock|;) 1;
}
server {
  listen 80 default_server;
  listen 443 ssl default_server;
  location / {
    if (\$block_shock) {
      return 403;
    }
    # existing config...
  }
}
EOF
  nginx -t && systemctl reload nginx
fi

echo
echo "✅ WAF deployed. Beginning automated tests..."
echo

# 8. Automated Tests

# 8.1 Test Bash Shellshock patch
echo "---- Test 1: Bash Shellshock CVE check ----"
echo "Command: env x='() { :;}; echo VULNERABLE' bash -c \"echo SAFE\""
env x='() { :;}; echo VULNERABLE' bash -c "echo SAFE"
echo "Expected output: SAFE"
echo

# 8.2 Test normal HTTP request
echo "---- Test 2: Normal HTTP request ----"
echo "Command: curl -s -o /dev/null -w \"%{http_code}\\n\" http://localhost/"
curl -v -I http://localhost/ || true
echo

# 8.3 Test malicious User-Agent blocked by WAF
echo "---- Test 3: Malicious Shellshock header ----"
echo "Command: curl -v -I -H 'User-Agent: () { :;}; echo PWNED' http://localhost/"
curl -v -I -H 'User-Agent: () { :;}; echo PWNED' http://localhost/ || true
echo "Should see HTTP/1.1 403 Forbidden"
echo

# 8.4 Verify Fail2Ban ban
echo "---- Test 4: Trigger Fail2Ban ban ----"
echo "Sending another malicious request to log and ban..."
curl -s -I -H 'User-Agent: () { :;}; echo PWNED' http://localhost/ || true
echo "Waiting 3s then checking Fail2Ban status for shellshock-apache..."
sleep 3
fail2ban-client status shellshock-apache || echo "No Fail2Ban jail found or not banned"
echo

echo "All tests complete. Review output above for PASS/FAIL indications."
