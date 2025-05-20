#!/usr/bin/env bash


  .--.--.     ,---,                ,--,    ,--,     .--.--.     ,---,                              ,-.
 /  /    '. ,--.' |              ,--.'|  ,--.'|    /  /    '. ,--.' |                          ,--/ /|
|  :  /`. / |  |  :              |  | :  |  | :   |  :  /`. / |  |  :       ,---.     ,---.  ,--. :/ |
;  |  |--`  :  :  :              :  : '  :  : '   ;  |  |--`  :  :  :      '   ,'\   '   ,'\ :  : ' /
|  :  ;_    :  |  |,--.   ,---.  |  ' |  |  ' |   |  :  ;_    :  |  |,--. /   /   | /   /   ||  '  /
 \  \    `. |  :  '   |  /     \ '  | |  '  | |    \  \    `. |  :  '   |.   ; ,. :.   ; ,. :'  |  :
  `----.   \|  |   /' : /    /  ||  | :  |  | :     `----.   \|  |   /' :'   | |: :'   | |: :|  |   \
  __ \  \  |'  :  | | |.    ' / |'  : |__'  : |__   __ \  \  |'  :  | | |'   | .; :'   | .; :'  : |. \
 /  /`--'  /|  |  ' | :'   ;   /||  | '.'|  | '.'| /  /`--'  /|  |  ' | :|   :    ||   :    ||  | ' \ \
'--'.     / |  :  :_:,''   |  / |;  :    ;  :    ;'--'.     / |  :  :_:,' \   \  /  \   \  / '  : |--'
  `--'---'  |  | ,'    |   :    ||  ,   /|  ,   /   `--'---'  |  | ,'      `----'    `----'  ;  |,'
            `--''       \   \  /  ---`-'  ---`-'              `--''                          '--'
                         `----'

                            S h e l l s h o c k   &   C G I   W A F

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

echo "1) Patch Bash"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y bash

echo "2) UFW lockdown"
apt-get install -qq -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

echo "3) iptables drop of '() {'"
iptables -C INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP 2>/dev/null \
 || iptables -I INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP
ip6tables -C INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP 2>/dev/null \
 || ip6tables -I INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP

echo "4) Install & configure Fail2Ban"
apt-get install -qq -y fail2ban

# Combined Shellshock + CGI injection filter
cat >/etc/fail2ban/filter.d/shellshock-cgi.conf <<'EOF'
[Definition]
# Shellshock patterns
failregex = ^.*bash: warning: HTTP_[A-Z_]+: ignoring function definition attempt$
            ^.*bash: error importing function definition for `HTTP_[A-Z_]+'.$
# CGI-style injection: backticks or $(
            ^<HOST> - - \[.*\] ".*(\`|\$\().*"
            ^<HOST> - - \[.*\] ".*\(\)\s*\{.*\}.*"
ignoreregex =
EOF

# Watch both host-nginx logs and any docker-container logs
cat >/etc/fail2ban/jail.local <<'EOF'
[shellshock-cgi]
enabled  = true
filter   = shellshock-cgi
logpath  = /var/log/nginx/access.log
           /var/log/nginx/error.log
           /var/lib/docker/containers/*/*.log
maxretry = 1
bantime  = 86400
# never ban localhost
ignoreip = 127.0.0.1/8 ::1
action   = ufw[name=ShellshockCGI, port="http,https", protocol=tcp]
EOF

systemctl reload fail2ban 2>/dev/null || service fail2ban restart

echo "5) Deploy host-nginx WAF snippet"
cat >/etc/nginx/conf.d/shellshock-cgi-waf.conf <<'EOF'
# Block Shellshock & CGI injection
map $http_user_agent $block_waf {
    default         0;
    "~\(\)\s*\{"    1;  # Shellshock
    "~(\`|\$\()"    1;  # CGI injection
}
server {
    listen 80  default_server;
    listen 443 ssl default_server;
    location / {
        if ($block_waf) {
            return 403;
        }
        # proxy_pass or root stays untouched
    }
}
EOF
nginx -t && systemctl reload nginx

# 6) Deploy into any running nginx Docker container
for cid in $(docker ps --filter ancestor=nginx --format '{{.ID}}'); do
  echo " → Copying WAF into container $cid"
  docker exec "$cid" mkdir -p /etc/nginx/conf.d
  docker cp /etc/nginx/conf.d/shellshock-cgi-waf.conf "$cid":/etc/nginx/conf.d/
  docker exec "$cid" nginx -t && docker exec "$cid" nginx -s reload
done

echo "🎉 WAF deployed: Bash patched, UFW locked, iptables/Fail2Ban/host-&-container nginx all protected."
