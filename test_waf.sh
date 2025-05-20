#!/usr/bin/env bash
#
# test_waf.sh — Continue-past-failures WAF validation
# Usage: sudo ./test_waf.sh

set +e
HOST="localhost"; HTTP=80; HTTPS=443
PASS=0; FAIL=0

report(){ [[ $2==PASS ]] && { echo "✅ $1"; ((PASS++)); } || { echo "❌ $1"; ((FAIL++)); } }

echo "Testing on $HOST (HTTP $HTTP, HTTPS $HTTPS)"
echo

# 1) Bash patch
out=$( env x='() { :;}; echo VULNERABLE' bash -c 'echo SAFE' 2>/dev/null )
report "Bash patch" $([[ $out=="SAFE" ]] && echo PASS || echo FAIL)

# 2) HTTP 200?
code=$(curl -s -m2 -o /dev/null -w '%{http_code}' http://$HOST:$HTTP)
report "HTTP $HTTP reachable (200)" $([[ $code=="200" ]] && echo PASS || echo FAIL)

# 3) HTTPS 200?
code=$(curl -k -s -m2 -o /dev/null -w '%{http_code}' https://$HOST:$HTTPS)
report "HTTPS $HTTPS reachable (200)" $([[ $code=="200" ]] && echo PASS || echo FAIL)

# 4) iptables drop
printf "GET/HTTP\r\nHost:$HOST\r\nUser-Agent:() { :;};echoX\r\n\r\n"\
| nc -w2 $HOST $HTTP >/dev/null 2>&1
report "iptables drop '() {'" $([[ $? -ne 0 ]] && echo PASS || echo FAIL)

# 5) Host-nginx header test
code=$(curl -s -m2 -o /dev/null -w '%{http_code}' \
  -H 'User-Agent: () { :;}; echo X' http://$HOST:$HTTP)
report "host nginx blocks WAF (403)" $([[ $code=="403" ]] && echo PASS || echo FAIL)

# 6) Container-nginx header test
for cid in $(docker ps --filter ancestor=nginx --format '{{.ID}}'); do
  code=$(docker exec $cid curl -s -m2 -o /dev/null -w '%{http_code}' \
    -H 'User-Agent: () { :;}; echo X' http://localhost/)
  report "container $cid nginx blocks WAF (403)" $([[ $code=="403" ]] && echo PASS || echo FAIL)
done

# 7) Fail2Ban ban test
fail2ban-client unban 127.0.0.1 shellshock-cgi >/dev/null 2>&1
curl -s -m2 -H 'User-Agent: () { :;}; echo X' http://$HOST:$HTTP >/dev/null 2>&1
sleep 2
fail2ban-client status shellshock-cgi | grep -q 127.0.0.1
report "Fail2Ban bans remote" $([[ $? -eq 1 ]] && echo PASS || echo FAIL)

echo; echo "✅ $PASS passed, ❌ $FAIL failed."
exit $FAIL
