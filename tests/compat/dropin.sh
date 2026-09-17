#!/usr/bin/env bash
# Proves the image can replace adguard/adguardhome under a live deployment.
#
# Runs the Go build on a volume, configures it, generates traffic, swaps the
# image underneath it, swaps back, and then has the Go build read everything
# this one wrote. What is being checked is that nothing on the volume has to
# change and nobody is signed out -- not that the two agree on an API shape,
# which api_diff.py covers.
#
# Usage: dropin.sh [agl-image] [go-image]
set -uo pipefail

AGL="${1:-ghcr.io/openhoangnc/sift:0.107.79}"
GO="${2:-adguard/adguardhome:v0.107.79}"
R="$(mktemp -d "${TMPDIR:-/tmp}/agl-dropin.XXXXXX")"
B=http://127.0.0.1:13900
U=admin
P='DropIn!2026'
A="$U:$P"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
is()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }
code(){ curl -sS -o /dev/null -w '%{http_code}' "$@"; }
J()   { curl -sS -u "$A" -H 'Content-Type: application/json' "$@"; }

cleanup() { docker rm -f agl-dropin >/dev/null 2>&1; rm -rf "$R"; }
trap cleanup EXIT

# The deployment. Only the image ever changes.
start() {
  docker rm -f agl-dropin >/dev/null 2>&1
  docker run -d --name agl-dropin \
    -v "$R/work:/opt/adguardhome/work" \
    -v "$R/conf:/opt/adguardhome/conf" \
    -p 15390:53/udp -p 13900:3000/tcp \
    --restart unless-stopped \
    "$1" >/dev/null 2>&1 || { echo "could not start $1" >&2; exit 1; }
  for _ in $(seq 80); do
    [ "$(code $B/control/status)" != "000" ] && return 0
    sleep 0.5
  done
  echo "$1 never answered" >&2; docker logs agl-dropin 2>&1 | tail -20 >&2; exit 1
}

mkdir -p "$R/work" "$R/conf"

echo "== the image contract =="
for field in Entrypoint Cmd WorkingDir User Volumes ExposedPorts StopSignal; do
  a=$(docker inspect "$GO"  --format "{{json .Config.$field}}")
  b=$(docker inspect "$AGL" --format "{{json .Config.$field}}")
  is "$field matches" "$b" "$a"
done

echo
echo "== a configured Go deployment =="
start "$GO"
is "install" "$(code -X POST $B/control/install/configure -H 'Content-Type: application/json' \
   -d "$(printf '{"web":{"ip":"0.0.0.0","port":3000},"dns":{"ip":"0.0.0.0","port":53},"username":"%s","password":"%s","set_static_ip":false}' "$U" "$P")")" "200"
sleep 3
J -o /dev/null -X POST "$B/control/filtering/set_rules" -d '{"rules":["||ads.example.com^","127.0.0.1 hosts.example.com"]}'
J -o /dev/null -X POST "$B/control/rewrite/add"        -d '{"domain":"rw.example.com","answer":"10.1.2.3"}'
J -o /dev/null -X PUT  "$B/control/blocked_services/update" -d '{"ids":["facebook"],"schedule":{"time_zone":"UTC"}}'
J -o /dev/null -X POST "$B/control/clients/add"        -d '{"name":"laptop","ids":["192.168.1.50"],"use_global_settings":false,"filtering_enabled":true,"parental_enabled":false,"safebrowsing_enabled":false,"use_global_blocked_services":true,"blocked_services":[],"upstreams":[],"tags":["device_laptop"]}'
sleep 2
# A live browser session, and some traffic to fill the log and the statistics.
JAR=$(curl -sS -i -X POST "$B/control/login" -H 'Content-Type: application/json' \
      -d "$(printf '{"name":"%s","password":"%s"}' "$U" "$P")" \
      | tr -d '\r' | grep -i '^set-cookie:' | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1)
for n in ads.example.com hosts.example.com rw.example.com facebook.com example.com; do
  dig @127.0.0.1 -p 15390 "$n" A +short +timeout=3 >/dev/null 2>&1
done
sleep 2
go_stats=$(J "$B/control/stats" | jq -r .num_dns_queries)
ok "Go recorded $go_stats queries"
docker stop agl-dropin >/dev/null; sleep 2
cp -a "$R/conf/AdGuardHome.yaml" "$R/config-go.yaml"

echo
echo "== swap the image, same volume, same flags =="
start "$AGL"
sleep 2
is "a session the Go build issued still works" "$(code -H "Cookie: $JAR" $B/control/status)" "200"
is "the Go-written password hash logs in"      "$(code -X POST $B/control/login -H 'Content-Type: application/json' -d "$(printf '{"name":"%s","password":"%s"}' "$U" "$P")")" "200"
is "custom rules survived"    "$(J "$B/control/filtering/status" | jq -c .user_rules)" '["||ads.example.com^","127.0.0.1 hosts.example.com"]'
is "rewrites survived"        "$(J "$B/control/rewrite/list" | jq -c '[.[].domain]')" '["rw.example.com"]'
is "blocked services survived" "$(J "$B/control/blocked_services/get" | jq -c .ids)" '["facebook"]'
is "the client and its tags survived" "$(J "$B/control/clients" | jq -c '[.clients[] | {name, tags}]')" '[{"name":"laptop","tags":["device_laptop"]}]'
is "a blocked name still answers 0.0.0.0" "$(dig @127.0.0.1 -p 15390 ads.example.com A +short +timeout=3 | head -1)" "0.0.0.0"
is "a rewrite still answers"              "$(dig @127.0.0.1 -p 15390 rw.example.com A +short +timeout=3 | head -1)" "10.1.2.3"
sift_stats=$(J "$B/control/stats" | jq -r .num_dns_queries)
[ "${sift_stats:-0}" -ge "${go_stats:-1}" ] && ok "statistics continued from Go's ($go_stats -> $sift_stats)" \
  || bad "statistics reset (Go had $go_stats, now $sift_stats)"
qn=$(J "$B/control/querylog?limit=100" | jq '.data | length')
[ "${qn:-0}" -ge "${go_stats:-1}" ] && ok "the Go build's query log is readable ($qn entries)" \
  || bad "query log lost entries (want >= $go_stats, got $qn)"
if diff -q "$R/config-go.yaml" "$R/conf/AdGuardHome.yaml" >/dev/null; then
  ok "the config file is untouched"
else
  bad "the config file changed:"; diff -u "$R/config-go.yaml" "$R/conf/AdGuardHome.yaml" | head -20
fi

echo
echo "== write settings here, then hand them back to the Go build =="
J -o /dev/null -X POST "$B/control/dns_config" -d '{"upstream_dns":["https://dns.quad9.net/dns-query","tls://1.1.1.1"],"bootstrap_dns":["9.9.9.10"],"ratelimit":30,"blocking_mode":"nxdomain","cache_size":8388608,"edns_cs_enabled":true,"dnssec_enabled":true}'
J -o /dev/null -X POST "$B/control/rewrite/add" -d '{"domain":"*.lab.example.com","answer":"10.7.7.7"}'
sleep 2
docker stop agl-dropin >/dev/null; sleep 2

start "$GO"
sleep 2
is "Go still logs in"          "$(code -X POST $B/control/login -H 'Content-Type: application/json' -d "$(printf '{"name":"%s","password":"%s"}' "$U" "$P")")" "200"
is "a session this build issued works on Go" "$(code -H "Cookie: $JAR" $B/control/status)" "200"
is "Go reads the upstreams we wrote" "$(J "$B/control/dns_info" | jq -c .upstream_dns)" '["https://dns.quad9.net/dns-query","tls://1.1.1.1"]'
is "Go reads the blocking mode"      "$(J "$B/control/dns_info" | jq -r .blocking_mode)" "nxdomain"
is "Go reads the wildcard rewrite"   "$(J "$B/control/rewrite/list" | jq -c '[.[].domain]')" '["rw.example.com","*.lab.example.com"]'
# We set blocking_mode=nxdomain above, so the verdict is now an NXDOMAIN
# rather than the null address -- which is itself the proof Go picked up the
# setting this build wrote.
is "Go blocks the way the mode we wrote says" \
   "$(dig @127.0.0.1 -p 15390 ads.example.com A +timeout=3 | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')" "NXDOMAIN"
go_back=$(J "$B/control/stats" | jq -r .num_dns_queries)
[ "${go_back:-0}" -ge "${sift_stats:-1}" ] && ok "Go continued our statistics ($sift_stats -> $go_back)" \
  || bad "Go lost our statistics (had $sift_stats, now $go_back)"

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
