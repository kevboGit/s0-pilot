#!/usr/bin/env bash
# Negative tests, run as the unprivileged `agent` user inside the pilot sandbox.
# Each capability probe must FAIL to gain the capability; each allowed host must be
# reachable through the proxy, and the npm registry must not be unless it is allowed.
# One line per probe; exit status 1 if any probe fails.
# Never prints a credential: credential searches report file paths and counts only.
# Usage: probes.sh <controls.env>
set -u
CONTROLS=${1:-/opt/s0/controls.env}
# shellcheck disable=SC1090
[ -r "$CONTROLS" ] && . "$CONTROLS"
GITHUB_IP=${GITHUB_IP:-140.82.112.3}
PROXY=http://127.0.0.1:3128
FAILED=0

report() {
	printf 'PROBE %-4s %-6s %-5s %s\n' "$1" "$2" "$3" "$4"
	[ "$2" = FAIL ] && FAILED=1
	return 0
}
# blocked ID DESC CMD...: PASS when CMD fails (the capability is absent).
blocked() {
	local id=$1 desc=$2
	shift 2
	if timeout 20 "$@" >/dev/null 2>&1; then report "$id" FAIL open "$desc"; else report "$id" PASS shut "$desc"; fi
}
# reachable ID DESC CMD...: PASS when CMD succeeds (the allowed path works).
reachable() {
	local id=$1 desc=$2
	shift 2
	if timeout 30 "$@" >/dev/null 2>&1; then report "$id" PASS open "$desc"; else report "$id" FAIL shut "$desc"; fi
}

# Identity and privilege
if [ "$(id -u)" -ne 0 ] && [ "$(id -Gn)" = "agent" ]; then report P01 PASS ok "runs as unprivileged agent, no extra groups ($(id -Gn))"; else report P01 FAIL bad "identity: $(id)"; fi
blocked P02 "sudo without a password" sudo -n true
blocked P03 "write a system path" touch /usr/local/bin/s0-probe
blocked P04 "change the packet filter" iptables -S
blocked P05 "change routing" ip route add 10.255.255.0/24 dev lo
blocked P06 "write the proxy configuration" test -w /etc/squid/squid.conf
blocked P07 "use the Docker socket" test -w /var/run/docker.sock

# Credentials and the runner's state
names=$(env | cut -d= -f1 | grep -E 'TOKEN|SECRET|PASSWORD|GITHUB_|ACTIONS_|RUNNER_|^GH_|AWS_|AZURE_|_KEY$' | grep -vx 'ANTHROPIC_API_KEY' | tr '\n' ' ')
if [ -z "$names" ]; then report P08 PASS none "no token-like variables in the agent's environment"; else report P08 FAIL found "variables: $names"; fi
readable=0
for d in /proc/[0-9]*; do
	owner=$(stat -c %U "$d" 2>/dev/null) || continue
	[ "$owner" = agent ] && continue
	head -c1 "$d/environ" >/dev/null 2>&1 && readable=$((readable + 1))
done
if [ "$readable" -eq 0 ]; then report P09 PASS none "no other user's process environment is readable"; else report P09 FAIL "$readable" "other users' process environments readable"; fi
blocked P10 "list the runner's home (workspace, temp files, logs)" ls /home/runner
# The patterns are assembled from parts so that this file itself never matches a
# secret scanner.
key_hdr='-----BEGIN [A-Z ]*PRIV''ATE KEY-----'
patterns="gh[pousr]_[A-Za-z0-9]{30,}|github_""pat_[A-Za-z0-9_]{40,}|${key_hdr}|sk-""ant-[A-Za-z0-9_-]{20,}"
hits=$(timeout 120 grep -rIlE "$patterns" /tmp /var/tmp /home /run /var/log /etc 2>/dev/null | grep -v '^/home/agent/' | head -20)
if [ -z "$hits" ]; then report P11 PASS none "no credential-like content in readable files (/tmp /var/tmp /home /run /var/log /etc)"; else report P11 FAIL found "paths: $(echo "$hits" | tr '\n' ' ')"; fi

# Network: direct paths must be closed
blocked P12 "DNS through the local stub" getent hosts github.com
blocked P13 "DNS to an outside resolver" dig +time=2 +tries=1 @1.1.1.1 github.com
blocked P14 "direct TCP to a GitHub address" curl --noproxy '*' -sS -m 8 -k "https://${GITHUB_IP}/"
blocked P15 "direct IPv6" curl --noproxy '*' -6 -sS -m 8 "https://[2606:4700:4700::1111]/"
blocked P16 "cloud metadata service" curl --noproxy '*' -sS -m 5 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
blocked P17 "Azure host service address" curl --noproxy '*' -sS -m 5 http://168.63.129.16/
blocked P18 "an allowed host without the proxy" env -u HTTPS_PROXY -u https_proxy curl --noproxy '*' -sS -m 8 https://api.anthropic.com/
blocked P19 "git over HTTPS to github.com without the proxy" git -c http.proxy= ls-remote https://github.com/actions/checkout

# Network: the proxy must allow only the two hosts, only by CONNECT on 443
blocked P20 "github.com through the proxy" curl -x "$PROXY" -sS -f -m 10 https://github.com/
blocked P21 "a GitHub IP literal through the proxy" curl -x "$PROXY" -sS -f -m 10 -k "https://${GITHUB_IP}/"
blocked P22 "plain HTTP through the proxy" curl -x "$PROXY" -sS -f -m 10 http://example.com/
blocked P23 "git over HTTPS to github.com through the proxy" git -c "http.proxy=$PROXY" ls-remote https://github.com/actions/checkout
code=$(timeout 30 curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' -m 20 https://api.anthropic.com/v1/models)
case "$code" in 2?? | 4??) report P24 PASS open "api.anthropic.com through the proxy (HTTP $code without a key)" ;; *) report P24 FAIL shut "api.anthropic.com through the proxy (HTTP $code)" ;; esac
if grep -qx registry.npmjs.org /opt/s0/allowed-hosts 2>/dev/null; then
	reachable P25 "registry.npmjs.org through the proxy (allowed in this phase)" curl -x "$PROXY" -sS -f -m 20 -o /dev/null https://registry.npmjs.org/
else
	blocked P25 "registry.npmjs.org through the proxy (not allowed in this phase)" curl -x "$PROXY" -sS -f -m 20 -o /dev/null https://registry.npmjs.org/
fi
blocked P26 "GitHub's REST API through the proxy" curl -x "$PROXY" -sS -f -m 10 https://api.github.com/

# Information only: what listens on loopback (the agent may reach 127.0.0.1)
printf 'INFO listening on 127.0.0.1: %s\n' "$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E '^127\.0\.0\.1:' | tr '\n' ' ')"

if [ "$FAILED" -eq 0 ]; then echo "RESULT all probes passed"; else echo "RESULT at least one probe failed: stop"; fi
exit "$FAILED"
