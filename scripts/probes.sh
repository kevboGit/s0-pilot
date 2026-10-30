#!/usr/bin/env bash
# Negative tests, run as the unprivileged `agent` user inside the pilot sandbox.
# Each capability probe must FAIL to gain the capability; each allowed host must be
# reachable through the proxy, and every other host must not be.
#
# A probe PASSES only when it proves the control it names is enforced. A command that
# fails for an unrelated reason (missing binary, unreadable directory, a control that was
# never reachable) is reported INCONCLUSIVE and fails the job exactly like a FAIL: an
# inconclusive probe never counts as a pass. One line per probe; exit 1 if any did not
# pass. It never prints a credential value; searches for one report only paths and counts.
# Usage: probes.sh <controls.env>
set -u
cd "${HOME:-/home/agent}" 2>/dev/null || cd / # never run from the runner's closed cwd
CONTROLS=${1:-/opt/s0/controls.env}
# shellcheck disable=SC1090
[ -r "$CONTROLS" ] && . "$CONTROLS"
GITHUB_IP=${GITHUB_IP:-140.82.112.3}
PROXY=http://127.0.0.1:3128
OPT=/opt/s0
FAILED=0

verdict() { # verdict <id> <PASS|FAIL|INCON> <tag> <desc>
	printf 'PROBE %-4s %-6s %-5s %s\n' "$1" "$2" "$3" "$4"
	[ "$2" = PASS ] || FAILED=1
}
# shut: capability probe. Any non-zero exit means the capability is absent (PASS).
shut() {
	local id=$1 desc=$2
	shift 2
	if timeout 20 "$@" >/dev/null 2>&1; then verdict "$id" FAIL open "$desc"; else verdict "$id" PASS shut "$desc"; fi
}
# reachable: an allowed path that must work.
reachable() {
	local id=$1 desc=$2
	shift 2
	if timeout 30 "$@" >/dev/null 2>&1; then verdict "$id" PASS open "$desc"; else verdict "$id" FAIL shut "$desc"; fi
}
# denied: network block. PASS only on an exit code the network policy produces; exit 0 is
# FAIL (reachable); any other exit is INCONCLUSIVE.
denied() {
	local id=$1 desc=$2 allow=$3
	shift 3
	local out code
	out=$(timeout 25 "$@" 2>&1)
	code=$?
	if [ "$code" -eq 0 ]; then
		verdict "$id" FAIL open "$desc (reachable)"
		return
	fi
	case " $allow " in
	*" $code "*) verdict "$id" PASS shut "$desc (exit $code)" ;;
	*) verdict "$id" INCON skip "$desc (unexpected exit $code: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-60))" ;;
	esac
}
# gated: denied, but only if the named control succeeded; otherwise INCONCLUSIVE.
gated() {
	local id=$1 desc=$2 cv=$3
	shift 3
	if [ "${!cv:-no}" != yes ]; then
		verdict "$id" INCON skip "$desc (control $cv=${!cv:-unset}: cannot test)"
		return
	fi
	denied "$id" "$desc" "$@"
}
# proxy_denied: the proxy must refuse this host with a 403 (a true policy denial), not
# merely fail to connect.
proxy_denied() {
	local id=$1 desc=$2 url=$3 code cexit
	code=$(timeout 20 curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' -m 15 "$url")
	cexit=$?
	if [ "$cexit" -ne 0 ]; then
		verdict "$id" INCON skip "$desc (curl exit $cexit, no HTTP status)"
		return
	fi
	case "$code" in
	403) verdict "$id" PASS shut "$desc (proxy 403)" ;;
	2??) verdict "$id" FAIL open "$desc (reachable, HTTP $code)" ;;
	*) verdict "$id" INCON skip "$desc (HTTP $code, not a proxy denial)" ;;
	esac
}

# Identity and privilege.
if [ "$(id -u)" -ne 0 ] && [ "$(id -Gn)" = agent ]; then verdict P01 PASS ok "unprivileged agent, no extra groups ($(id -Gn))"; else verdict P01 FAIL bad "identity $(id)"; fi
shut P02 "sudo without a password" sudo -n true
shut P03 "write a system path" touch /usr/local/bin/s0-probe
shut P04 "change the packet filter" iptables -S
shut P05 "change routing" ip route add 10.255.255.0/24 dev lo
# A missing target is reported inconclusive, not passed: "not writable" must mean the
# target exists and is protected, not that it is simply absent.
present_unwritable() {
	local id=$1 desc=$2 path=$3
	if [ ! -e "$path" ]; then
		verdict "$id" INCON skip "$desc ($path absent: cannot test)"
	elif [ -w "$path" ]; then
		verdict "$id" FAIL open "$desc ($path writable)"
	else
		verdict "$id" PASS shut "$desc"
	fi
}
present_unwritable P06 "write the proxy configuration" /etc/squid/squid.conf
present_unwritable P07 "use the Docker socket" /var/run/docker.sock

# Credentials and the runner's state.
names=$(env | cut -d= -f1 | grep -E 'TOKEN|SECRET|PASSWORD|GITHUB_|ACTIONS_|RUNNER_|^GH_|AWS_|AZURE_|_KEY$' | grep -vx 'ANTHROPIC_API_KEY' | tr '\n' ' ')
[ -z "$names" ] && verdict P08 PASS none "no token-like variables in the agent's environment" || verdict P08 FAIL found "$names"
readable=0
for d in /proc/[0-9]*; do
	owner=$(stat -c %U "$d" 2>/dev/null) || continue
	[ "$owner" = agent ] && continue
	head -c1 "$d/environ" >/dev/null 2>&1 && readable=$((readable + 1))
done
[ "$readable" -eq 0 ] && verdict P09 PASS none "no other user's process environment is readable" || verdict P09 FAIL "$readable" "other environments readable"
shut P10 "list the runner's home (workspace, temp files, logs)" ls /home/runner
# Patterns assembled from parts so this file never itself matches a secret scanner.
key_hdr='-----BEGIN [A-Z ]*PRIV''ATE KEY-----'
patterns="gh[pousr]_[A-Za-z0-9]{30,}|github_""pat_[A-Za-z0-9_]{40,}|${key_hdr}|sk-""ant-[A-Za-z0-9_-]{20,}"
hits=$(timeout 120 grep -rIlE "$patterns" /tmp /var/tmp /home /run /var/log /etc 2>/dev/null | grep -v '^/home/agent/' | head -20)
[ -z "$hits" ] && verdict P11 PASS none "no credential-like content in readable files (/tmp /var/tmp /home /run /var/log /etc)" || verdict P11 FAIL found "$(echo "$hits" | tr '\n' ' ')"

# Network: direct paths must be closed, and each is tested only where its control worked.
# The filter rejects with ICMP admin-prohibited, so a direct TCP attempt fails to connect
# with exit 7; getent/dig failures and name-resolution failures (6) are the DNS block.
# TLS/data-phase errors (35/52/56) would mean the connection was allowed, so they are not
# accepted as a block (they fall through to inconclusive).
gated P12 "DNS through the local stub" C01 "2" getent hosts github.com
gated P13 "DNS to an outside resolver" C08 "9 10" dig +time=2 +tries=1 @1.1.1.1 github.com
gated P14 "direct TCP to a GitHub address" C02 "7" curl --noproxy '*' -sS -m 8 -k "https://${GITHUB_IP}/"

# IPv6 egress, proved against a live root-owned ::1 listener (control = its own heartbeat).
ipv6_probe() {
	local ctl port hb now
	ctl=$(cat "$OPT/ipv6-ctl" 2>/dev/null || echo fail)
	port=$(cat "$OPT/ipv6-port" 2>/dev/null || echo 0)
	hb=$(cat "$OPT/ipv6-hb" 2>/dev/null || echo 0)
	case "$port" in '' | *[!0-9]*) port=0 ;; esac
	case "$hb" in '' | *[!0-9]*) hb=0 ;; esac
	now=$(date +%s)
	if [ "$ctl" != ok ] || [ "$port" = 0 ] || [ $((now - hb)) -gt 5 ]; then
		verdict P15 INCON skip "IPv6 listener control missing or stale (ctl=$ctl port=$port age=$((now - hb))s)"
		return
	fi
	denied P15 "IPv6 to the live ::1 listener" "7" curl --noproxy '*' -sS -m 8 "http://[::1]:$port/"
}
ipv6_probe

gated P16 "cloud metadata service (IMDS)" C04 "7" curl --noproxy '*' -sS -m 5 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
if [ "${C05:-no}" = yes ]; then
	denied P17 "Azure host service address" "7" curl --noproxy '*' -sS -m 5 http://168.63.129.16/
else
	verdict P17 INCON skip "Azure host 168.63.129.16 unreachable even by the runner (C05=${C05:-unset}): cannot prove the agent is blocked — owner to accept or drop this probe"
fi
gated P18 "an allowed host without the proxy" C06 "6 7" env -u HTTPS_PROXY -u https_proxy curl --noproxy '*' -sS -m 8 https://api.anthropic.com/
gated P19 "git over HTTPS to github.com without the proxy" C07 "128" git -c http.proxy= ls-remote https://github.com/actions/checkout

# Network: the proxy must allow only the listed hosts, only by CONNECT on 443.
proxy_denied P20 "github.com through the proxy" "https://github.com/"
proxy_denied P21 "a GitHub IP literal through the proxy" "https://${GITHUB_IP}/"
proxy_denied P22 "plain HTTP through the proxy" "http://example.com/"
denied P23 "git over HTTPS to github.com through the proxy" "128" git -c "http.proxy=$PROXY" ls-remote https://github.com/actions/checkout
reach_code=$(timeout 30 curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' -m 20 https://api.anthropic.com/v1/models)
case "$reach_code" in
2?? | 401 | 4??) verdict P24 PASS open "api.anthropic.com through the proxy (HTTP $reach_code without a key)" ;;
*) verdict P24 FAIL shut "api.anthropic.com through the proxy (HTTP $reach_code)" ;;
esac
if grep -qx registry.npmjs.org "$OPT/allowed-hosts" 2>/dev/null; then
	reachable P25 "registry.npmjs.org through the proxy (allowed in this phase)" curl -x "$PROXY" -sS -f -m 20 -o /dev/null https://registry.npmjs.org/
else
	proxy_denied P25 "registry.npmjs.org through the proxy (not allowed in this phase)" "https://registry.npmjs.org/"
fi
proxy_denied P26 "GitHub's REST API through the proxy" "https://api.github.com/"

# No directory a privileged command searches for a binary (nor any ancestor, resolving
# symlinks) may be writable by the agent: either would let it plant a binary a later root
# command runs. This is the direct check for the /usr/local/bin finding.
priv_path=$(cat "$OPT/priv-path" 2>/dev/null || echo /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)
writ=""
for d in ${priv_path//:/ }; do
	real=$(readlink -f "$d" 2>/dev/null) || continue
	[ -d "$real" ] || continue
	p=$real
	while :; do
		[ -w "$p" ] && {
			writ="$writ $d->$p"
			break
		}
		[ "$p" = / ] && break
		p=$(dirname "$p")
	done
done
[ -z "$writ" ] && verdict P27 PASS none "no privileged executable path is agent-writable" || verdict P27 FAIL found "agent-writable:$writ"

# Nor may any trusted binary the privileged steps run be an agent-writable FILE: directory
# hardening stops new entries, not an in-place overwrite of a writable binary.
binw=""
for b in $(cat "$OPT/trusted-bins" 2>/dev/null); do [ -e "$b" ] && [ -w "$b" ] && binw="$binw $b"; done
[ -z "$binw" ] && verdict P29 PASS none "no trusted privileged binary is agent-writable" || verdict P29 FAIL found "agent-writable binaries:$binw"

# A broad sweep of every mounted filesystem the agent can see (so a writable spot on a
# separate mount or behind a symlink still shows up), excluding the agent's own areas and
# the world-writable sticky temp dirs. A writable bin/sbin/lib directory is a blocker; any
# other writable directory is reported for the record. A find that times out is reported
# inconclusive (its listing is truncated), never a silent pass.
exec_hits=""
info=0
timed_out=0
sweep=$(mktemp "${TMPDIR:-/tmp}/s0sweep.XXXXXX") || sweep=/home/agent/tmp/s0sweep
for m in $(awk '{print $5}' /proc/self/mountinfo | sort -u); do
	timeout 60 find "$m" -xdev -type d -writable >"$sweep" 2>/dev/null
	[ $? -eq 124 ] && timed_out=1
	while IFS= read -r dir; do
		case "$dir" in
		/home/agent | /home/agent/* | /tmp | /tmp/* | /var/tmp | /var/tmp/* | /dev/shm | /dev/shm/* | /proc/* | /sys/* | /run/user/*) continue ;;
		esac
		info=$((info + 1))
		case "$dir" in */bin | */sbin | */lib | */bin/* | */sbin/* | */lib/*) exec_hits="$exec_hits $dir" ;; esac
	done <"$sweep"
done
rm -f "$sweep"
if [ -n "$exec_hits" ]; then
	verdict P28 FAIL found "agent-writable exec dirs:$exec_hits"
elif [ "$timed_out" -eq 1 ]; then
	verdict P28 INCON skip "filesystem sweep timed out: listing incomplete ($info writable dirs seen)"
else
	verdict P28 PASS none "no agent-writable executable directory on any mount ($info other writable dirs, informational)"
fi

printf 'INFO listening on 127.0.0.1: %s\n' "$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E '^127\.0\.0\.1:' | tr '\n' ' ')"

[ "$FAILED" -eq 0 ] && echo "RESULT all probes passed" || echo "RESULT at least one probe did not pass: stop"
exit "$FAILED"
