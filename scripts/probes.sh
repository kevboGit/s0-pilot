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
# proxy_attempt: the agent makes the CONNECT attempt so the proxy logs it, but it cannot
# read the proxy's own access log, so the authoritative pass/fail for a denial is decided
# by the root "corroborate proxy denials" step, which greps that log for this exact
# request. Here the agent only fails fast if the host is actually REACHABLE; a non-reach
# is marked DEFER (not a pass, not counted) and left to the log-corroboration step. The
# proxy's per-request CONNECT response code is printed for cross-checking.
proxy_attempt() {
	local id=$1 desc=$2 url=$3 hc fc
	read -r hc fc < <(
		timeout 20 curl -x "$PROXY" -s -o /dev/null -w '%{http_connect} %{http_code}' -m 15 "$url"
		echo
	)
	# A denied host must never get a tunnel. Fail fast if the proxy returned 200 to the
	# CONNECT (tunnel established) or the inner request reached a 2xx; otherwise DEFER to
	# the root Squid-log step, which is authoritative.
	if [ "${hc:-000}" = 200 ] || printf '%s' "${fc:-000}" | grep -qE '^2'; then
		verdict "$id" FAIL open "$desc (proxy tunneled it: CONNECT=${hc:-none}, HTTP=${fc:-none})"
	else
		printf 'PROBE %-4s %-6s %-5s %s\n' "$id" DEFER log "$desc (proxy CONNECT reply=${hc:-none}; authoritative result from the root Squid-log step)"
	fi
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
# P17 (the Azure wire-server 168.63.129.16) was REMOVED: its control target is unreachable
# even from the runner on GitHub-hosted infrastructure (control C05), so no probe from here
# can prove the agent is blocked from it. COVERAGE LIMITATION: egress to 168.63.129.16 is
# not tested. The real credential-exposure vector, the IMDS endpoint 169.254.169.254, IS
# covered conclusively by P16, and all other direct egress is denied by the filter (P14)
# and proved blocked; a connection to 168.63.129.16 would be caught by the same P14 rule.
gated P18 "an allowed host without the proxy" C06 "6 7" env -u HTTPS_PROXY -u https_proxy curl --noproxy '*' -sS -m 8 https://api.anthropic.com/
gated P19 "git over HTTPS to github.com without the proxy" C07 "128" git -c http.proxy= ls-remote https://github.com/actions/checkout

# Network: the proxy must allow only the listed hosts, only by CONNECT on 443. The HTTPS
# denials (P20/P21/P25/P26) are CONNECT attempts whose authoritative verdict comes from the
# root Squid-log corroboration step; here they are DEFER unless the host is reachable.
proxy_attempt P20 "github.com through the proxy" "https://github.com/"
proxy_attempt P21 "a GitHub IP literal through the proxy" "https://${GITHUB_IP}/"
# P22 is plain HTTP (not CONNECT), so squid's 403 is visible to the agent directly.
p22_code=$(timeout 20 curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' -m 15 http://example.com/)
case "$p22_code" in
403) verdict P22 PASS shut "plain HTTP through the proxy (proxy 403)" ;;
2??) verdict P22 FAIL open "plain HTTP through the proxy (reachable, HTTP $p22_code)" ;;
*) verdict P22 INCON skip "plain HTTP through the proxy (HTTP $p22_code, not a proxy denial)" ;;
esac
denied P23 "git over HTTPS to github.com through the proxy" "128" git -c "http.proxy=$PROXY" ls-remote https://github.com/actions/checkout
reach_code=$(timeout 30 curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' -m 20 https://api.anthropic.com/v1/models)
case "$reach_code" in
2?? | 401 | 4??) verdict P24 PASS open "api.anthropic.com through the proxy (HTTP $reach_code without a key)" ;;
*) verdict P24 FAIL shut "api.anthropic.com through the proxy (HTTP $reach_code)" ;;
esac
if grep -qx registry.npmjs.org "$OPT/allowed-hosts" 2>/dev/null; then
	reachable P25 "registry.npmjs.org through the proxy (allowed in this phase)" curl -x "$PROXY" -sS -f -m 20 -o /dev/null https://registry.npmjs.org/
else
	proxy_attempt P25 "registry.npmjs.org through the proxy (not allowed in this phase)" "https://registry.npmjs.org/"
fi
proxy_attempt P26 "GitHub's REST API through the proxy" "https://api.github.com/"

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

# P28: no path a privileged command loads code or configuration from may be agent-writable.
# This is the precise library analogue of P27: (a) every directory on root's dynamic-linker
# search path (and its ancestors, symlinks resolved), (b) every shared library each trusted
# binary actually loads, and (c) the loader and privilege configuration files. Each would
# let the agent influence a root process, so all are strict blockers. Writable directories
# that are on NONE of these privileged paths are reported in the INFO line below, never
# failed on — but only after this check has cleared the paths that matter.
p28=""
while IFS= read -r d; do
	[ -n "$d" ] || continue
	real=$(readlink -f "$d" 2>/dev/null) || continue
	[ -d "$real" ] || continue
	p=$real
	while :; do
		[ -w "$p" ] && {
			p28="$p28 libdir:$d->$p"
			break
		}
		[ "$p" = / ] && break
		p=$(dirname "$p")
	done
done <"$OPT/priv-lib-path"
for b in $(cat "$OPT/trusted-bins" 2>/dev/null); do
	[ -x "$b" ] || continue
	while IFS= read -r lib; do
		[ -e "$lib" ] || continue
		{ [ -w "$lib" ] || [ -w "$(dirname "$lib")" ]; } && p28="$p28 lib:$b:$lib"
	done < <(ldd "$b" 2>/dev/null | grep -oE '/[^ ]+')
done
# ld.so.preload first: a library listed there is preloaded into every dynamically linked
# process, including every later root command. A config that does not exist but whose
# parent directory is agent-writable is also a finding, because the agent could create it
# (the mis-shipped-writable case this whole check exists for).
for c in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.cache /etc/nsswitch.conf /etc/sudoers /etc/sudoers.d /etc/sudo.conf /etc/environment; do
	if [ -e "$c" ]; then
		[ -w "$c" ] && p28="$p28 cfg:$c"
	else
		[ -w "$(dirname "$c")" ] && p28="$p28 cfg:$c(creatable)"
	fi
done
[ -z "$p28" ] && verdict P28 PASS none "no privileged library path, loaded library, or loader/privilege config is agent-writable" || verdict P28 FAIL found "privileged execution deps agent-writable:$p28"

# Informational only (never pass/fail): other agent-writable directories that are on NO
# privileged executable or library search path — e.g. the runner image's writable tool
# trees. Summarised by count and top categories, never enumerated, so no log dump.
sweep=$(mktemp "${TMPDIR:-/tmp}/s0sweep.XXXXXX") || sweep=/home/agent/tmp/s0sweep
: >"$sweep"
swept_out=0
for m in $(awk '{print $5}' /proc/self/mountinfo | sort -u); do
	timeout 60 find "$m" -xdev -type d -writable 2>/dev/null >>"$sweep"
	[ $? -eq 124 ] && swept_out=1
done
other=$(grep -vE '^(/home/agent|/tmp|/var/tmp|/dev/shm|/proc|/sys|/run/user)(/|$)' "$sweep")
total=$(printf '%s\n' "$other" | grep -c . || true)
cats=$(printf '%s\n' "$other" | grep . | sed -E 's#(/[^/]+/[^/]+).*#\1#' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s(%s) ", $2, $1}')
rm -f "$sweep"
printf 'INFO other agent-writable dirs, not on any privileged path%s: %s total; top: %s\n' "$([ "$swept_out" = 1 ] && echo ' [sweep partial: timed out]')" "$total" "${cats:-none}"
printf 'INFO listening on 127.0.0.1: %s\n' "$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E '^127\.0\.0\.1:' | tr '\n' ' ')"

[ "$FAILED" -eq 0 ] && echo "RESULT all probes passed" || echo "RESULT at least one probe did not pass: stop"
exit "$FAILED"
