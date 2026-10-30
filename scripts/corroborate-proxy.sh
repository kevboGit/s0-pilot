#!/usr/bin/env bash
# Runs as root AFTER the agent probe phase. The agent cannot read the proxy's access log
# (and must not be given access to it), so this step is the authoritative verdict for the
# HTTPS-via-proxy denials P20/P21/P25/P26: each counts as a PASS only when the Squid log
# holds a TCP_DENIED/403 CONNECT entry for that exact host AND no TCP_TUNNEL/200 entry for
# it. Missing, ambiguous or contradictory evidence is INCONCLUSIVE and fails the job. The
# one allowed host is confirmed positively. Reads only root-owned inputs.
# Usage: sudo bash corroborate-proxy.sh
set -u
LOG=/var/log/squid/access.log
CONTROLS=/opt/s0/controls.env
ALLOW=/opt/s0/allowed-hosts
GITHUB_IP=140.82.112.3
# shellcheck disable=SC1090
[ -r "$CONTROLS" ] && . "$CONTROLS"
FAILED=0

if [ ! -r "$LOG" ]; then
	echo "CORROBORATE INCON: the Squid access log is not readable at $LOG: cannot corroborate; stop"
	exit 1
fi

# The Squid log puts a size field between the result code and the method
# (`TCP_DENIED/403 <size> CONNECT host:443`); the host's dots are escaped so an IP literal
# matches literally. The allowlist is read from the sandbox so the expected verdict tracks
# whatever hosts were actually allowed, not a hardcoded assumption.
esc() { printf '%s' "$1" | sed 's/\./\\./g'; }
count() { grep -cE "$1[[:space:]]+[0-9]+[[:space:]]+CONNECT[[:space:]]+$(esc "$2"):443" "$LOG"; }
is_allowed() { grep -qxF "$1" "$ALLOW" 2>/dev/null; }

check_denied() { # id host  -> PASS only with a 403 denial and no tunnel
	local id=$1 host=$2
	if [ "$(count TCP_TUNNEL/200 "$host")" -gt 0 ]; then
		echo "CORROBORATE $id FAIL open: $host was tunneled: the proxy allowed it"
		FAILED=1
	elif [ "$(count TCP_DENIED/403 "$host")" -gt 0 ]; then
		echo "CORROBORATE $id PASS shut: $host denied by the proxy (TCP_DENIED/403 CONNECT, no tunnel)"
	else
		echo "CORROBORATE $id INCON: no TCP_DENIED/403 CONNECT $host:443 entry: cannot prove denial; stop"
		FAILED=1
	fi
}
check_allowed() { # id host  -> must actually tunnel
	local id=$1 host=$2
	if [ "$(count TCP_TUNNEL/200 "$host")" -gt 0 ]; then
		echo "CORROBORATE $id PASS open: $host allowed and tunneled"
	else
		echo "CORROBORATE $id INCON: $host is allowed but did not tunnel: the allow path is broken; stop"
		FAILED=1
	fi
}

# The hosts that must be denied unless this run explicitly allowed them.
for pair in "P20 github.com" "P21 ${GITHUB_IP}" "P25 registry.npmjs.org" "P26 api.github.com"; do
	# shellcheck disable=SC2086
	set -- $pair
	if is_allowed "$2"; then check_allowed "$1" "$2"; else check_denied "$1" "$2"; fi
done
# Every explicitly allowed host must actually tunnel (covers api.anthropic.com and any
# custom allowlist entry); a denial there would mean the allowed path is broken.
while IFS= read -r h; do [ -n "$h" ] && check_allowed "allow:$h" "$h"; done <"$ALLOW"

[ "$FAILED" -eq 0 ] && echo "CORROBORATE RESULT: all proxy denials corroborated by the Squid log" || echo "CORROBORATE RESULT: proxy corroboration failed: stop"
exit "$FAILED"
