#!/usr/bin/env bash
# Verifies an Anthropic workspace spend limit before the pilot. Run it yourself, against a
# separate test workspace whose monthly spend limit is set to $1, with a key from that
# workspace only:
#
#   bash spend/spend-stop-test.sh <key-file> [ceiling-usd]
#
# It sends long-output requests until the API rejects one, and records the HTTP status,
# the error type, and how much had been spent by then (computed from each response's
# usage at list price). If the provider has not stopped it by the ceiling (default $1.20),
# it stops itself and reports the limit as NOT verified. The key is read from a file, sent
# only in a request header, and never printed or logged.
set -euo pipefail

KEY_FILE=${1:?usage: spend-stop-test.sh <key-file> [ceiling-usd]}
CEILING=${2:-1.20}
MODEL=claude-opus-5-5
IN_PER_MTOK=4.00   # list price, USD per million input tokens (claude-api reference, 2026-10)
OUT_PER_MTOK=20.00 # list price, USD per million output tokens
LOG=spend/spend-stop-test.$(date -u +%Y%m%dT%H%M%SZ).jsonl

[ -r "$KEY_FILE" ] || {
	echo "cannot read $KEY_FILE" >&2
	exit 2
}
perm=$(stat -c %a "$KEY_FILE")
[ "$perm" = 600 ] || [ "$perm" = 400 ] || {
	echo "$KEY_FILE must be mode 600 or 400 (it is $perm)" >&2
	exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077
printf 'x-api-key: %s\n' "$(tr -d '\r\n' <"$KEY_FILE")" >"$work/auth.hdr"

body=$(
	cat <<'JSON'
{"model": "claude-opus-5-5", "max_tokens": 8000,
 "messages": [{"role": "user", "content": "Write a long, detailed technical essay (at least 4000 words) on the history of version control systems. This is a load test; content quality does not matter."}]}
JSON
)

spent=0
n=0
echo "spend-stop test: model $MODEL, ceiling \$$CEILING, log $LOG"
while :; do
	n=$((n + 1))
	status=$(curl -sS -o "$work/resp.json" -w '%{http_code}' -m 600 https://api.anthropic.com/v1/messages \
		-H @"$work/auth.hdr" -H 'anthropic-version: 2026-10-21' -H 'content-type: application/json' \
		-d "$body") || status=000
	read -r etype emsg inp outp < <(
		python3 - "$work/resp.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("unparsable - 0 0"); sys.exit()
e = d.get("error") or {}
u = d.get("usage") or {}
msg = (e.get("message") or "-").replace(" ", "_")[:120]
print(e.get("type") or "-", msg, u.get("input_tokens", 0), u.get("output_tokens", 0))
PY
	)
	cost=$(python3 -c "print(round($inp*$IN_PER_MTOK/1e6 + $outp*$OUT_PER_MTOK/1e6, 4))")
	spent=$(python3 -c "print(round($spent + $cost, 4))")
	printf '{"n":%d,"time":"%s","status":"%s","error_type":"%s","error":"%s","input_tokens":%s,"output_tokens":%s,"cost":%s,"spent":%s}\n' \
		"$n" "$(date -u +%FT%TZ)" "$status" "$etype" "$emsg" "$inp" "$outp" "$cost" "$spent" >>"$LOG"
	printf 'request %2d: HTTP %s %s, spent so far $%s\n' "$n" "$status" "$etype" "$spent"
	if [ "$status" = 429 ]; then
		sleep 30
		continue
	fi
	if [ "$status" != 200 ]; then
		echo "STOPPED BY PROVIDER: HTTP $status, $etype, after \$$spent (computed). Overshoot vs \$1: \$$(python3 -c "print(round($spent-1,4))")"
		echo "Now compare with the Console's usage for this workspace, which is authoritative."
		exit 0
	fi
	if python3 -c "import sys; sys.exit(0 if $spent >= $CEILING else 1)"; then
		echo "NOT VERIFIED: the provider had not stopped requests by \$$spent (ceiling \$$CEILING). Treat the workspace limit as unproven; rely on our own guard."
		exit 1
	fi
done
