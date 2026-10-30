#!/usr/bin/env bash
# Positive controls, run as the normal runner user BEFORE the sandbox exists. They show
# that the targets the probes try to reach are really reachable from this runner, so a
# probe that is "shut" afterwards counts as evidence. Writes controls.env for the probes.
# Usage: controls.sh <output controls.env>
set -u
OUT=${1:-controls.env}
ok() { if timeout 20 "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

ip=$(getent ahostsv4 github.com | awk 'NR==1 {print $1}')
echo "GITHUB_IP=${ip:-140.82.112.3}" >"$OUT"

printf 'CONTROL C01 %-3s DNS resolves github.com (%s)\n' "$(ok getent hosts github.com)" "${ip:-none}"
printf 'CONTROL C02 %-3s direct TCP to a GitHub address\n' "$(ok curl -sS -m 8 -k "https://${ip:-140.82.112.3}/")"
printf 'CONTROL C03 %-3s direct IPv6\n' "$(ok curl -6 -sS -m 8 "https://[2606:4700:4700::1111]/")"
printf 'CONTROL C04 %-3s cloud metadata service\n' "$(ok curl -sS -m 5 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')"
printf 'CONTROL C05 %-3s Azure host service address\n' "$(ok curl -sS -m 5 http://168.63.129.16/)"
printf 'CONTROL C06 %-3s api.anthropic.com directly\n' "$(ok curl -sS -m 10 -o /dev/null https://api.anthropic.com/)"
printf 'CONTROL C07 %-3s git ls-remote to github.com\n' "$(ok git ls-remote https://github.com/actions/checkout)"
printf 'CONTROL C08 %-3s DNS to an outside resolver\n' "$(ok dig +time=2 +tries=1 @1.1.1.1 github.com)"
echo "A control marked 'no' means its probe cannot show anything: such a probe is reported as inconclusive."
