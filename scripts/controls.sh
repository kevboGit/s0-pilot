#!/usr/bin/env bash
# Positive controls, run as the normal runner user BEFORE the sandbox exists. They show
# that the targets the probes try to reach are really reachable from this runner, so a
# probe that is "shut" afterwards is evidence of enforcement rather than of an unrelated
# failure. Writes controls.env: GITHUB_IP, plus one Cnn=yes|no per control that the probes
# read to decide whether each block is testable. A probe whose control is "no" is reported
# inconclusive and fails the job; it is never counted as a pass.
# Usage: controls.sh <output controls.env>
set -u
OUT=${1:-controls.env}
ok() { if timeout 20 "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

ip=$(getent ahostsv4 github.com | awk 'NR==1 {print $1}')
c01=$(ok getent hosts github.com)
c02=$(ok curl -sS -m 8 -k "https://${ip:-140.82.112.3}/")
c03=$(ok curl -6 -sS -m 8 "https://[2606:4700:4700::1111]/")
c04=$(ok curl -sS -m 5 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')
c05=$(ok curl -sS -m 5 http://168.63.129.16/)
c06=$(ok curl -sS -m 10 -o /dev/null https://api.anthropic.com/)
c07=$(ok git ls-remote https://github.com/actions/checkout)
c08=$(ok dig +time=2 +tries=1 @1.1.1.1 github.com)

{
	echo "GITHUB_IP=${ip:-140.82.112.3}"
	echo "C01=$c01"
	echo "C02=$c02"
	echo "C03=$c03"
	echo "C04=$c04"
	echo "C05=$c05"
	echo "C06=$c06"
	echo "C07=$c07"
	echo "C08=$c08"
} >"$OUT"

printf 'CONTROL C01 %-3s DNS resolves github.com (%s)\n' "$c01" "${ip:-none}"
printf 'CONTROL C02 %-3s direct TCP to a GitHub address\n' "$c02"
printf 'CONTROL C03 %-3s direct public IPv6\n' "$c03"
printf 'CONTROL C04 %-3s cloud metadata service (IMDS)\n' "$c04"
printf 'CONTROL C05 %-3s Azure host service address\n' "$c05"
printf 'CONTROL C06 %-3s api.anthropic.com directly\n' "$c06"
printf 'CONTROL C07 %-3s git ls-remote to github.com\n' "$c07"
printf 'CONTROL C08 %-3s DNS to an outside resolver\n' "$c08"
echo "A control marked 'no' means its probe cannot prove enforcement: that probe is reported inconclusive and fails the job."
