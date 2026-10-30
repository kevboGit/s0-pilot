#!/usr/bin/env bash
# Builds the pilot sandbox on a fresh GitHub-hosted runner. Runs as root (sudo), before
# any untrusted code. Afterwards:
#   - user `agent` exists with no sudo rights, no extra groups, and its own home and tmp;
#   - the runner's own home is closed to it (its workspace, logs and temporary files);
#   - no directory a privileged (root/sudo) command searches for a binary is writable by
#     the agent, so it cannot plant a binary that a later root command would execute;
#   - the only network path out for `agent` is a local squid proxy that allows the host
#     names given (default: api.anthropic.com) on port 443; DNS, IPv6, metadata addresses
#     and everything else are refused; the proxy itself may only reach TCP 443;
#   - a root-owned IPv6 loopback listener and a root metadata control exist so the IPv6
#     and metadata probes can prove enforcement rather than infer it from absence.
# It changes permissions only on an explicit list of PATH directories, never recursively
# across the filesystem, and logs every change. It never receives a credential.
# Usage: sudo bash setup-sandbox.sh [allowed-host ...]
set -euo pipefail

AGENT=agent
PROXY_PORT=3128
OPT=/opt/s0
# Every directory a root/sudo command searches for an executable, including /snap/bin
# (on ubuntu-24.04's default sudo secure_path). Privileged steps use absolute paths, so
# this is defence in depth rather than the only barrier.
PRIV_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
# The exact binaries the privileged (root/sudo) steps invoke by absolute path. Hardened as
# files and probed, because dir `go-w` stops new entries but not in-place overwrite of a
# file that is itself writable.
TRUSTED_BINS="/usr/bin/bash /usr/sbin/runuser /usr/bin/env /usr/bin/cat /usr/bin/install"
if [ "$#" -gt 0 ]; then ALLOW_HOSTS=("$@"); else ALLOW_HOSTS=(api.anthropic.com); fi
HERE=$(dirname "$0")

log() { printf 'setup: %s\n' "$*"; }

# 1. The unprivileged user.
useradd --create-home --shell /bin/bash --user-group "$AGENT"
install -d -o "$AGENT" -g "$AGENT" -m 700 "/home/$AGENT/ws" "/home/$AGENT/tmp"
install -d -o root -g root -m 755 "$OPT"
log "user $AGENT: $(id "$AGENT")"

# 2. Close the runner's home (workspace, _temp, runner logs) to other users.
chmod 700 /home/runner
log "/home/runner is now $(stat -c '%a %U' /home/runner)"

# 3. The egress proxy.
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y squid >/dev/null
{
	echo "http_port 127.0.0.1:${PROXY_PORT}"
	echo "acl localhost_src src 127.0.0.1/32"
	echo "acl ssl_port port 443"
	echo "acl CONNECT method CONNECT"
	printf 'acl allowed_hosts dstdomain'
	printf ' %s' "${ALLOW_HOSTS[@]}"
	echo
	echo "http_access deny !localhost_src"
	echo "http_access deny CONNECT !ssl_port"
	echo "http_access allow CONNECT allowed_hosts"
	echo "http_access deny all"
	echo "cache deny all"
	echo "via off"
	echo "forwarded_for delete"
	echo "access_log stdio:/var/log/squid/access.log"
} >/etc/squid/squid.conf
chmod 644 /etc/squid/squid.conf
systemctl restart squid
log "squid on 127.0.0.1:${PROXY_PORT}, allowing: ${ALLOW_HOSTS[*]}"

# 4. Close every directory a privileged command would search for an executable OR a shared
#    library to non-root writers (done after the squid install so its binaries are placed).
#    This covers the exec PATH and the dynamic-linker search path (ld.so.conf*), because a
#    writable library directory on that path lets the agent plant a library a root process
#    would load. Idempotent on a normal system; it repairs a runner image that ships one
#    writable. Resolves symlinks. Never recursive: only these directories are touched.
harden_dirs() { # <label> <dir...>
	local label=$1 d real before after changed=0
	shift
	for d in "$@"; do
		real=$(readlink -f "$d" 2>/dev/null) || continue
		[ -d "$real" ] || continue
		before=$(stat -c '%a %U:%G' "$real")
		chown root:root "$real"
		chmod go-w "$real"
		after=$(stat -c '%a %U:%G' "$real")
		[ "$before" = "$after" ] || {
			log "$label hardened $d ($real): $before -> $after"
			changed=$((changed + 1))
		}
	done
	log "$label directories checked ($changed changed)"
}
# The dynamic-linker search path: the defaults plus every directory ld.so.conf references,
# following one level of `include <glob>` directives so a dir pulled in by an include is
# not missed.
lib_search_dirs() {
	local f g
	{
		echo /lib /lib64 /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
		for f in /etc/ld.so.conf /etc/ld.so.conf.d/*.conf; do
			[ -r "$f" ] || continue
			grep -E '^[[:space:]]*/' "$f"
			while read -r _ g; do
				# shellcheck disable=SC2086
				[ -n "$g" ] && cat $g 2>/dev/null
			done < <(grep -E '^[[:space:]]*include[[:space:]]' "$f")
		done
	} | grep -E '^[[:space:]]*/' | awk '{print $1}' | sort -u
}
LIB_DIRS=$(lib_search_dirs)
# shellcheck disable=SC2086
harden_dirs exec-path ${PRIV_PATH//:/ }
# shellcheck disable=SC2086
harden_dirs lib-path $LIB_DIRS

# Each trusted binary must be a root-owned regular file no other user can overwrite. An
# anomaly (missing, not root-owned) stops the job before any untrusted code runs.
harden_bins() {
	local b
	for b in $TRUSTED_BINS; do
		[ -f "$b" ] || {
			echo "trusted binary missing: $b" >&2
			exit 1
		}
		[ "$(stat -c %U "$b")" = root ] || {
			echo "trusted binary not root-owned: $b" >&2
			exit 1
		}
		chmod go-w "$b"
	done
	printf '%s\n' "$TRUSTED_BINS" >"$OPT/trusted-bins"
	log "trusted privileged binaries hardened: $(echo "$TRUSTED_BINS" | wc -w)"
}
harden_bins
printf '%s\n' "$PRIV_PATH" >"$OPT/priv-path"
printf '%s\n' "$LIB_DIRS" >"$OPT/priv-lib-path"

# 5. Packet filter, by user. The agent may reach only 127.0.0.1 (the proxy and local test
#    servers), never the DNS stub at 127.0.0.53; all IPv6 is administratively prohibited.
#    The proxy user may reach only TCP 443 and loopback.
PROXY_USER=proxy
for cmd in iptables ip6tables; do
	$cmd -N S0_AGENT 2>/dev/null || $cmd -F S0_AGENT
	$cmd -N S0_PROXY 2>/dev/null || $cmd -F S0_PROXY
	$cmd -I OUTPUT 1 -m owner --uid-owner "$AGENT" -j S0_AGENT
	$cmd -I OUTPUT 2 -m owner --uid-owner "$PROXY_USER" -j S0_PROXY
done
iptables -A S0_AGENT -o lo -d 127.0.0.1/32 -j ACCEPT
iptables -A S0_AGENT -j REJECT --reject-with icmp-admin-prohibited
ip6tables -A S0_AGENT -j REJECT --reject-with icmp6-adm-prohibited
iptables -A S0_PROXY -o lo -j ACCEPT
iptables -A S0_PROXY -p tcp --dport 443 -j ACCEPT
iptables -A S0_PROXY -j REJECT
ip6tables -A S0_PROXY -o lo -j ACCEPT
ip6tables -A S0_PROXY -p tcp --dport 443 -j ACCEPT
ip6tables -A S0_PROXY -j REJECT
log "packet filter installed for users $AGENT and $PROXY_USER"

# 6. A root-owned IPv6 loopback listener and its control, so the IPv6 probe is conclusive.
install -o root -g root -m 755 "$HERE/ipv6-listener.py" "$OPT/ipv6-listener.py"
setsid /usr/bin/python3 "$OPT/ipv6-listener.py" "$OPT/ipv6-port" "$OPT/ipv6-hb" >"$OPT/ipv6.log" 2>&1 &
disown || true
for _ in $(seq 1 25); do
	[ -s "$OPT/ipv6-port" ] && break
	sleep 0.2
done
IPV6_PORT=$(cat "$OPT/ipv6-port" 2>/dev/null || true)
if [ -n "$IPV6_PORT" ] && curl -sS -m 5 -o /dev/null "http://[::1]:$IPV6_PORT/"; then
	echo ok >"$OPT/ipv6-ctl"
	log "IPv6 loopback control: root reached [::1]:$IPV6_PORT"
else
	echo fail >"$OPT/ipv6-ctl"
	log "IPv6 loopback control FAILED; the IPv6 probe will be inconclusive (and fail closed)"
fi

# 7. Probe scripts and the data they read, readable by the agent but not writable. The
#    corroboration script is root-run after the agent phase; keeping it under root-owned
#    /opt/s0 puts it out of the agent's reach.
install -o root -g root -m 755 "$HERE/probes.sh" "$OPT/probes.sh"
install -o root -g root -m 755 "$HERE/corroborate-proxy.sh" "$OPT/corroborate-proxy.sh"
printf '%s\n' "${ALLOW_HOSTS[@]}" >"$OPT/allowed-hosts"
chmod 644 "$OPT/priv-path" "$OPT/priv-lib-path" "$OPT/trusted-bins" "$OPT/allowed-hosts" "$OPT/ipv6-port" "$OPT/ipv6-hb" "$OPT/ipv6-ctl" 2>/dev/null || true
log "done"
