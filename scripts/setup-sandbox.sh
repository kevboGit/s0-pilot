#!/usr/bin/env bash
# Builds the pilot sandbox on a fresh GitHub-hosted runner. Runs as root (sudo), before
# any untrusted code. Afterwards:
#   - user `agent` exists with no sudo rights, no extra groups, and its own home and tmp;
#   - the runner's own home is closed to it (its workspace, logs and temporary files);
#   - the only network path out for `agent` is a local squid proxy that allows the host
#     names given (default: api.anthropic.com only) on port 443; DNS, IPv6, metadata
#     addresses and everything else are refused;
#   - the proxy itself may only reach TCP 443 (plus the local DNS stub it needs).
# It never receives a credential. Dependencies a task needs are installed before this
# runs, so the agent never needs a package registry (the registry would also serve the
# fixed upstream code of the pilot's tasks).
# Usage: sudo bash setup-sandbox.sh [allowed-host ...]
set -euo pipefail

AGENT=agent
PROXY_PORT=3128
if [ "$#" -gt 0 ]; then ALLOW_HOSTS=("$@"); else ALLOW_HOSTS=(api.anthropic.com); fi

log() { printf 'setup: %s\n' "$*"; }

# 1. The unprivileged user.
useradd --create-home --shell /bin/bash --user-group "$AGENT"
install -d -o "$AGENT" -g "$AGENT" -m 700 "/home/$AGENT/ws" "/home/$AGENT/tmp"
install -d -o root -g root -m 755 /opt/s0
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
log "squid listening on 127.0.0.1:${PROXY_PORT}, allowing: ${ALLOW_HOSTS[*]}"

# 4. Packet filter, by user. The agent may reach only 127.0.0.1 (the proxy and local test
#    servers), never the DNS stub at 127.0.0.53; the proxy user only TCP 443 and loopback.
PROXY_USER=proxy
for cmd in iptables ip6tables; do
	$cmd -N S0_AGENT 2>/dev/null || $cmd -F S0_AGENT
	$cmd -N S0_PROXY 2>/dev/null || $cmd -F S0_PROXY
	$cmd -I OUTPUT 1 -m owner --uid-owner "$AGENT" -j S0_AGENT
	$cmd -I OUTPUT 2 -m owner --uid-owner "$PROXY_USER" -j S0_PROXY
done
iptables -A S0_AGENT -o lo -d 127.0.0.1/32 -j ACCEPT
iptables -A S0_AGENT -j REJECT
ip6tables -A S0_AGENT -j REJECT
iptables -A S0_PROXY -o lo -j ACCEPT
iptables -A S0_PROXY -p tcp --dport 443 -j ACCEPT
iptables -A S0_PROXY -j REJECT
ip6tables -A S0_PROXY -o lo -j ACCEPT
ip6tables -A S0_PROXY -p tcp --dport 443 -j ACCEPT
ip6tables -A S0_PROXY -j REJECT
log "packet filter installed for users $AGENT and $PROXY_USER"

# 5. Probe scripts, readable by the agent but not writable.
install -o root -g root -m 755 "$(dirname "$0")/probes.sh" /opt/s0/probes.sh
printf '%s\n' "${ALLOW_HOSTS[@]}" > /opt/s0/allowed-hosts
chmod 644 /opt/s0/allowed-hosts
log "done"
