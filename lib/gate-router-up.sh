#!/usr/bin/env bash
set -euo pipefail
[ -r /etc/gate/gate.conf ] || { echo "missing /etc/gate/gate.conf" >&2; exit 1; }
# shellcheck disable=SC1091
source /etc/gate/gate.conf

case "${1:-up}" in
  up)
    ip link set "$AP_IFACE" up
    ip addr flush dev "$AP_IFACE"
    ip addr add "$AP_ADDR/$AP_PREFIX" dev "$AP_IFACE"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    iptables -t nat -C POSTROUTING -s "$AP_NET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "$AP_NET" -o "$WAN_IF" -j MASQUERADE
    iptables -C FORWARD -i "$AP_IFACE" -o "$WAN_IF" -s "$AP_NET" -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -i "$AP_IFACE" -o "$WAN_IF" -s "$AP_NET" -j ACCEPT
    iptables -C FORWARD -i "$WAN_IF" -o "$AP_IFACE" -d "$AP_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -i "$WAN_IF" -o "$AP_IFACE" -d "$AP_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ;;
  down)
    while iptables -t nat -D POSTROUTING -s "$AP_NET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -D FORWARD -i "$AP_IFACE" -o "$WAN_IF" -s "$AP_NET" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -i "$WAN_IF" -o "$AP_IFACE" -d "$AP_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
    ;;
  restart)
    "$0" down || true
    "$0" up
    ;;
  *) echo "usage: $0 {up|down|restart}" >&2; exit 2 ;;
esac
