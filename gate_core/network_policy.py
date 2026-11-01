"""Declarative fail-closed policy only; no real traffic is protected here."""
from dataclasses import dataclass
import ipaddress
import re


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class NetworkPolicy:
    endpoint: str
    port: int
    protocol: str
    transport_interface: str
    before_connect: tuple = ('vpn_endpoint',)
    after_connect: tuple = ('tunnel_ipv4', 'tunnel_dns')
    dns_mode: str = 'tunnel'
    ipv4: bool = True
    ipv6: bool = False
    fail_closed: bool = True
    on_disconnect: str = 'block_payload'

    def validate(self):
        try:
            address = ipaddress.ip_address(self.endpoint)
        except (ValueError, TypeError):
            raise PolicyError('Endpoint must be a literal IPv4 address') from None
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
            raise PolicyError('Unsupported endpoint address')
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise PolicyError('Invalid endpoint port')
        if self.protocol not in ('udp', 'tcp-client'):
            raise PolicyError('Unsupported transport protocol')
        if not isinstance(self.transport_interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', self.transport_interface):
            raise PolicyError('Invalid transport interface')
        if self.transport_interface == 'lo':
            raise PolicyError('Loopback transport unsupported')
        if self.before_connect != ('vpn_endpoint',) or self.after_connect != ('tunnel_ipv4', 'tunnel_dns'):
            raise PolicyError('Traffic must remain tunnel-only')
        if self.dns_mode != 'tunnel' or self.ipv4 is not True or self.ipv6 is not False:
            raise PolicyError('Only IPv4 with tunnel DNS and blocked IPv6 is supported')
        if self.fail_closed is not True or self.on_disconnect != 'block_payload':
            raise PolicyError('Fail-closed disconnect policy required')
        return self

    def traffic_for(self, state):
        """Model decision, not a firewall implementation."""
        from .plans import ConnectionState
        self.validate()
        state = ConnectionState(state)
        if state == ConnectionState.CONNECTED:
            return self.before_connect + self.after_connect
        if state in (ConnectionState.PREPARING, ConnectionState.CONNECTING):
            return self.before_connect
        return ()  # Stopped, failed, recovery and tunnel-loss states block everything.
