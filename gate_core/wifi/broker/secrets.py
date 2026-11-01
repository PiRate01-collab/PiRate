"""Future root-only resolver boundary. This implementation never reads any file."""
from dataclasses import dataclass,field
from enum import Enum
import re
from typing import Protocol
from ..models import profile_id
from .contracts import BrokerError


class SecretPurpose(str,Enum):
    WIFI_PSK='wifi_psk'
    VPN_CREDENTIALS='vpn_credentials'
    PRIVATE_KEY='private_key'
    WIREGUARD_KEY='wireguard_key'
    PROXY_CREDENTIALS='proxy_credentials'


@dataclass(frozen=True)
class SecretContext:
    owner_uid: int
    profile_id: str
    scope: str
    purpose: SecretPurpose


@dataclass(frozen=True)
class SecretMaterial:
    purpose: SecretPurpose
    value: str = field(repr=False)


class SecretResolver(Protocol):
    def available(self, reference: str, context: SecretContext) -> bool: ...
    def resolve(self, reference: str, context: SecretContext) -> SecretMaterial: ...


def validate_context(reference,context):
    if type(context) is not SecretContext or type(context.owner_uid) is not int or context.owner_uid<0 or type(context.purpose) is not SecretPurpose:
        raise BrokerError('secret_denied')
    try:profile_id(context.profile_id)
    except ValueError:raise BrokerError('secret_denied') from None
    namespace,scope={SecretPurpose.WIFI_PSK:('wifi','ap-primary'),SecretPurpose.VPN_CREDENTIALS:('vpn','vpn-primary'),SecretPurpose.PRIVATE_KEY:('key','vpn-primary'),SecretPurpose.WIREGUARD_KEY:('wg','vpn-primary'),SecretPurpose.PROXY_CREDENTIALS:('proxy','proxy-primary')}[context.purpose]
    if not isinstance(reference,str) or not re.fullmatch(namespace+r':[a-z0-9_-]{1,64}',reference) or context.scope!=scope:
        raise BrokerError('secret_denied')


class SyntheticSecretResolver:
    def __init__(self):self._entries={}

    def register(self, reference, context):
        """Trusted fixture setup only. No supplied secret values accepted."""
        validate_context(reference,context)
        key=(reference,context)
        if key in self._entries:raise BrokerError('secret_denied')
        self._entries[key]=SecretMaterial(context.purpose,'SYNTHETIC_ONLY_'+context.purpose.value+'_NOT_FOR_DEPLOYMENT')

    def available(self, reference, context):
        validate_context(reference,context)
        return (reference,context) in self._entries

    def resolve(self, reference, context):
        if not self.available(reference,context):raise BrokerError('secret_denied')
        return self._entries[(reference,context)]
