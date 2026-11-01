"""Read-only proof boundary; injected iw/nl80211 data only, never execute tools."""
from dataclasses import dataclass
from typing import Protocol
from ..radio import RadioCapabilities

@dataclass(frozen=True)
class HardwareProof:
    capabilities: RadioCapabilities
    source: str = 'unknown'
    trusted: bool = False
    hardware_mac_change: bool | None = None
    bssid_change: bool | None = None

    def permits(self, profile):
        caps=self.capabilities
        # Wider channels need constituent-channel/driver proof, not one channel flag.
        if not isinstance(profile,dict) or profile.get('width')!=20:return False
        if not isinstance(caps,RadioCapabilities):return False
        if self.trusted is not True or self.source not in ('mock','iw','nl80211') or caps.ap_mode is not True or caps.regulatory_domain is None:
            return False
        if profile['mac_mode']!='hardware' and self.bssid_change is not True:return False
        if profile['security'] not in caps.security or any(x not in caps.features for x in profile['features']):return False
        return any(c.band==profile['band'] and c.number==profile['channel'] and profile['width'] in c.widths and all(flag is False for flag in (c.disabled,c.no_ir,c.dfs)) for c in caps.channels)

class HardwareProofProvider(Protocol):
    def snapshot(self) -> HardwareProof: ...

class MockHardwareProofProvider:
    def __init__(self, proof):
        if type(proof) is not HardwareProof:raise ValueError('Hardware proof required')
        self.proof=proof
    def snapshot(self):return self.proof

class ReadonlyHardwareProofProvider:
    """Caller supplies an inspected RadioCapabilities snapshot; no implicit iw call.

    Existing IwRadioProvider is optional future read-only acquisition. Its conservative
    capabilities leave security/BSSID/AP-specific widths unknown, so cannot permit Apply.
    nl80211 adapter should implement HardwareProofProvider with verified per-AP evidence.
    """
    def __init__(self, capabilities=None):self.capabilities=capabilities or RadioCapabilities()
    def snapshot(self):return HardwareProof(self.capabilities, self.capabilities.source, False)
