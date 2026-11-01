"""Read-only radio capabilities. Unknown never implies support."""
from dataclasses import dataclass, asdict
import re
import shutil
import subprocess
from .models import valid_mac, WiFiError


@dataclass(frozen=True)
class Channel:
    band: str
    number: int
    frequency: int
    widths: tuple = (20,)
    disabled: bool = False
    no_ir: bool = False
    dfs: bool = False


@dataclass(frozen=True)
class RadioCapabilities:
    interface: str | None = None
    hardware_mac: str | None = None
    ap_mode: bool | None = None
    bssid_change: bool | None = None
    regulatory_domain: str | None = None
    channels: tuple = ()
    features: tuple = ()
    security: tuple = ()
    limitations: tuple = ('Hardware compatibility unknown',)
    source: str = 'unknown'
    advertised_features: tuple = ()
    observed_mac: str | None = None

    def as_dict(self):
        result = asdict(self)
        result['compatibility'] = 'unknown' if self.ap_mode is None else 'supported' if self.ap_mode else 'unsupported'
        result['bssid_compatibility'] = 'unknown' if self.bssid_change is None else 'supported' if self.bssid_change else 'unsupported'
        return result


class UnknownRadioProvider:
    def snapshot(self):
        return RadioCapabilities()


class MockRadioProvider:
    def __init__(self, capabilities):
        if not isinstance(capabilities, RadioCapabilities):
            raise TypeError('RadioCapabilities required')
        self.capabilities = capabilities
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        return self.capabilities


def execute_readonly(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=3).stdout


class IwRadioProvider:
    """Optional explicit read-only iw integration; no writes or probing supported.

    Conservative parser: reports only 20 MHz channel combinations, AP mode and
    frequency flags. BSSID changes, hostapd security and AP-specific HT/VHT/HE/EHT
    support remain unknown until a stronger nl80211 provider is available.
    """
    def __init__(self, run=execute_readonly, which=shutil.which,interface=None):
        self.run, self.which = run, which
        self.interface=interface

    def snapshot(self):
        binary = self.which('iw')
        if not binary:
            return RadioCapabilities(limitations=('iw unavailable',))
        try:
            devices = self.run([binary, 'dev'])
            if self.interface:
                if not re.fullmatch('[a-zA-Z0-9_.-]{1,15}',self.interface):return RadioCapabilities()
                selected=self.run([binary,'dev',self.interface,'info'])
                number=re.search(r'wiphy (\d+)',selected)
                if not number:return RadioCapabilities()
                devices='phy#'+number[1]+'\n'+selected
            match = re.search(r'phy#(\d+)\s+Interface ([a-zA-Z0-9_.-]{1,15})\b', devices)
            if not match:
                return RadioCapabilities(limitations=('No identifiable Wi-Fi adapter',), source='iw')
            phy, interface = 'phy' + match[1], match[2]
            info = self.run([binary, 'phy', phy, 'info'])
            regulatory = self.run([binary, 'reg', 'get'])
            countries = set(re.findall(r'country ([A-Z0-9]{2}):', regulatory))
            country = next(iter(countries)) if len(countries) == 1 else None
            mac_match = re.search(r'\baddr ((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b', devices[match.start():])
            mac = valid_mac(mac_match[1]) if mac_match else None
            modes = re.search(r'Supported interface modes:\s*\n((?:\s*\*[^\n]+\n?)+)', info)
            ap = bool(re.search(r'^\s*\* AP\s*$', modes[1], re.M)) if modes else None
            channels = []
            for frequency, number, flags in re.findall(r'\*\s+(\d+(?:\.\d+)?)\s+MHz\s+\[(\d+)\]([^\n]*)', info):
                mhz = int(float(frequency))
                band = '2.4' if 2400 <= mhz < 2500 else '5' if 5000 <= mhz < 5925 else '6' if 5925 <= mhz <= 7125 else None
                if band:
                    lowered = flags.lower()
                    channels.append(Channel(band, int(number), mhz, (20,),
                                            'disabled' in lowered or 'no 20mhz' in lowered,
                                            'no ir' in lowered or 'passive scanning' in lowered,
                                            'radar' in lowered or 'dfs' in lowered))
            advertised = tuple(feature for feature, marker in (
                ('ht', r'\bHT Capabilities'), ('vht', r'\bVHT Capabilities'),
                ('he', r'\bHE (?:Iftypes|Capabilities)'), ('eht', r'\bEHT (?:Iftypes|Capabilities)'))
                if re.search(marker, info))
            return RadioCapabilities(interface=interface, hardware_mac=None, ap_mode=ap,
                                     bssid_change=None, regulatory_domain=country, channels=tuple(channels),
                                     limitations=('First detected adapter only; multi-radio selection unavailable',
                                                  'Only observed 20 MHz channels; wider widths and AP-specific features unknown',
                                                  'Observed interface MAC is not proof of permanent hardware identity',
                                                  'MAC changes and WPA2/WPA3 backend compatibility unknown',
                                                  'DFS/CAC orchestration and interface-combination verification unavailable'),
                                     source='iw', advertised_features=advertised, observed_mac=mac)
        except (OSError, subprocess.SubprocessError, WiFiError, ValueError, TypeError):
            return RadioCapabilities(limitations=('Read-only radio inspection unavailable',), source='iw')
