"""Closed hostapd subset. Rendering only, with explicit synthetic credentials."""
from dataclasses import dataclass, field
import hashlib
import re
from ..models import validate_saved, FIELDS, valid_mac
from ..validation import validate_configuration, MockSecretReferences
from ..radio import RadioCapabilities
from .storage import FoundationError


@dataclass(frozen=True)
class RenderCapabilities:
    radio: RadioCapabilities
    hostapd_backend: bool | None = None
    bssid_override: bool | None = None
    pmf: bool | None = None
    # Explicit driver-reviewed (primary channel, secondary channel) combinations.
    ht40_pairs: tuple = ()
    vht80_centers: tuple = ()  # (primary, center); all four constituent channels checked.


@dataclass(frozen=True)
class PreparedConfiguration:
    interface: str
    profile_id: str
    text: str = field(repr=False)
    sha256: str
    mode: str = 'dry-run'

    def public(self):
        return {'interface':self.interface, 'profile_id':self.profile_id,
                'sha256':self.sha256, 'dry_run':True, 'real_execution_available':False}


def configuration_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def render_hostapd(profile, capabilities):
    """No external files/resolver: only synthetic key material in this substage.

    A future private credential renderer must be a separate trusted boundary.
    PreparedConfiguration.text is private, not an API response or log field.
    """
    profile = validate_saved(profile)
    if type(capabilities) is not RenderCapabilities or capabilities.hostapd_backend is not True:
        raise FoundationError('Hostapd backend compatibility unknown')
    radio = capabilities.radio
    if not isinstance(radio, RadioCapabilities) or not isinstance(radio.interface,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',radio.interface) or radio.interface == 'lo':
        raise FoundationError('Radio interface identity unknown')
    report = validate_configuration({k:profile[k] for k in FIELDS}, radio,
                                    MockSecretReferences([profile['password_ref']]), identifier=profile['id'])
    if report['status'] != 'compatible':
        raise FoundationError('Radio settings or credential reference unsupported or unknown')
    if profile['band'] not in ('2.4','5') or profile['width'] not in (20,40,80) or any(x not in ('wmm','ht','vht','isolate_clients') for x in profile['features']):
        raise FoundationError('Radio mode outside supported hostapd subset')
    primary=next(x for x in radio.channels if x.band==profile['band'] and x.number==profile['channel'])
    allowed_channel=1<=primary.number<=13 if profile['band']=='2.4' else primary.number in (36,40,44,48,149,153,157,161,165)
    expected_frequency=(2407 if profile['band']=='2.4' else 5000)+5*primary.number
    if not allowed_channel or primary.frequency!=expected_frequency:
        raise FoundationError('Channel frequency outside verified non-DFS subset')
    lines = ['interface='+radio.interface, 'driver=nl80211', 'ctrl_interface=/run/hostapd',
             'ssid2='+profile['ssid'].encode('utf-8').hex(),
             'ignore_broadcast_ssid='+('1' if profile['announcement']=='hidden' else '0'),
             'country_code='+radio.regulatory_domain, 'ieee80211d=1',
             'hw_mode='+('g' if profile['band']=='2.4' else 'a'), 'channel='+str(profile['channel']),
             'beacon_int='+str(profile['beacon_interval']), 'dtim_period='+str(profile['dtim']),
             'wmm_enabled='+('1' if 'wmm' in profile['features'] else '0'),
             'ap_isolate='+('1' if 'isolate_clients' in profile['features'] else '0'),
             'ieee80211n='+('1' if 'ht' in profile['features'] else '0'),
             'ieee80211ac='+('1' if 'vht' in profile['features'] else '0')]
    if profile['mac_mode'] != 'hardware':
        if capabilities.bssid_override is not True:
            raise FoundationError('Driver BSSID override not independently verified')
        lines.append('bssid='+valid_mac(report['effective_mac'],local=True))
    if profile['width'] in (40,80):
        secondary = next((s for p,s in capabilities.ht40_pairs if p==profile['channel']),None)
        channel = next((x for x in radio.channels if x.band==profile['band'] and x.number==secondary),None)
        if secondary is None or abs(secondary-profile['channel'])!=4 or channel is None or abs(channel.frequency-primary.frequency)!=20 or channel.disabled or channel.no_ir or channel.dfs:
            raise FoundationError('HT40 secondary channel not verified')
        lines.append('ht_capab=[HT40'+('+' if secondary>profile['channel'] else '-')+']')
    if 'vht' in profile['features']:
        if profile['width'] == 80:
            center = next((c for p,c in capabilities.vht80_centers if p==profile['channel']),None)
            if type(center) is not int or center not in (42,155) or profile['channel'] not in (center-6,center-2,center+2,center+6):
                raise FoundationError('VHT80 center channel not verified')
            expected_secondary=profile['channel']+4 if profile['channel'] in (center-6,center+2) else profile['channel']-4
            if secondary!=expected_secondary:
                raise FoundationError('HT40 pairing inconsistent with VHT80 primary block')
            for number in (center-6,center-2,center+2,center+6):
                channel=next((x for x in radio.channels if x.band=='5' and x.number==number),None)
                if channel is None or channel.frequency!=5000+5*number or channel.disabled or channel.no_ir or channel.dfs:
                    raise FoundationError('VHT80 occupied spectrum not verified')
        else:
            center = profile['channel'] if profile['width']==20 else (profile['channel']+secondary)//2
        lines += ['vht_oper_chwidth='+('1' if profile['width']==80 else '0'),
                  'vht_oper_centr_freq_seg0_idx='+str(center)]
    if profile['width']==80 and 'vht' not in profile['features']:
        raise FoundationError('80 MHz rendering requires verified VHT')
    lines += ['auth_algs=1','wpa=2','rsn_pairwise=CCMP']
    # Deterministic fake credential, deliberately unrelated to the password reference.
    synthetic = hashlib.sha256(b'PiRate dry-run synthetic credential; never deploy').hexdigest()
    if profile['security']=='wpa3':
        if capabilities.pmf is not True:
            raise FoundationError('WPA3 management-frame protection unknown')
        lines += ['wpa_key_mgmt=SAE','ieee80211w=2','sae_require_mfp=1','sae_password='+synthetic[:32]]
    else:
        lines += ['wpa_key_mgmt=WPA-PSK','ieee80211w=0','wpa_psk='+synthetic]
    text='\n'.join(lines)+'\n'
    return PreparedConfiguration(radio.interface,profile['id'],text,configuration_hash(text))
