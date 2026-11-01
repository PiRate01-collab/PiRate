"""Capability-aware validation and hostapd text preview; never reads secrets."""
from typing import Protocol
import re
from .models import validate_profile, stable_mac, valid_mac, WiFiError
from .radio import RadioCapabilities


class SecretReferences(Protocol):
    def status(self, reference: str) -> str: ...


class UnknownSecretReferences:
    def status(self, reference):
        return 'unknown'


class MockSecretReferences:
    def __init__(self, available=()):
        self.available = set(available)

    def status(self, reference):
        return 'available' if reference in self.available else 'missing'


def validate_configuration(payload, capabilities, secrets=None, *, identifier=None):
    data = validate_profile(payload)
    if not isinstance(capabilities, RadioCapabilities):
        raise TypeError('RadioCapabilities required')
    issues = []
    def issue(field, code, message, status='unsupported'):
        issues.append({'field': field, 'code': code, 'message': message, 'status': status})
    caps = capabilities
    if caps.ap_mode is not True:
        issue('radio', 'ap_mode', 'AP mode unsupported' if caps.ap_mode is False else 'AP support unknown',
              'unsupported' if caps.ap_mode is False else 'unknown')
    if not isinstance(caps.regulatory_domain, str) or not re.fullmatch(r'[A-Z]{2}', caps.regulatory_domain) or caps.regulatory_domain in ('XX', 'ZZ'):
        issue('radio', 'regulatory', 'Effective regulatory domain unknown; no channel approved', 'unknown')
    if data['mac_mode'] == 'hardware':
        try:
            valid_mac(caps.hardware_mac)
        except WiFiError:
            issue('mac_mode', 'hardware_identity', 'Hardware MAC not verified', 'unknown')
    if data['mac_mode'] != 'hardware' and caps.bssid_change is not True:
        issue('mac_mode', 'bssid_change', 'BSSID change unsupported' if caps.bssid_change is False else 'BSSID change support unknown',
              'unsupported' if caps.bssid_change is False else 'unknown')
    channel = next((x for x in caps.channels if x.band == data['band'] and x.number == data['channel']), None)
    if channel is None:
        issue('channel', 'channel', 'Channel unavailable or not observed', 'unknown' if not caps.channels else 'unsupported')
    elif channel.disabled or channel.no_ir:
        issue('channel', 'prohibited_channel', 'Channel prohibits AP initiation')
    elif channel.dfs:
        issue('channel', 'dfs', 'DFS/CAC management not implemented')
    elif data['width'] not in channel.widths:
        issue('width', 'width', 'Channel and width combination not verified', 'unknown')
    if data['band'] == '2.4' and data['width'] > 40:
        issue('width', 'band_width', '2.4 GHz supports only 20/40 MHz')
    if data['width'] == 320 and (data['band'] != '6' or 'eht' not in data['features']):
        issue('width', 'eht_width', '320 MHz requires 6 GHz EHT')
    if data['band'] == '6' and (data['security'] != 'wpa3' or 'he' not in data['features']):
        issue('security', 'six_ghz', '6 GHz requires WPA3 and HE')
    features = data['features']
    if any(x in features for x in ('ht', 'vht', 'he', 'eht')) and 'wmm' not in features:
        issue('features', 'wmm_required', 'HT/VHT/HE/EHT require WMM')
    if data['band'] == '6' and any(x in features for x in ('ht', 'vht', 'short_gi')):
        issue('features', 'legacy_six_ghz', 'Legacy HT/VHT/Short GI modes unavailable in 6 GHz')
    if 'vht' in features and (data['band'] != '5' or 'ht' not in features):
        issue('features', 'vht', 'VHT requires 5 GHz and HT')
    if 'eht' in features and 'he' not in features:
        issue('features', 'eht', 'EHT requires HE')
    if data['width'] == 40 and data['band'] != '6' and 'ht' not in features:
        issue('width', 'ht_width', '40 MHz requires HT')
    if data['width'] in (80, 160) and not any(x in features for x in ('vht', 'he', 'eht')):
        issue('width', 'wide_mode', 'Wide channels require VHT/HE/EHT')
    if 'short_gi' in features and 'ht' not in features:
        issue('features', 'short_gi', 'Short GI requires HT')
    for feature in features:
        if feature not in ('isolate_clients',) and feature not in caps.features:
            issue('features', 'feature_' + feature, 'Requested radio feature not verified: ' + feature, 'unknown' if not caps.features else 'unsupported')
    if data['security'] not in caps.security:
        issue('security', 'security', 'Adapter and hostapd security compatibility not verified', 'unknown' if not caps.security else 'unsupported')
    reference = data['password_ref']
    if reference is None:
        issue('password_ref', 'secret_missing', 'Wi-Fi secret reference required')
    else:
        try:
            secret_status = (secrets or UnknownSecretReferences()).status(reference)
        except Exception:
            secret_status = 'unknown'
        if secret_status != 'available':
            issue('password_ref', 'secret_' + ('missing' if secret_status == 'missing' else 'unknown'),
                  'Secret availability or security suitability not verified',
                  'unsupported' if secret_status == 'missing' else 'unknown')
    mac = caps.hardware_mac if data['mac_mode'] == 'hardware' else data['custom_mac'] if data['mac_mode'] == 'custom' else stable_mac(identifier) if identifier else None
    if data['mac_mode'] == 'stable-local' and identifier is None:
        issue('mac_mode', 'identity', 'Save profile to allocate stable identity', 'unknown')
    status = 'unsupported' if any(x['status'] == 'unsupported' for x in issues) else 'unknown' if issues else 'compatible'
    return {'status': status, 'valid': not issues, 'issues': issues, 'effective_mac': mac,
            'preview_only': True, 'apply_available': False}


def preview_configuration(payload, capabilities, secrets=None, *, identifier=None):
    data = validate_profile(payload)
    report = validate_configuration(data, capabilities, secrets, identifier=identifier)
    if report['status'] == 'unsupported':
        return {**report, 'configuration': None}
    # A template only, always incomplete: no actual password, interface or application path.
    lines = ['# PiRate Preview Only — NOT an executable configuration',
             '# Interface, credentials and radio-specific details require Safe Apply validation',
             'interface=<AP_INTERFACE>', 'driver=nl80211', 'ssid2=' + data['ssid'].encode('utf-8').hex(),
             'ignore_broadcast_ssid=' + ('1' if data['announcement'] == 'hidden' else '0'),
             'hw_mode=' + ('g' if data['band'] == '2.4' else 'a'), 'channel=' + str(data['channel']),
             '# band=' + data['band'] + '; width=' + str(data['width']) + ' MHz',
             '# Secondary/center frequency and operating class require hardware-specific generation',
             'beacon_int=' + str(data['beacon_interval']), 'dtim_period=' + str(data['dtim']),
             'wmm_enabled=' + ('1' if 'wmm' in data['features'] else '0'),
             'ap_isolate=' + ('1' if 'isolate_clients' in data['features'] else '0'), 'wpa=2', 'rsn_pairwise=CCMP',
             'wpa_key_mgmt=' + ('SAE' if data['security'] == 'wpa3' else 'WPA-PSK'),
             'ieee80211w=' + ('2' if data['security'] == 'wpa3' else '1'),
             '# Credentials must be resolved privately by Safe Apply; omitted here']
    for feature, directive in (('ht', 'ieee80211n'), ('vht', 'ieee80211ac'), ('he', 'ieee80211ax'), ('eht', 'ieee80211be')):
        lines.append(directive + '=' + ('1' if feature in data['features'] else '0'))
    if data['mac_mode'] != 'hardware' and report['effective_mac'] and capabilities.bssid_change is True:
        lines.append('bssid=' + report['effective_mac'])
    else:
        lines.append('# BSSID remains unverified or uses hardware identity')
    return {**report, 'configuration': '\n'.join(lines) + '\n'}
