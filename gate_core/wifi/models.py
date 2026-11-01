"""Strict non-secret Wi-Fi profile schema and deterministic local identity."""
import hashlib
import re
import unicodedata
import uuid


class WiFiError(ValueError):
    pass


FIELDS = {'name', 'ssid', 'announcement', 'mac_mode', 'custom_mac', 'band', 'channel',
          'width', 'security', 'beacon_interval', 'dtim', 'features', 'password_ref'}
FEATURES = ('wmm', 'ht', 'vht', 'he', 'eht', 'isolate_clients', 'short_gi')
DEFAULTS = {'announcement': 'broadcast', 'mac_mode': 'hardware', 'custom_mac': None,
            'band': '2.4', 'channel': 1, 'width': 20, 'security': 'wpa2',
            'beacon_interval': 100, 'dtim': 2, 'features': ['wmm'], 'password_ref': None}


def profile_id(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise WiFiError('Invalid Wi-Fi profile ID') from None
    return value


def valid_mac(value, *, local=False):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise WiFiError('Invalid MAC address format')
    raw = bytes.fromhex(value.replace(':', ''))
    if raw == bytes(6) or raw[0] & 1:
        raise WiFiError('MAC must be a nonzero unicast address')
    if local and not raw[0] & 2:
        raise WiFiError('Custom MAC must be locally administered')
    return value.lower()


def stable_mac(identifier):
    profile_id(identifier)
    raw = bytearray(hashlib.sha256(('pirate-wifi:' + identifier).encode()).digest()[:6])
    raw[0] = (raw[0] | 2) & 0xfe
    return ':'.join(f'{x:02x}' for x in raw)


def validate_profile(payload):
    if not isinstance(payload, dict) or set(payload) - FIELDS:
        raise WiFiError('Expected Wi-Fi metadata object with supported fields only')
    data = {**DEFAULTS, **payload}
    for key, max_len in (('name', 80), ('ssid', 32)):
        value = data.get(key)
        if not isinstance(value, str) or not value or any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp') for c in value):
            raise WiFiError('Name and SSID require nonempty text without control characters')
        if key == 'name':
            if not 1 <= len(value.strip()) <= max_len:
                raise WiFiError('Name must be 1–80 characters')
            data[key] = value.strip()
        elif len(value.encode('utf-8')) > max_len:
            raise WiFiError('SSID must be 1–32 UTF-8 bytes')
    for key, allowed in (('announcement', ('broadcast', 'hidden')), ('mac_mode', ('hardware', 'stable-local', 'custom')),
                         ('band', ('2.4', '5', '6')), ('security', ('wpa2', 'wpa3'))):
        if data[key] not in allowed:
            raise WiFiError('Unsupported Wi-Fi mode')
    if data['mac_mode'] == 'custom':
        data['custom_mac'] = valid_mac(data['custom_mac'], local=True)
    elif data['custom_mac'] is not None:
        raise WiFiError('Custom MAC only allowed in custom mode')
    for key, lower, upper in (('channel', 1, 233), ('width', 20, 320), ('beacon_interval', 15, 65535), ('dtim', 1, 255)):
        if type(data[key]) is not int or not lower <= data[key] <= upper:
            raise WiFiError('Invalid radio numeric parameter')
    if data['width'] not in (20, 40, 80, 160, 320):
        raise WiFiError('Unsupported channel width')
    features = data['features']
    if not isinstance(features, list) or any(not isinstance(x, str) or x not in FEATURES for x in features) or len(set(features)) != len(features):
        raise WiFiError('Unsupported or duplicate radio feature')
    data['features'] = sorted(features)
    reference = data['password_ref']
    if reference is not None and (not isinstance(reference, str) or not re.fullmatch(r'wifi:[a-z0-9_-]{1,64}', reference)):
        raise WiFiError('Password must be a Wi-Fi secret reference, not a value or path')
    return data


def saved_profile(payload, identifier):
    data = validate_profile(payload)
    data['id'] = profile_id(identifier)
    data['stable_mac'] = stable_mac(identifier) if data['mac_mode'] == 'stable-local' else None
    return data


def validate_saved(record):
    if not isinstance(record, dict) or set(record) != FIELDS | {'id', 'stable_mac'}:
        raise WiFiError('Invalid stored Wi-Fi profile schema')
    expected = saved_profile({k: record[k] for k in FIELDS}, record['id'])
    if record != expected:
        raise WiFiError('Invalid stored Wi-Fi profile identity')
    return expected
