"""PiRate Profile v1 contract and secret-safe editable configuration views.

Flat runtime-compatible fields are intentional: Direct and existing WG paths keep
using their existing store/backend. Schema version and private original source
are additions, not an alternative runtime or a second profile database.
"""
import re
from typing import TypedDict
from gate_core.core import ProfileError

VERSION=1
PRIVATE={'password','config','wg_private_key','wg_preshared_key','ovpn_source','import_source'}
MARKER='[PiRate secret retained]'

class PiRateProfileV1(TypedDict, total=False):
    profile_version: int
    name: str
    type: str
    server: str
    port: int
    config: str
    import_source: str  # exact original upload, base64; private, never returned
    import_encoding: str
    username: str
    password: str
    ovpn_remote: int
    ovpn_proto: str
    ovpn_server_name: str
    dns_servers: list[str]
    wg_private_key: str
    wg_peer_key: str
    wg_preshared_key: str
    wg_address: list[str]
    wg_allowed_ips: list[str]
    wg_mtu: int
    wg_keepalive: int


def editable_config(content):
    """Option text with opaque inline blocks; never stored key/auth material."""
    from .openvpn_import import inspect_config
    if not content:return ''
    parsed=inspect_config(content);lines=parsed['lines'];replacements={}
    for block in parsed['blocks']:
        # All inline material is private in API views, including certs.
        replacements[block['start']]=(block['end'],f"<{block['kind']}>\n{MARKER}\n</{block['kind']}>\n")
    for i,line in enumerate(lines):
        if line.lstrip().startswith(('#',';')):lines[i]='\n'
    for d in parsed['directives']:
        if d['key']=='auth-user-pass':lines[d['line']]='auth-user-pass\n'
    result=[];index=0
    while index<len(lines):
        if index in replacements:
            end,text=replacements[index];result.append(text);index=end+1
        else:result.append(lines[index]);index+=1
    return ''.join(result)


def merge_editable(content,private):
    """Restore each opaque block from THIS profile/draft, never another profile."""
    from .openvpn_import import inspect_config
    if MARKER not in content:return content
    previous=inspect_config(private);blocks={}
    for b in previous['blocks']:
        blocks.setdefault((b['kind'],b['context']),[]).append(b)
    parsed=inspect_config(content);lines=list(parsed['lines']);output=[];index=0
    for b in parsed['blocks']:
        if MARKER not in b['content']:continue
        if b['content'].strip()!=MARKER:raise ProfileError('Stored secret placeholder must occupy the entire inline block')
        matching=blocks.get((b['kind'],b['context']),[])
        if len(matching)!=1:raise ProfileError('Stored secret block is unavailable or ambiguous; re-upload the original config')
        original=matching[0];output.extend(lines[index:b['start']]);output.extend(previous['lines'][original['start']:original['end']+1]);index=b['end']+1
    output.extend(lines[index:]);result=''.join(output)
    if MARKER in result:raise ProfileError('Invalid stored-secret placeholder; re-upload the original config')
    return result


def imported_ca_identity(content,original):
    """Honor ONLY the original CA+server-role policy; never remove a name pin.

    No caller-controlled 'disable verification' option. Original CA bytes and
    server-role check must survive unchanged in the working config.
    """
    from .openvpn_import import inspect_config
    first=inspect_config(original);current=inspect_config(content)
    if any(d['key']=='verify-x509-name' for d in first['directives']+current['directives']):return False
    def identity(parsed):
        roles=[d for d in parsed['directives'] if d['key']=='remote-cert-tls']
        ca=[b for b in parsed['blocks'] if b['kind']=='ca']
        if len(roles)!=1 or roles[0]['context'] is not None or roles[0]['args']!=['server']:return None
        if len(ca)!=1 or ca[0]['context'] is not None or not ca[0]['content'].strip():return None
        return ca[0]['content']
    ca=identity(first)
    return ca is not None and ca==identity(current)


def profile_ca_identity(profile):
    from .openvpn_import import decode_upload
    if profile.get('ovpn_server_name'):return False
    source=profile.get('import_source') or profile.get('ovpn_source')
    if not source:return False
    original,_=decode_upload(source,profile.get('import_encoding') or profile.get('ovpn_encoding') or None)
    return imported_ca_identity(profile.get('config',''),original)
