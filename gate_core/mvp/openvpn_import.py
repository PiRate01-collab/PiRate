"""Bounded OpenVPN upload inspection. Never executes options or reads references."""
import base64
import binascii
import codecs
import ipaddress
import re
from gate_core.core import ProfileError
from .openvpn_compat import compile_options,legacy_cipher_proposal

MAX_UPLOAD=256*1024
MAX_CONFIG=512*1024
MAX_JSON=4*1024*1024
ENCODINGS={'utf-8','utf-16','windows-1251','windows-1252'}


def check_text(content):
    if not isinstance(content,str):raise ProfileError('OpenVPN configuration must be text')
    try:size=len(content.encode('utf-8'))
    except UnicodeError:raise ProfileError('OpenVPN contains invalid Unicode') from None
    if not content.strip():raise ProfileError('OpenVPN configuration is empty')
    if size>MAX_CONFIG:raise ProfileError('OpenVPN UTF-8 configuration exceeds 512 KiB')
    if any(ord(c)<32 and c not in '\r\n\t' or 127<=ord(c)<=159 for c in content):
        raise ProfileError('OpenVPN contains binary/control characters; check the selected encoding')
    lines=content.splitlines(keepends=True)
    if len(lines)>8192:raise ProfileError('OpenVPN exceeds 8192 lines')
    if any(len(line)>16384 for line in lines):raise ProfileError('OpenVPN line exceeds 16384 characters')
    return lines


def decode_upload(encoded,encoding=None):
    if not isinstance(encoded,str) or len(encoded)>4*((MAX_UPLOAD+2)//3):
        raise ProfileError('OpenVPN upload exceeds 256 KiB')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,binascii.Error):raise ProfileError('OpenVPN upload must be valid base64') from None
    if len(raw)>MAX_UPLOAD:raise ProfileError('OpenVPN upload exceeds 256 KiB')
    if encoding is not None and (not isinstance(encoding,str) or encoding not in ENCODINGS):raise ProfileError('Unsupported OpenVPN encoding; choose UTF-8, UTF-16 BOM, Windows-1251 or Windows-1252')
    if raw.startswith((codecs.BOM_UTF32_LE,codecs.BOM_UTF32_BE)):raise ProfileError('UTF-32 is unsupported; export as UTF-8')
    detected='utf-16' if raw.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)) else 'utf-8'
    selected=encoding or detected
    if selected=='utf-16' and not raw.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)):
        raise ProfileError('UTF-16 requires a BOM; export as UTF-8 or UTF-16 with BOM')
    codec={'windows-1251':'cp1251','windows-1252':'cp1252','utf-8':'utf-8-sig'}.get(selected,selected)
    try:content=raw.decode(codec,errors='strict')
    except UnicodeError:raise ProfileError('Cannot decode OpenVPN file as '+selected+'; select its known encoding or export as UTF-8. No bytes were replaced.') from None
    check_text(content)
    return content,selected


def inspect_config(content,filename='OpenVPN.ovpn'):
    check_text(content)
    from gate_core.openvpn_syntax import parse_document, OpenVPNSyntaxError
    try:document=parse_document(content)
    except OpenVPNSyntaxError as exc:
        error=ProfileError(str(exc));error.category=exc.category;error.line=exc.line
        raise error from None
    lines=document['lines'];directives=document['directives'];blocks=document['blocks'];connections=document['connections']
    def option(key,group,default):
        found=[d for d in directives if d['key']==key and d['context']==group]
        if len(found)>1:raise ProfileError(f"OpenVPN line {found[-1]['line']+1}: duplicate {key} option")
        if found:
            if len(found[0]['args'])!=1:raise ProfileError(f"OpenVPN line {found[0]['line']+1}: invalid {key} option")
            return found[0]['args'][0]
        return default
    global_proto=option('proto',None,'udp');global_port=option('rport',None,option('port',None,'1194'))
    remotes=[]
    for d in directives:
        if d['key']!='remote':continue
        args=d['args'];group=d['context']
        if not 1<=len(args)<=3:raise ProfileError(f"OpenVPN line {d['line']+1}: remote requires server [port] [proto]")
        server=args[0];port=args[1] if len(args)>1 else option('rport',group,option('port',group,global_port)) if group is not None else global_port
        proto=args[2] if len(args)>2 else option('proto',group,global_proto) if group is not None else global_proto
        if not server or len(server)>253 or not re.fullmatch(r'[A-Za-z0-9_.:\-]+',server):raise ProfileError(f"OpenVPN line {d['line']+1}: invalid remote server")
        if not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535:raise ProfileError(f"OpenVPN line {d['line']+1}: remote port must be 1–65535")
        if proto not in ('udp','udp4','udp6','tcp','tcp-client','tcp4-client','tcp6-client'):raise ProfileError(f"OpenVPN line {d['line']+1}: invalid remote transport")
        remotes.append({'server':server,'port':int(port),'proto':proto,'line':d['line'],'context':group})
    if not remotes:raise ProfileError('OpenVPN: no remote SERVER [PORT] [PROTO] found')
    if len(remotes)>64:raise ProfileError('OpenVPN exceeds 64 remotes')
    dns=[];dns_by_context={};warnings=[]
    for d in directives:
        if d['key']=='dhcp-option' and d['args'][:1]==['DNS']:
            try:address=str(ipaddress.ip_address(d['args'][1])) if len(d['args'])==2 else None
            except ValueError:raise ProfileError(f"OpenVPN line {d['line']+1}: invalid DNS address") from None
            if address is None:raise ProfileError('OpenVPN invalid DNS option')
            if address not in dns:dns.append(address)
            dns_by_context.setdefault(d['context'],[])
            if address not in dns_by_context[d['context']]:dns_by_context[d['context']].append(address)
    if len(dns)>10:raise ProfileError('OpenVPN exceeds 10 DNS servers')
    for remote in remotes:
        remote['dns_servers']=list(dict.fromkeys(dns_by_context.get(None,[])+(dns_by_context.get(remote['context'],[]) if remote['context'] is not None else [])))
    dns=remotes[0]['dns_servers']
    auth=[d for d in directives if d['key']=='auth-user-pass'];inline=[b for b in blocks if b['kind']=='auth-user-pass']
    username=password=''
    scoped_auth=any(d['context'] is not None for d in auth) or any(b['context'] is not None for b in inline)
    if scoped_auth:
        warnings.append('Connection-scoped credentials retained but not auto-populated; runtime requires explicit global auth-user-pass.')
    all_auth=bool(auth or inline)
    auth=[d for d in auth if d['context'] is None];inline=[b for b in inline if b['context'] is None]
    if inline:
        if len(inline)!=1 or auth:raise ProfileError('OpenVPN duplicate auth-user-pass settings')
        credentials=inline[0]['content'].splitlines()
        if not 1<=len(credentials)<=2:raise ProfileError('OpenVPN inline auth-user-pass requires username and optional password on separate lines')
        username=credentials[0];password=credentials[1] if len(credentials)==2 else ''
    if auth and (len(auth)!=1 or len(auth[0]['args'])>1):raise ProfileError('OpenVPN invalid auth-user-pass option')
    if auth and auth[0]['args']:warnings.append('auth-user-pass references a file. Original reference is preserved but never opened; supply username/password explicitly in the dedicated fields.')
    if (auth or inline) and not password:warnings.append('Password is not supplied. Enter it explicitly; no credentials are guessed.')
    name=re.split(r'[/\\]',filename if isinstance(filename,str) else '')[-1]
    name=re.sub(r'\.ovpn$','',name,flags=re.I);name=''.join(c for c in name if c.isprintable()).strip()[:80] or 'OpenVPN'
    return {'name':name,'remotes':remotes,'dns_servers':dns,'username':username,'password':password,
            'auth_required':all_auth,'scoped_auth':scoped_auth,'inline_blocks':[{'kind':b['kind'],'bytes':len(b['content'].encode())} for b in blocks],
            'warnings':warnings,'directives':directives,'blocks':blocks,'connections':connections,'lines':lines}


def select_remote(content,index,protocol=''):
    """Compile explicit remote selection; retain every applicable security option."""
    parsed=inspect_config(content)
    if type(index) is not int or not 0<=index<len(parsed['remotes']):raise ProfileError('OpenVPN selected remote is missing')
    if parsed['scoped_auth']:raise ProfileError('Connection-scoped credentials are unsupported; original settings retained, no credentials guessed')
    selected=parsed['remotes'][index];context=selected['context'];skip=set()
    for block in parsed['connections']:
        if context is not None and block is parsed['connections'][context]:skip.update((block['start'],block['end']))
        else:skip.update(range(block['start'],block['end']+1))
    for d in parsed['directives']:
        if d['key'] in ('remote','proto','port','rport'):skip.add(d['line'])
    inline_auth=False
    for block in parsed['blocks']:
        if block['kind']=='auth-user-pass' and block['context'] in (None,context):
            skip.update(range(block['start'],block['end']+1));inline_auth=True
    result=''.join(line if i not in skip else '\n' for i,line in enumerate(parsed['lines']))
    transport=protocol or selected['proto']
    if transport not in ('udp','udp4','tcp','tcp-client','tcp4-client'):raise ProfileError('OpenVPN runtime supports only IPv4 UDP/TCP client transport')
    # Inline credentials remain in private original config; runtime uses the
    # explicit profile fields and a private auth file, never a guessed password.
    return result+('\nauth-user-pass\n' if inline_auth else '\n')+f"proto {transport}\nremote {selected['server']} {selected['port']} {transport}\n"


def diagnostic(line,directive,classification,message):
    return {'line':line,'directive':directive,'classification':classification,'message':message}


def analyze_openvpn(content,filename,automatic=False,*,legacy=False):
    """Pure profile preparation; legacy mode retains source and preview policy.

    No persistence, endpoint resolution, subprocesses or connection actions.
    """
    parsed=inspect_config(content,filename);first=parsed['remotes'][0];diagnostics=[];confirmation=False
    profile={'name':parsed['name'],'type':'openvpn','server':first['server'],'port':first['port'],
             'ovpn_remote':0,'ovpn_proto':first['proto'],'username':parsed['username'],'password':parsed['password'],
             'dns_servers':parsed['dns_servers'],'config':content}
    incompatible=False;working=content;compatibility=[];proposed=None
    try:normalized,changes=compile_options(working,automatic=automatic)
    except ProfileError as exc:
        compatibility=getattr(exc,'diagnostics',[]);proposed=getattr(exc,'proposed_config',None)
        normalized=getattr(exc,'proposed_config',None);errors=getattr(exc,'diagnostics',[])
        if normalized:
            try:
                normalized,changes=compile_options(normalized,automatic=automatic)
                changes+=getattr(exc,'compatibility_changes',[])
            except ProfileError:normalized=None
        if normalized:
            confirmation=True
            diagnostics.extend(diagnostic(e['line'],e['directive'],'requires_confirmation',e['message']) for e in errors)
        else:
            incompatible=True;changes=[]
            diagnostics.extend(dict(diagnostic(e['line'],e['directive'],'incompatible',e['message']),error_kind=e['error_kind']) for e in errors)
    if not compatibility:compatibility=changes
    if normalized and not legacy:profile['config']=normalized
    proposal=legacy_cipher_proposal(parsed) if not incompatible and not legacy else None
    if proposal:
        confirmation=True;profile['config']+=proposal[0];diagnostics.append(proposal[1])
    changed={c['line']:c for c in changes};seen={d['line'] for d in diagnostics}
    controlled={'remote','proto','port','rport','dhcp-option','redirect-gateway','pull','verb','mute','resolv-retry','explicit-exit-notify'}
    for d in parsed['directives']:
        line=d['line']+1
        if line in seen:continue
        c=changed.get(line)
        diagnostics.append(diagnostic(line,d['key'],'safely_normalized' if c and c.get('action')!='warning' or d['key'] in controlled else 'preserved',c['message'] if c else 'PiRate controls endpoint/routing/DNS; original retained.' if d['key'] in controlled else 'Preserved and checked by runtime policy.'))
    for b in parsed['blocks']:
        diagnostics.append(diagnostic(b['start']+1,b['kind'],'preserved','Inline material retained privately; never emitted in API responses.'))
    for b in parsed['blocks']:
        if b['kind']=='key' and ('ENCRYPTED PRIVATE KEY' in b['content'] or 'Proc-Type: 4,ENCRYPTED' in b['content']):
            incompatible=True;diagnostics.append(dict(diagnostic(b['start']+1,'key','incompatible','Encrypted client keys require an interactive passphrase, unsupported by this unattended runtime. Export a dedicated self-contained client key for private router storage.'),error_kind='unsupported_feature'))
    required=[]
    if parsed['auth_required']:
        required.extend(k for k in ('username','password') if not profile[k])
    from .profile_v1 import imported_ca_identity
    ca_policy=automatic and imported_ca_identity(profile['config'],content)
    if not legacy and not any(d['key']=='verify-x509-name' for d in parsed['directives']) and not ca_policy:required.append('ovpn_server_name')
    # Validate every offered endpoint, retaining all alternatives in the profile.
    # A missing exact name is an input field, not permission to disable identity.
    runtime_error=None;category='missing_credentials' if any(k in required for k in ('username','password')) else None
    if legacy or not incompatible:
        from .tunnels import normalize_openvpn
        from .proxy import ConnectionError
        for i,remote in enumerate(parsed['remotes'][:1] if legacy else parsed['remotes']):
            try:normalize_openvpn(profile['config'],'192.0.2.1',remote['port'],i,remote['proto'] if legacy else '','converter-validation-only' if 'ovpn_server_name' in required else '',ca_policy)
            except ConnectionError as exc:
                runtime_error=str(exc);category=getattr(exc,'category','local_security_policy')
                incompatible=True
                match=re.search(r'line (\d+)',str(exc),re.I)
                line=int(match[1]) if match else 1
                # Global validator failures still refer to the offending
                # ORIGINAL option, not an unrelated selected remote line.
                if not match:
                    causes=[('digest',{'auth'}),('DNS',{'dhcp-option'}),('Client TUN',{'dev','client'}),('certificate name',{'verify-x509-name'}),('certificate and key',{'cert','key'}),('server certificate role',{'remote-cert-tls','ca'}),('transport',{'proto','remote'})]
                    keys=next((keys for text,keys in causes if text in str(exc)),set())
                    candidates=[d['line']+1 for d in parsed['directives'] if d['key'] in keys]+[b['start']+1 for b in parsed['blocks'] if b['kind'] in keys]
                    if candidates:line=candidates[-1]
                diagnostics.append(dict(diagnostic(line,'runtime_policy','incompatible',str(exc)),error_kind=getattr(exc,'category','local_security_policy')))
    if automatic and not incompatible:
        confirmation=False
        for d in diagnostics:
            if d['classification']=='requires_confirmation':
                d['classification']='safely_normalized';d['message']='Applied automatically without lowering the imported TLS/authentication requirements. '+d['message'].replace('Confirm server compatibility.','Server compatibility is checked only on connect.')
        if ca_policy:diagnostics.append(diagnostic(1,'certificate_policy','preserved','Original inline CA and mandatory server-role authentication retained; no certificate name guessed or existing pin removed.'))
    return {'profile':profile,'diagnostics':sorted(diagnostics,key=lambda d:d['line']),
            'required_fields':required,'confirmation_required':confirmation,'incompatible':incompatible,
            'remotes':parsed['remotes'],'parsed':parsed,'compatibility':compatibility,
            'proposed_config':proposed,'runtime_error':runtime_error,'error_kind':category}


def preview_upload(data):
    if not isinstance(data,dict):raise ProfileError('OpenVPN preview requires a JSON object')
    if set(data)-{'file_base64','encoding','filename'} or 'file_base64' not in data:raise ProfileError('Expected file_base64, optional filename and encoding')
    if not isinstance(data.get('filename','OpenVPN.ovpn'),str) or len(data.get('filename',''))>1024:raise ProfileError('OpenVPN filename must be text up to 1024 characters')
    content,encoding=decode_upload(data['file_base64'],data.get('encoding'))
    result=analyze_openvpn(content,data.get('filename','OpenVPN.ovpn'),legacy=True)
    parsed=result['parsed'];profile=result['profile']
    profile.update(ovpn_encoding=encoding,ovpn_source=data['file_base64'])
    changes=result['compatibility'];proposed=result['proposed_config']
    runtime_error=result['runtime_error'];category=result['error_kind']
    parsed['warnings'].extend(f"Original line {c['line']} ({c['directive']}): {c['message']}" for c in changes)
    return {'error_kind':category,'runtime_error':runtime_error,'compatibility':changes,'proposed_config':proposed,'profile':profile,'remotes' :parsed['remotes'],'inline_blocks':parsed['inline_blocks'],
            'auth_required':parsed['auth_required'],'encoding':encoding,'warnings':parsed['warnings'],
            'notice':'Original bytes and full config retained privately. Explicit compatibility transformations are shown below and revalidated at save/start. Credentials must be supplied by the owner.'}
