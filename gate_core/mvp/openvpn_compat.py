"""Explicit Asus/OpenVPN compatibility policy; no hooks, file reads or guessing.

Original text stays private in the profile. Diagnostics contain names and original
line numbers only. Compilation is repeated at save AND runtime.
"""
import re
from gate_core.core import ProfileError

AEAD={'AES-128-GCM','AES-256-GCM','CHACHA20-POLY1305'}
CBC={'AES-128-CBC','AES-256-CBC'}
EXTRA={'cipher','data-ciphers-fallback','keepalive','mssfix','mute-replay-warnings',
       'key-direction','reneg-sec','script-security','tls-version-min','tls-cipher','pull-filter'}


def unsigned(value):
    """Bound decimal conversion without changing leading-zero semantics."""
    if not value.isascii() or not value.isdecimal():return None
    digits=value.lstrip('0') or '0'
    return int(digits) if len(digits)<=10 else 10**10  # exceeds every local bound


def validate_option(key,args):
    def integers(low,high,count=1):
        return len(args)==count and all(unsigned(a) is not None and low<=unsigned(a)<=high for a in args)
    if key in ('data-ciphers','cipher','data-ciphers-fallback'):
        return len(args)==1 and 1<=len(args[0].split(':'))<=16 and all(c in AEAD|CBC for c in args[0].split(':')) and (key=='data-ciphers' or ':' not in args[0])
    if key=='key-direction':return args in (['0'],['1'])
    if key=='keepalive':return integers(1,86400,2) and unsigned(args[1])>unsigned(args[0])
    if key=='mssfix':return bool(args) and (args==['0'] or integers(576,9000) or len(args)==2 and args[1]=='mtu' and validate_option(key,args[:1]))
    if key=='mute-replay-warnings':return not args
    if key=='reneg-sec':return integers(0,604800) or integers(0,604800,2) and unsigned(args[1])<=unsigned(args[0])
    if key=='script-security':return args==['1']
    if key=='tls-version-min':return len(args) in (1,2) and args[0] in ('1.2','1.3') and (len(args)==1 or args[1]=='or-highest')
    if key=='tls-cipher':
        # Literal strong TLS 1.2 suites only: no OpenSSL expressions, aliases,
        # security-level overrides, static RSA or anonymous authentication.
        return len(args)==1 and all(re.fullmatch(r'(?:(?:ECDHE-(?:RSA|ECDSA)|DHE-RSA)-AES(?:128|256)-GCM-SHA(?:256|384)|(?:ECDHE-(?:RSA|ECDSA)|DHE-RSA)-AES(?:128|256)-SHA(?:256|384))',c) for c in args[0].split(':'))
    if key=='pull-filter':return len(args)==2 and args[0] in ('ignore','reject') and bool(re.fullmatch(r'[A-Za-z0-9 _.:-]{1,200}',args[1]))
    return False


def canonical_tls_suite(value):
    match=re.fullmatch(r'TLS-(ECDHE-RSA|ECDHE-ECDSA|DHE-RSA)-WITH-AES-(128|256)-(GCM|CBC)-SHA(256|384)',value)
    return match[1]+'-AES'+match[2]+('-GCM' if match[3]=='GCM' else '')+'-SHA'+match[4] if match else value


def error_kind(key,args):
    """Local option rejection only; never evidence about a remote server."""
    if key=='tls-version-min' and (len(args) not in (1,2) or not re.fullmatch(r'[0-9]+\.[0-9]+',args[0]) or len(args)==2 and args[1]!='or-highest'):return 'invalid_syntax'
    if key=='script-security' and (len(args)!=1 or unsigned(args[0]) is None):return 'invalid_syntax'
    if key=='reneg-sec':
        numeric=len(args) in (1,2) and all(unsigned(a) is not None for a in args)
        return 'local_security_policy' if numeric and any(unsigned(a)>604800 for a in args) else 'invalid_syntax'
    if key in {'cipher','data-ciphers','data-ciphers-fallback','ncp-ciphers','auth','tls-version-min','tls-cipher','script-security','pull-filter','up','down','route-up','plugin','config','management','daemon','log','writepid','tls-verify','iproute','auth-user-pass-verify','setenv'}:return 'local_security_policy'
    if key in EXTRA or key in {'remote','proto','port','rport','float','auth-user-pass'}:return 'invalid_syntax'
    return 'unsupported_feature'


def legacy_cipher_proposal(parsed):
    cipher=[d for d in parsed['directives'] if d['key']=='cipher']
    lists=[d for d in parsed['directives'] if d['key'] in ('data-ciphers','ncp-ciphers') or d['key']=='setenv' and d['args'][:2]==['opt','data-ciphers']]
    if len(cipher)!=1 or lists:return None
    d=cipher[0];value=d['args'][0]
    return ('\ndata-ciphers '+value+'\ndata-ciphers-fallback '+value+'\n',
            {'line':d['line']+1,'directive':'cipher','classification':'requires_confirmation','message':'Legacy cipher alone is ignored by OpenVPN 2.5+. Explicit same-cipher negotiation/fallback proposed; no new cipher inferred. Confirm server compatibility.'})


def compile_options(content,automatic=False):
    from .openvpn_import import inspect_config
    parsed=inspect_config(content)
    automatic_changes=[];working=content
    if automatic:
        lines=list(parsed['lines'])
        for d in parsed['directives']:
            if d['key']=='push':
                # In a CLIENT export push cannot impose client-side TLS/auth.
                # Never unpack/execute its contents, including embedded hooks.
                lines[d['line']]='# PiRate: server-only push omitted\n'
                automatic_changes.append({'line':d['line']+1,'directive':'push','message':'Server-only push removed from client runtime; embedded contents are never executed.'})
            if d['key']=='tls-cipher' and len(d['args'])==1:
                keep=[]
                for value in d['args'][0].split(':'):
                    canonical=canonical_tls_suite(value)
                    if validate_option('tls-cipher',[canonical]):keep.append(canonical)
                if keep and ':'.join(keep)!=d['args'][0]:
                    lines[d['line']]='tls-cipher '+':'.join(keep)+'\n'
                    automatic_changes.append({'line':d['line']+1,'directive':'tls-cipher','message':'Equivalent strong suites retained; unsupported/weak alternatives removed without adding ciphers.'})
        working=''.join(lines)
    parsed=inspect_config(working);lines=list(parsed['lines']);changes=automatic_changes;errors=[];cipher_options=[];proposals={}
    def diagnostic(d,action,message):
        key=d['key'] if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]{0,80}',d['key']) else '(invalid)'
        return {'line':d['line']+1,'directive':key,'action':action,'message':message,**({'error_kind':error_kind(d['key'],d['args'])} if action=='error' else {})}
    def replace(d,text,message):
        lines[d['line']]=text+'\n';changes.append(diagnostic(d,'transform',message))
    for original in parsed['directives']:
        d=dict(original);key=d['key'];args=d['args']
        if parsed['lines'][d['line']].lstrip().startswith('--'):
            lines[d['line']]=parsed['lines'][d['line']].replace('--'+key,key,1)
            changes.append(diagnostic(d,'transform','Leading command-line option prefix normalized to configuration syntax.'))
        if key=='setenv':
            if len(args)==3 and args[:1]==['opt'] and args[1] in ('data-ciphers','data-ciphers-fallback'):
                key=args[1];args=args[2:];d.update(key=key,args=args)
                if validate_option(key,args):replace(original,key+' '+args[0],'Recognized optional cipher setting made explicit; same cipher value retained.')
                else:errors.append(diagnostic(original,'error','Unsupported cipher; export AES-GCM or explicit AES-CBC with SHA256/384/512.'))
            elif args==['opt','block-outside-dns']:
                replace(d,'# PiRate: Windows block-outside-dns omitted','Windows-only DNS control replaced by PiRate namespace DNS and kill-switch.')
                continue
            elif len(args)==2 and args[0]=='CLIENT_CERT' and args[1] in ('0','1'):
                replace(d,'# PiRate: CLIENT_CERT metadata omitted','Exporter metadata omitted; actual certificate/key and authentication remain required.')
                continue
            else:
                errors.append(diagnostic(d,'error','Only recognized exporter metadata and typed opt data-ciphers settings supported.'));continue
        elif key=='ncp-ciphers':
            key='data-ciphers';d.update(key=key)
            if validate_option(key,args):replace(original,key+' '+args[0],'Legacy ncp-ciphers renamed to data-ciphers without changing offered ciphers.')
        elif key=='float':
            if args:errors.append(diagnostic(d,'error','float takes no arguments.'))
            else:replace(d,'# PiRate: float omitted','Remote roaming disabled: runtime pins the selected endpoint and its firewall rule.')
            continue
        elif key=='auth-user-pass' and len(args)==1:
            replace(d,'auth-user-pass','External credential path is never opened; owner must supply username/password in dedicated private fields.');continue
        elif key=='push':
            # Only obsolete server-side routing/DNS exports may be omitted.
            value=' '.join(args)
            if re.fullmatch(r'(redirect-gateway(?: def1)?|route [0-9.]+ [0-9.]+|dhcp-option DNS [0-9.]+)',value):
                replace(d,'# PiRate: server-only push omitted','Server-side routing/DNS push has no client role; PiRate manages routing and DNS.')
            else:errors.append(diagnostic(d,'error','Server-only push unsupported; remove it from the client export after reviewing the server policy.'))
            continue
        elif key=='tls-cipher' and len(args)==1:
            suites=[]
            for value in args[0].split(':'):
                suites.append(canonical_tls_suite(value))
            if ':'.join(suites)!=args[0]:
                args=[':'.join(suites)];replace(d,'tls-cipher '+args[0],'IANA strong TLS suite names mapped to equivalent OpenSSL names; cipher strength unchanged.')
        elif key=='script-security' and args in (['2'],['3']):
            replace(d,'script-security 1','Reduced to built-in network tools only; custom hooks/plugins remain prohibited.');args=['1']
        if key in EXTRA|{'data-ciphers'}:
            if not validate_option(key,args):
                suggestions={'tls-version-min':'Use TLS 1.2 or 1.3; older minimums require explicit owner/server migration.',
                             'reneg-sec':'Expected non-negative seconds: max [min], with min <= max. Zero disables the client timer. PiRate policy supports at most 604800 seconds per value.',
                             'script-security':'Only level 1 (built-in tools) is supported.',
                             'pull-filter':'Only bounded ignore/reject filters are supported; accept filters could override route protections.',
                             'tls-cipher':'Use literal ECDHE RSA/ECDSA AES-GCM TLS suites; no aliases or security-level overrides.'}
                message=suggestions.get(key,'Unsupported arguments; export a supported OpenVPN 2.5+ client option.')
                if key=='reneg-sec' and len(args) in (1,2) and all(unsigned(a) is not None for a in args) and any(unsigned(a)>604800 for a in args):
                    message='PiRate policy limit: reneg-sec values above 604800 seconds are unsupported; this is not an OpenVPN syntax error. No replacement interval is applied.'
                errors.append(diagnostic(original,'error',message))
                if key=='tls-version-min' and args in (['1.0'],['1.1']):proposals[original['line']]='tls-version-min 1.2\n'
            if key=='reneg-sec' and validate_option(key,args) and unsigned(args[0])==0:
                changes.append(diagnostic(original,'warning','Preserved: reneg-sec 0 disables the client periodic TLS renegotiation timer. The server may still initiate renegotiation; byte/packet limits remain effective. Optional security warning: longer-lived session keys; certificate authentication is unchanged.'))
            if key in ('data-ciphers','cipher','data-ciphers-fallback'):cipher_options.append((original,args))
        elif key in ('up','down','route-up','plugin','config','management','daemon','log','writepid','tls-verify','iproute','auth-user-pass-verify'):
            errors.append(diagnostic(d,'error','Executable hooks, nested configuration and process control are prohibited. Export a self-contained client profile.'))
        elif key not in {'client','dev','remote','proto','port','rport','nobind','persist-key','persist-tun','auth-nocache','auth-user-pass','ca','cert','key','tls-auth','tls-crypt','remote-cert-tls','verify-x509-name','auth','dhcp-option','verb','mute','resolv-retry','redirect-gateway','pull','explicit-exit-notify'}:
            errors.append(diagnostic(d,'error','Unsupported option: remove it only after reviewing its purpose; it will never be executed.'))
    # OpenVPN uses the last cipher-list setting. Canonicalize aliases/wrappers to
    # one effective setting so validator/runtime agree, preserving order/values.
    groups={}
    for d in parsed['directives']:
        from gate_core.openvpn_syntax import tokens
        parts=tokens(lines[d['line']],d['line']+1);key=parts[0] if parts else ''
        if key in ('data-ciphers','data-ciphers-fallback','cipher'):groups.setdefault((d['context'],key),[]).append(d)
    for (_,key),items in groups.items():
        for d in items[:-1]:replace(d,'# PiRate: superseded '+key,'Earlier cipher setting superseded by the later explicit setting, matching OpenVPN option order.')
    for d,args in cipher_options:
        if any(c in CBC for a in args for c in a.split(':')):
            auth=[x['args'] for x in parsed['directives'] if x['key']=='auth' and x['context'] in (None,d['context'])]
            if not auth or auth[-1] not in (['SHA256'],['SHA384'],['SHA512']):errors.append(diagnostic(d,'error','AES-CBC requires an explicit SHA256, SHA384 or SHA512 HMAC. No digest is inferred.'))
    if errors:
        exc=ProfileError('; '.join(f"OpenVPN original line {e['line']} ({e['directive']}): {e['message']}" for e in errors));exc.diagnostics=errors;exc.category=errors[0]['error_kind'];exc.line=errors[0]['line'];exc.compatibility_changes=automatic_changes
        # Suggestions are never applied by the compiler. UI requires an explicit
        # owner action and keeps the original upload bytes for audit/rollback.
        exc.proposed_config=''.join(proposals.get(i,line) for i,line in enumerate(parsed['lines'])) if proposals else None
        raise exc
    return ''.join(lines),changes
