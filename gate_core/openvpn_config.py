"""Small strict OpenVPN subset. Returns metadata, never source or credential contents."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
from .network_policy import NetworkPolicy


class ConfigurationError(ValueError):
    category = 'local_security_policy'


@dataclass(frozen=True)
class ServerAuthentication:
    certificate_role: str
    expected_name: str
    ca_source: str
    identity_policy: str = 'exact_name'


@dataclass(frozen=True)
class ValidatedOpenVPN:
    endpoint: str
    port: int
    protocol: str
    authentication: ServerAuthentication
    file_references: tuple = field(default=(), repr=False)
    inline_types: tuple = ()
    # No secret material is retained; this cannot be passed to a real VPN client.

    def validate(self):
        try:
            NetworkPolicy(self.endpoint, self.port, self.protocol, 'tun0').validate()
            auth = self.authentication
            if not isinstance(auth, ServerAuthentication) or auth.certificate_role != 'server' or auth.ca_source not in ('inline', 'trusted_file'):
                raise ValueError()
            exact=auth.identity_policy=='exact_name' and isinstance(auth.expected_name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',auth.expected_name)
            imported=auth.identity_policy=='imported_ca_server_role' and auth.expected_name=='' and auth.ca_source=='inline'
            if not (exact or imported):
                raise ValueError()
        except (ValueError, TypeError):
            raise ConfigurationError('Invalid server authentication model') from None
        return self


def external_reference(root, value):
    if root is None:
        raise ConfigurationError('External files require an explicit trusted directory')
    root = Path(root)
    candidate = Path(value)
    if candidate.is_absolute() or not candidate.parts or any(part in ('.', '..') for part in value.split('/')):
        raise ConfigurationError('Unsafe external file reference')
    if '\\' in value or '\x00' in value:
        raise ConfigurationError('Unsafe external file reference')
    for ancestor in (root, *root.parents):
        if ancestor.is_symlink():
            raise ConfigurationError('Symlink references unsupported')
    target = root
    for part in candidate.parts:
        target = target / part
        if target.is_symlink():
            raise ConfigurationError('Symlink references unsupported')
    try:
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ConfigurationError('External file must be private and owned by current user')
        target.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        raise ConfigurationError('External file unavailable or unsafe') from None
    return value


def validate_openvpn(content, *, trusted_directory=None, max_bytes=65536, compatible=False, allow_imported_ca=False):
    def fail(line, reason):
        # Never echo unknown directive, argument, paths or inline contents.
        error=ConfigurationError(f'Line {line}: {reason}');error.line=line
        if reason in ('Unsupported argument count','Duplicate directive','Empty inline block','Malformed inline block'):error.category='invalid_syntax'
        if reason=='Unsupported directive':error.category='unsupported_feature'
        raise error
    if not isinstance(content, str) or '\x00' in content:
        raise ConfigurationError('Configuration must be UTF-8 text')
    try:
        size = len(content.encode('utf-8'))
    except UnicodeError:
        raise ConfigurationError('Configuration must be UTF-8 text') from None
    if size > max_bytes or not content.strip():
        raise ConfigurationError('Configuration empty or exceeds '+str(max_bytes//1024)+' KiB')
    options, blocks, references = {}, set(), []
    active, block_nonempty = None, False
    flags = {'client', 'nobind', 'persist-key', 'persist-tun', 'auth-nocache'}
    files = {'ca', 'cert', 'key', 'tls-crypt', 'auth-user-pass'}
    allowed = flags | files | {'dev', 'remote', 'proto', 'remote-cert-tls', 'verify-x509-name', 'data-ciphers', 'auth'}
    if compatible:
        from .mvp.openvpn_compat import EXTRA, validate_option
        files |= {'tls-auth'}
        allowed |= EXTRA | {'tls-auth'}
    lexical=None;inline_tags={}
    if compatible:
        from .openvpn_syntax import parse_document, OpenVPNSyntaxError
        try:document=parse_document(content)
        except OpenVPNSyntaxError as exc:
            error=ConfigurationError(str(exc));error.category='invalid_syntax';error.line=exc.line
            raise error from None
        if document['connections']:raise ConfigurationError('Final configuration must select one connection')
        lexical={d['line']+1:d for d in document['directives']}
        for block in document['blocks']:
            inline_tags[block['start']+1]='<'+block['kind']+'>'
            inline_tags[block['end']+1]='</'+block['kind']+'>'
    for number, raw in enumerate(content.splitlines(), 1):
        line = inline_tags.get(number,raw.strip())
        if active:
            if line == f'</{active}>':
                if not block_nonempty: fail(number, 'Empty inline block')
                active = None
            else:
                if '<' in line or '>' in line: fail(number, 'Malformed inline block')
                block_nonempty |= bool(line)
            continue
        if not line or line.startswith(('#', ';')):
            continue
        tag = re.fullmatch(r'<([a-z-]+)>', line)
        if tag:
            active = tag[1]
            if active not in files or active in options or active in blocks:
                fail(number, 'Unsupported or duplicate inline block')
            blocks.add(active); block_nonempty = False
            continue
        if compatible:
            d=lexical.get(number)
            if d is None:continue
            parts=[d['key'],*d['args']]
            if any(c in value for value in parts for c in ('<','>','\\')):
                fail(number,'Unsupported argument syntax')
        else:
            if any(c in line for c in ('<','>','"',"'",'\\')):
                fail(number,'Unsupported quoting, continuation or inline syntax')
            parts=line.split()
        directive, values = parts[0], parts[1:]
        if directive not in allowed:
            fail(number, 'Unsupported directive')
        if compatible and directive in EXTRA | {'data-ciphers'}:
            if not validate_option(directive,values):
                from .mvp.openvpn_compat import error_kind
                error=ConfigurationError(f'Line {number}: Unsupported compatible option arguments');error.line=number;error.category=error_kind(directive,values)
                raise error
            if directive in options and directive != 'pull-filter': fail(number, 'Duplicate directive')
            options[directive]=values
            continue
        if directive in options or directive in blocks:
            fail(number, 'Duplicate directive')
        expected = 0 if directive in flags else (2 if directive == 'verify-x509-name' else 3 if directive == 'remote' else 1)
        if len(values) != expected:
            fail(number, 'Unsupported argument count')
        if directive in files:
            references.append((directive, external_reference(trusted_directory, values[0])))
        options[directive] = values
    if active:
        raise ConfigurationError('Unterminated inline block')
    if options.get('client') != [] or options.get('dev') != ['tun']:
        raise ConfigurationError('Client TUN configuration required')
    if 'remote' not in options or 'proto' not in options:
        raise ConfigurationError('Explicit endpoint, port and protocol required')
    endpoint, port_text, remote_proto = options['remote']
    if not port_text.isascii() or not port_text.isdecimal() or len(port_text) > 5:
        raise ConfigurationError('Invalid endpoint port')
    protocol = options['proto'][0]
    if remote_proto != protocol:
        raise ConfigurationError('Conflicting endpoint protocols')
    try:
        NetworkPolicy(endpoint, int(port_text), protocol, 'tun0').validate()
    except ValueError:
        raise ConfigurationError('Invalid endpoint, port or protocol') from None
    if options.get('remote-cert-tls') != ['server'] or ('ca' not in blocks and 'ca' not in options):
        raise ConfigurationError('Trusted CA and server certificate role required')
    if compatible and 'tls-auth' in blocks | set(options) and 'tls-crypt' in blocks | set(options):
        raise ConfigurationError('tls-auth and tls-crypt are mutually exclusive')
    if compatible and 'key-direction' in options and 'tls-auth' not in blocks | set(options):
        raise ConfigurationError('key-direction requires tls-auth')
    identity = options.get('verify-x509-name', [])
    ca_identity=compatible and allow_imported_ca is True and not identity and 'ca' in blocks
    if not ca_identity and (len(identity) != 2 or identity[1] != 'name' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', identity[0])):
        raise ConfigurationError('Exact server certificate name required')
    if ('cert' in blocks or 'cert' in options) != ('key' in blocks or 'key' in options):
        raise ConfigurationError('Client certificate and key must be paired')
    if compatible:
        from .mvp.openvpn_compat import CBC
        if any(c in CBC for k in ('cipher','data-ciphers','data-ciphers-fallback') for v in options.get(k,[]) for c in v.split(':')) and options.get('auth') not in (['SHA256'],['SHA384'],['SHA512']):
            raise ConfigurationError('AES-CBC requires explicit strong HMAC')
    if not compatible and 'data-ciphers' in options and options['data-ciphers'][0] not in ('AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'):
        raise ConfigurationError('Unsupported cipher')
    if 'auth' in options and options['auth'][0] not in ('SHA256', 'SHA384', 'SHA512'):
        raise ConfigurationError('Unsupported digest')
    ca_source = 'inline' if 'ca' in blocks else 'trusted_file'
    return ValidatedOpenVPN(endpoint, int(port_text), protocol,
                            ServerAuthentication('server', identity[0] if identity else '', ca_source,'imported_ca_server_role' if ca_identity else 'exact_name'),
                            tuple(references), tuple(sorted(blocks))).validate()
