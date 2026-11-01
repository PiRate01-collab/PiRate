"""Allowlisted DNS discovery through the selected transport, never host DNS."""
import ipaddress
from .proxy import ConnectionError

ALLOWED=('1.1.1.1','9.9.9.9','8.8.8.8')
DOH_ALLOWED=('https://cloudflare-dns.com/dns-query','https://dns.google/dns-query')


def candidates(profile,manual=None):
    values=manual if manual is not None else [*[ip for ip in profile.get('dns_servers',[]) if ipaddress.ip_address(ip).version==4],*ALLOWED]
    if not isinstance(values,list) or not 1<=len(values)<=(10 if manual is not None else 13):raise ConnectionError('Укажи от 1 до 10 IPv4 DNS resolver')
    try:return list(dict.fromkeys(str(ipaddress.IPv4Address(value)) for value in values))
    except (ValueError,TypeError):raise ConnectionError('DNS resolver должен быть IPv4 адресом') from None


def select(backend,config,manual=None):
    from .router import DNSPolicy
    attempts=[];available=candidates(backend.profile,manual)
    doh=list(DOH_ALLOWED) if manual is None and backend.profile['type'] in ('http','socks5') else []
    for resolver in [*available,*doh]:
        mode='doh' if resolver.startswith('https://') else 'tcp'
        trial=dict(config,dns_mode=mode,dns_server=available[0] if mode=='doh' else resolver,
                   doh_url=resolver if mode=='doh' else '',dns_auto=False,dns_fallbacks=[],dns_doh_fallbacks=[])
        try:
            check=DNSPolicy(trial,lambda:backend).check(backend)
            selected=dict(trial,dns_auto=True,dns_candidates=available,dns_fallbacks=[ip for ip in available if ip!=resolver],dns_doh_fallbacks=doh)
            return selected,dict(check,resolver=resolver,attempts=attempts,via=backend.profile['type'])
        except (OSError,ValueError,ConnectionError) as exc:
            attempts.append({'resolver':resolver,'status':'FAIL','reason':str(exc)})
    error=ConnectionError('DNS FAIL: разрешённые resolver недоступны через '+backend.profile['type']+'; укажи другой IPv4 DNS. '+ '; '.join(item['resolver']+': '+item['reason'] for item in attempts))
    error.attempts=attempts
    raise error
