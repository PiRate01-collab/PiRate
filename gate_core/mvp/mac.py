"""Adapter identity changes, with observed verification and explicit recovery."""
import json
from pathlib import Path
import re
import secrets
from .proxy import ConnectionError
from .router import network_command, command_failure


def validate(value):
    if not isinstance(value,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value):raise ConnectionError('MAC должен содержать 6 hex байт через двоеточия')
    value=value.lower()
    if int(value[:2],16)&1 or value=='00:00:00:00:00:00':raise ConnectionError('Нужен unicast MAC, не нулевой и не multicast')
    return value


def generate():
    raw=bytearray(secrets.token_bytes(6));raw[0]=(raw[0]|2)&0xfe
    return ':'.join(f'{byte:02x}' for byte in raw)


def link(interface):
    result=network_command('ip','-j','-d','link','show','dev',interface)
    values=json.loads(result.stdout)
    if not values:raise ConnectionError('Wi-Fi interface отсутствует: '+interface)
    return values[0]


def hardware(interface):
    info=link(interface)
    if info.get('permaddr'):return validate(info['permaddr'])
    try:
        if (Path('/sys/class/net')/interface/'addr_assign_type').read_text().strip()=='0':return validate(info['address'])
    except OSError:pass
    try:text=network_command('ethtool','-P',interface,check=False).stdout
    except ConnectionError:text=''
    match=re.search(r'Permanent address:\s*([0-9a-fA-F:]{17})',text)
    if match:return validate(match[1])
    raise ConnectionError('Драйвер не сообщает hardware MAC. Текущий MAC оставлен; используй сохранённый исходный адрес или Manual.')


def apply(interface,address):
    address=validate(address)
    info=link(interface)
    if info.get('address','').lower()==address:return
    # hostapd may leave its owned netdev in AP mode after exiting. nl80211
    # drivers can refuse MAC changes there even with IFF_UP cleared. Do not
    # repeat a failed operation or stop any global networking service.
    mode=network_command('iw','dev',interface,'info',check=False)
    current=re.search(r'^\s*type\s+(\S+)',mode.stdout,re.M)
    if 'UP' in info.get('flags',[]):network_command('ip','link','set',interface,'down')
    if current and current[1]=='AP':
        network_command('iw','dev',interface,'set','type','managed')
    args=('ip','link','set','dev',interface,'address',address)
    result=network_command(*args,check=False)
    if result.returncode:
        error=command_failure(args,result,getattr(result,'pirate_operation',None))
        raise error
    if link(interface).get('address','').lower()!=address:raise ConnectionError('Драйвер не применил MAC; возвращается предыдущая настройка')


def restore_mode(interface,mode,failed=None):
    """Restore only our released netdev; no assumption about global services."""
    observed=network_command('iw','dev',interface,'info',check=False)
    current=re.search(r'^\s*type\s+(\S+)',observed.stdout,re.M)
    if not current or current[1]==mode:return
    if mode not in ('managed','AP'):raise ConnectionError('Original interface mode cannot be safely restored: '+mode)
    args=('iw','dev',interface,'set','type',mode)
    if failed and failed.get('arguments')==list(args):
        raise ConnectionError('Rollback mode restoration unverified: refusing to repeat the failed interface mode operation')
    info=link(interface)
    if 'UP' in info.get('flags',[]):network_command('ip','link','set',interface,'down')
    network_command(*args)
    verify=network_command('iw','dev',interface,'info')
    actual=re.search(r'^\s*type\s+(\S+)',verify.stdout,re.M)
    if not actual or actual[1]!=mode:raise ConnectionError('Rollback interface mode was not verified')
