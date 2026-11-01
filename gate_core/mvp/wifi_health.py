"""Bounded AP control and attributed kernel observations, never beacon proof."""
from collections import deque
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid


def execute(*args):
    try:return subprocess.run(args,capture_output=True,text=True,timeout=2)
    except (OSError,subprocess.SubprocessError):return subprocess.CompletedProcess(args,1,'','unavailable')


def values(text):
    return dict(line.split('=',1) for line in (text or '').splitlines() if '=' in line)


class HostapdControl:
    """Separate request/event datagrams so unsolicited events cannot spoof STATUS."""
    def __init__(self,directory,interface):
        self.directory=Path(directory);self.interface=interface;self.socket=None;self.local=None

    def _open(self):
        local=self.directory/('c-'+uuid.uuid4().hex[:8])
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        try:
            sock.settimeout(.3);sock.bind(str(local));os.chmod(local,0o600)
            sock.connect(str(self.directory/self.interface))
            return sock,local
        except OSError:
            sock.close();local.unlink(missing_ok=True);raise

    def request(self,command):
        sock=local=None
        try:
            sock,local=self._open();sock.send(command.encode());return sock.recv(16384).decode(errors='replace').strip()
        except OSError:return None
        finally:
            if sock:sock.close()
            if local:local.unlink(missing_ok=True)

    def status(self):return values(self.request('STATUS'))

    def stations(self):
        # Control data is filtered; GET_CONFIG (which can return PSKs) is forbidden.
        text=self.request('STA-FIRST');result=[];seen=set()
        for _ in range(64):
            lines=(text or '').splitlines();mac=lines[0] if lines else ''
            if not re.fullmatch(r'[0-9a-fA-F:]{17}',mac) or mac in seen:break
            seen.add(mac);item=values(text)
            result.append({'mac':mac.lower(),**{k:item[k] for k in ('flags','rx_packets','tx_packets','connected_time') if k in item}})
            text=self.request('STA-NEXT '+mac)
        return result

    def events(self):
        if self.socket is None:
            sock=local=None
            try:
                sock,local=self._open();sock.send(b'ATTACH')
                if sock.recv(64).strip()!=b'OK':raise OSError('ATTACH rejected')
                sock.setblocking(False);self.socket,self.local=sock,local
            except OSError:
                if sock:sock.close()
                if local:local.unlink(missing_ok=True)
                return []
        result=[]
        for _ in range(32):
            try:text=self.socket.recv(2048).decode(errors='replace')
            except (BlockingIOError,socket.timeout):break
            except OSError:self.close();break
            event=re.search(r'\b(AP-ENABLED|AP-DISABLED|CTRL-EVENT-TERMINATING|AP-STA-CONNECTED|AP-STA-DISCONNECTED)\b',text)
            if event:result.append({'at':time.time(),'event':event[1]})
        return result

    def close(self):
        if self.socket:
            try:self.socket.send(b'DETACH')
            except OSError:pass
            self.socket.close();self.socket=None
        if self.local:self.local.unlink(missing_ok=True);self.local=None


def identifiers(interface):
    result={interface};base=Path('/sys/class/net')/interface
    try:
        result.add((base/'phy80211').resolve(strict=True).name)
        device=(base/'device').resolve(strict=True)
        for path in (device,*device.parents):
            if re.fullmatch(r'\d+-[\d.]+(?::\d+\.\d+)?',path.name):result.add(path.name)
    except OSError:pass
    return result


DRIVER_ERRORS=re.compile(r'error beacon valid|failed to (?:download (?:rsvd page|firmware)|leave ips state|send h2c command)|(?:failed|unable) to .*firmware|firmware.*(?:error|fail|timeout|crash|unresponsive|not responding)|microcode.*(?:error|fail)|(?:firmware|command).*timed out',re.I)
USB_ERRORS=re.compile(r'USB disconnect|(?:USB|usb|urb).*?(?:error.*?-71|error -\d+|disconnect|reset.*fail)|device descriptor read.*error',re.I)


class KernelHealth:
    def __init__(self,interface,run=execute):
        self.interface=interface;self.run=run;self.targets=identifiers(interface)
        self.cursor=None;self.since=time.monotonic();self.errors=deque(maxlen=32);self.available=False;self.note='Kernel observations unavailable';self.seen=deque(maxlen=256)

    def begin(self):
        self.targets.update(identifiers(self.interface));self.since=time.monotonic();self.errors.clear()

    def poll(self):
        args=['journalctl','-k','-b','--no-pager','-n','128','-o','json','--output-fields=MESSAGE,__CURSOR,__MONOTONIC_TIMESTAMP,_KERNEL_DEVICE']
        args+=['--after-cursor',self.cursor] if self.cursor else ['--since','-30 seconds']
        result=self.run(*args);now=time.monotonic();parsed=False
        if result.returncode==0:
            self.available=True;self.note='No attributed driver fault in the observation window; beacon transmission unverified'
            for line in result.stdout[-131072:].splitlines():
                try:row=json.loads(line)
                except ValueError:continue
                parsed=True
                cursor=row.get('__CURSOR') if isinstance(row.get('__CURSOR'),str) else None
                if cursor:
                    if cursor in self.seen:continue
                    self.seen.append(cursor);self.cursor=cursor
                try:stamp=int(row['__MONOTONIC_TIMESTAMP'])/1e6
                except (KeyError,TypeError,ValueError):continue
                if stamp<self.since or stamp>now+1:continue
                message=row.get('MESSAGE','');device=row.get('_KERNEL_DEVICE','')
                if not isinstance(message,str) or not isinstance(device,str):continue
                scoped=any(re.search(r'(?<![\w.-])'+re.escape(target)+r'(?![\w.-])',message+' '+device) for target in self.targets)
                if not scoped:continue
                kind='usb' if USB_ERRORS.search(message) else 'firmware' if DRIVER_ERRORS.search(message) else 'busy' if re.search(r'device or resource busy|\bEBUSY\b',message,re.I) else None
                if kind:self.errors.append({'at':stamp,'kind':kind,'detail':message[:400]})
        else:self.available=False;self.note='Kernel journal unavailable (exit '+str(result.returncode)+': '+result.stderr.strip()[:200]+'); driver health Unknown'
        if result.returncode==0 and not parsed and self.cursor is None:
            self.available=False;self.note='No kernel journal data; driver health Unknown'
        recent=[row for row in self.errors if now-row['at']<=30]
        fatal=any(row['kind']=='usb' and 'disconnect' in row['detail'].lower() for row in recent)
        confirmed=fatal or len(recent)>=3
        return {'state':'Error' if confirmed else 'Degraded' if recent else 'Ready' if self.available else 'Unknown',
                'confirmed_fault':confirmed,'reason':('USB communication/disconnect error' if any(r['kind']=='usb' for r in recent) else 'Adapter busy' if all(r['kind']=='busy' for r in recent) else 'Adapter firmware communication error') if recent else None,
                'journal_returncode':result.returncode,'events':recent,'note':self.note,'source':'journal/kernel','available':self.available}
