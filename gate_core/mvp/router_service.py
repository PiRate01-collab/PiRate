"""Small router API: discover hardware, compose safe defaults and expose real metrics."""
import ipaddress
import json
from pathlib import Path
import time
from .admin import command
from .ap import normalize
from .proxy import ConnectionError


class RouterService:
    def __init__(self,app):self.app=app;self.samples={};self.cpu=None

    def interfaces(self):
        links=command('ip','-j','link');routes=command('ip','-j','-4','route','show','default')
        try:links=json.loads(links.stdout) if links.returncode==0 else []
        except ValueError:links=[]
        try:routes=json.loads(routes.stdout) if routes.returncode==0 else []
        except ValueError:routes=[]
        result=[]
        for link in links:
            name=link['ifname']
            if name=='lo' or name.startswith(('pv','pr-','tun','wg')):continue
            wifi=(Path('/sys/class/net')/name/'phy80211').exists() or (Path('/sys/class/net')/name/'wireless').exists()
            if not wifi:wifi=command('iw','dev',name,'info').returncode==0
            radio=None;label=name
            if wifi:
                from .ap import capabilities
                radio=capabilities(name)
                device=Path('/sys/class/net')/name/'device'
                try:
                    resolved=device.resolve(strict=True)
                    product=next((p.joinpath('product').read_text().strip() for p in [resolved,*list(resolved.parents)[:3]] if p.joinpath('product').is_file()),'')
                    driver=device.joinpath('driver').resolve(strict=True).name
                    label=(product+' · ' if product else '')+driver
                except OSError:pass
            result.append({'adapter':label,'capabilities':radio,'name':name,'kind':'wifi' if wifi else 'ethernet','up':'UP' in link.get('flags',[]),'mac':link.get('address'),'default_route':any(r.get('dev')==name for r in routes)})
        return result

    def setup(self):
        config=self.app.ap.active or self.app.ap.saved
        deployment=self.app.ap.management.config or {}
        devices=self.interfaces();wifi=[v['name'] for v in sorted(devices,key=lambda v:(v.get('capabilities') or {}).get('ap_mode') is not True) if v['kind']=='wifi']
        ap_interface=(config or {}).get('interface') or deployment.get('ap_interface') or (wifi[0] if wifi else '')
        wan=deployment.get('wan_interface') or next((v['name'] for v in devices if v['default_route']),None)
        gateway=self.app.router.current.config if self.app.router.current else self.app.router.blocked_config or {}
        wan=gateway.get('wan_interface',wan)
        address=ipaddress.IPv4Interface((config or {}).get('subnet',deployment.get('subnet','10.42.0.1/24')))
        settings={**{'interface':ap_interface,'ssid':'PiRate','security':'wpa2','country':'','channel':0,'band':'auto','width':'auto','mac_mode':'keep','mac_address':'','fingerprint':'default'},**({k:v for k,v in config.items() if k!='password'} if config else {})}
        if not settings['country']:
            reg=command('iw','reg','get')
            import re
            country=re.search(r'country ([A-Z]{2}):',reg.stdout)
            if country:settings['country']=country[1]
        current=self.app.current
        if current:selected=current.profile['id']
        else:
            try:selected=json.loads(self.app.confirmed_path.read_text()).get('profile_id')
            except (OSError,ValueError):selected=None
        return {'interfaces':devices,'wifi':settings,'password_saved':bool(config and config.get('password')),'wan_interface':wan or '',
                'profile_id':selected,'subnet':str(address),'dns_candidates':gateway.get('dns_candidates',[]),'dns_auto':gateway.get('dns_auto',True),'dns_manual':gateway.get('dns_manual',False),'doh_url':gateway.get('doh_url','') if gateway.get('dns_manual') else ''}

    def apply(self,data):
        if isinstance(data,dict) and data.get('wifi_profile_id'):
            with self.app.lock:return self._apply(data)
        return self._apply(data)

    def _apply(self,data):
        allowed={'profile_id','wifi','wifi_profile_id','wan_interface','dns','timeout'}
        if isinstance(data,dict) and data.get('wifi_profile_id'):
            from .ap_profiles import store
            record=store(self.app).get(data['wifi_profile_id'])
            data=dict(data,wifi=dict(record['wifi'],saved_profile_id=record['id']))
        if not isinstance(data,dict) or set(data)-allowed or not isinstance(data.get('wifi'),dict):raise ConnectionError('Expected router settings')
        if not data.get('wifi_profile_id') and 'saved_profile_id' in data['wifi']:raise ConnectionError('Use wifi_profile_id to apply saved settings')
        prior=self.setup();wifi=dict(data['wifi'])
        if set(wifi)-{'interface','ssid','password','security','country','channel','band','width','mac_mode','mac_address','fingerprint','saved_profile_id'}:raise ConnectionError('Unknown Wi-Fi setting')
        subnet=ipaddress.IPv4Interface(prior['subnet']);net=subnet.network
        previous=self.app.ap.active or self.app.ap.saved or {}
        wifi.update(subnet=str(subnet),dhcp_start=previous.get('dhcp_start',str(net[10 if net.num_addresses>16 else 2])),
                    dhcp_end=previous.get('dhcp_end',str(net[min(200,net.num_addresses-2)])),lease_minutes=previous.get('lease_minutes',60))
        value=normalize(wifi,self.app.ap.active or self.app.ap.saved,getattr(self.app.ap,'requested_identity',None))
        dns=data.get('dns',{})
        if not isinstance(dns,dict) or set(dns)-{'mode','servers','doh_url'} or dns.get('mode','auto') not in ('auto','manual'):raise ConnectionError('Invalid DNS settings')
        gateway={'lan_interface':value['interface'],'wan_interface':data.get('wan_interface') or prior['wan_interface'],
                 'dns_mode':'auto','dns_auto':True,'dns_server':'1.1.1.1','lan_subnet':str(net),'fingerprint':value['fingerprint']}
        if dns.get('mode')=='manual':
            from .dns_auto import candidates
            gateway['dns_manual']=True
            if dns.get('doh_url'):
                from .router import configuration
                gateway.update(dns_auto=False,dns_mode='doh',doh_url=dns['doh_url'])
                gateway=configuration(gateway)
            else:gateway['dns_candidates']=candidates({},dns.get('servers',[]))
        return self.app.connect(data['profile_id'],data.get('timeout',90),gateway_config=gateway,ap_config=value)

    def apply_wifi_profile(self, identifier):
        from .ap_profiles import store
        with self.app.lock:
            if self.app.pending:raise ConnectionError('Сначала подтвердите или отмените текущие изменения.')
            if not self.app.current or not self.app.router.current:
                raise ConnectionError('Сначала подключите роутер на экране «Подключения». Затем примените профиль Wi-Fi.')
            record=store(self.app).get(identifier)
            previous=self.app.ap.active or self.app.ap.saved or {}
            raw=dict(record['wifi'],saved_profile_id=record['id'])
            for key in ('subnet','dhcp_start','dhcp_end','lease_minutes'):
                if key in previous:raw[key]=previous[key]
            value=normalize(raw)
            gateway=dict(self.app.router.current.config,lan_interface=value['interface'],
                         lan_subnet=str(ipaddress.IPv4Interface(value['subnet']).network),fingerprint=value['fingerprint'])
            # Same backend identity: connect() already reuses it for AP changes.
            return self.app.connect(self.app.current.profile['id'],90,gateway_config=gateway,ap_config=value)

    def system(self):
        from gate_core import VERSION
        def content(path):
            try:return Path(path).read_text()
            except OSError:return ''
        try:uptime=float(content('/proc/uptime').split()[0])
        except (ValueError,IndexError):uptime=None
        mem={line.split(':')[0]:int(line.split()[1])*1024 for line in content('/proc/meminfo').splitlines() if ':' in line and len(line.split())>1 and line.split()[1].isdigit()}
        try:
            values=[int(value) for value in content('/proc/stat').splitlines()[0].split()[1:9]];total=sum(values);idle=values[3]+values[4]
            cpu=round(100*(1-(idle-self.cpu[1])/(total-self.cpu[0])),1) if self.cpu and total>self.cpu[0] else None
            self.cpu=(total,idle)
        except (ValueError,IndexError,ZeroDivisionError):cpu=None
        temperatures=[]
        for path in Path('/sys/class/thermal').glob('thermal_zone*/temp'):
            try:temperatures.append(float(content(path))/1000)
            except ValueError:pass
        return {'version':VERSION,'uptime_seconds':uptime,'cpu_percent':cpu,'ram_total':mem.get('MemTotal'),'ram_used':mem['MemTotal']-mem['MemAvailable'] if 'MemAvailable' in mem else None,
                'temperature_c':max(temperatures) if temperatures else None}

    def clients(self,interface):
        result=command('iw','dev',interface,'station','dump')
        if result.returncode:
            control=getattr(self.app.ap,'control',None)
            if control:
                data=control.stations()
                return [{**row,'hostname':'Клиент '+row['mac'][-8:],'ip':None,'signal_dbm':None,**{d+'_mbps':None for d in ('tx','rx')}} for row in data] if data else None
            return None
        from .wifi_performance import stations
        items=stations(result.stdout)
        leases={}
        try:
            for line in (self.app.ap.directory/'leases').read_text().splitlines():
                expiry,mac,ip,host,*_=line.split()
                if int(expiry)==0 or int(expiry)>time.time():leases[mac.lower()]=(ip,host)
        except (OSError,ValueError):pass
        for item in items:
            ip,host=leases.get(item['mac'],(None,None))
            item.update(ip=ip,hostname=host if host and host!='*' else 'Клиент '+item['mac'][-8:])
            item['warning']='Низкий link bitrate; это не замер скорости интернета' if any(item[d+'_mbps'] is not None and item[d+'_mbps']<30 for d in ('tx','rx')) else None
        return items

    def dashboard(self):
        if not self.app.lock.acquire(blocking=False):
            return {'service':'Running','wifi_health':{'state':'Starting' if getattr(getattr(self.app,'ap',None),'starting',False) else 'Unknown'},'state':'CHECKING','internet':{'status':'UNKNOWN'},'external_ip':None,'profile':None,
                    'ap':'UNKNOWN','ssid':None,'mac':None,'clients':None,'speed':None,'dns':{'status':'UNKNOWN'},
                    'pending':None,'seconds_remaining':None,'error':None,'restore':self.app.restore_state,
                    'lan':'CHECKING','system':self.system()}
        try:return self._dashboard_locked()
        finally:self.app.lock.release()

    def _dashboard_locked(self):
        with self.app.lock:
            state=self.app.status();active=self.app.ap.active;current=self.app.current
            check=dict(getattr(current,'last_check',{'status':'NOT TESTED'})) if current else {'status':'DISCONNECTED'};external=None
            if check.get('status')=='PASS' and time.time()-check.get('checked_at',0)>90:check['status']='UNKNOWN'
            if check.get('status')=='PASS':
                try:
                    ip=ipaddress.ip_address(check.get('body','').strip())
                    if ip.is_global:external=str(ip)
                except ValueError:pass
            upstream_check=dict(check)
            native=current is not None and current.profile['type'] in ('wireguard','openvpn')
            if native and check.get('status')=='PASS':check=dict(check,status='UNVERIFIED',scope='Tunnel namespace probe passed; LAN client path unverified')
            speed=None;clients=None;observed_mac=None
            if active:
                name=active['interface'];clients=self.clients(name)
                from .wifi_performance import observed_ap
                try:state['ap']['radio']={**state['ap'].get('radio',{}),'observed':observed_ap(command('iw','dev',name,'info').stdout)}
                except (OSError,ValueError):state['ap']['radio']['observed']={}
                try:
                    folder=Path('/sys/class/net')/name
                    rx=int((folder/'statistics/rx_bytes').read_text());tx=int((folder/'statistics/tx_bytes').read_text());now=time.monotonic()
                    prior=self.samples.get(name)
                    if prior and .2<now-prior[0]<10 and rx>=prior[1] and tx>=prior[2]:speed={'rx_bps':(rx-prior[1])*8/(now-prior[0]),'tx_bps':(tx-prior[2])*8/(now-prior[0])}
                    self.samples[name]=(now,rx,tx);observed_mac=(folder/'address').read_text().strip()
                except (OSError,ValueError):pass
            return {'state':state['state'],'internet':check,'external_ip':external,'profile':self.app.profiles.public(current.profile) if current else None,
                    'service':'Running','wifi_health':state['ap'].get('health',{}),'wifi_power_save':state['ap'].get('power_save',{}),'wifi_recovery':state['ap'].get('recovery',{}),'wifi_control_directory':state['ap'].get('control_directory'),'wifi_apply_failure':state['ap'].get('apply_failure'),'wifi_ownership':state['ap'].get('ownership'),'wifi_failure':state['ap'].get('failure'),'radio':state['ap'].get('radio',{}),'ap':state['ap']['state'],'ssid':active['ssid'] if active else None,'mac':observed_mac,'clients':clients,'speed':speed,
                    'vpn':state['router'].get('vpn'),'client_connectivity':state['router'].get('client_connectivity'),'dns_local':state['router'].get('dns_local'),'upstream_check':upstream_check,'dns':state['router']['dns_check'],'pending':state['pending'],'seconds_remaining':state['seconds_remaining'],
                    'error':state['last_error'],'restore':state['restore'],'lan':state['router']['state'],'system':self.system()}
