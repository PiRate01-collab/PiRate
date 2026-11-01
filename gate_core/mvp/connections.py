"""Live connection selection and timed Safe Apply using real backend probes."""
import json
import fcntl
import os
import threading
import time
from pathlib import Path
from gate_core.core import ProfileError, command
from .proxy import ProxyBackend, DirectBackend, Gateway, ConnectionError
from .support import connection_event, backend_evidence, record, secret_values

class Connections:
    def __init__(self, profiles, state_dir, proxy_port=8088, check_url='https://api.ipify.org/'):
        self.profiles = profiles
        self.directory = Path(state_dir)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.process_lock = (self.directory/'connection.lock').open('a')
        os.fchmod(self.process_lock.fileno(),0o600)
        try:fcntl.flock(self.process_lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.process_lock.close()
            raise ProfileError('Another PiRate instance owns this data directory') from None
        self.path = self.directory/'connection.json'
        self.lock = threading.RLock()
        self.current = None
        self.previous = None
        self.pending = None
        self.deadline_monotonic = None
        self.last_check = {'status':'NOT TESTED'}
        self.last_error = None
        self.last_action = 'STARTED'
        self.confirmed_path=self.directory/'confirmed-router.json'
        self.restore_state='NOT CONFIGURED'
        self.check_url = check_url
        self.closed = False
        from .router import RouterGateway
        self.router = RouterGateway(self)
        from .ap import AccessPoint
        self.ap = AccessPoint(self)
        # Process-owned proxy connections cannot survive a server restart.
        # Persisted native namespace resources are recovered by their owning backend.
        if self.path.exists():
            state = json.loads(self.path.read_text())
            from .tunnels import recover_namespaces
            recover_namespaces(state.get('native_resources', []), self.directory)
            self.last_action = 'RECOVERED_DISCONNECTED'
        if not self.path.exists():
            from .tunnels import recover_namespaces
            recover_namespaces([], self.directory)
        self.gateway = Gateway(('127.0.0.1', proxy_port), self.active)
        self.server_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.server_thread.start()
        self.persist()
        self.watchdog = threading.Thread(target=self.watch, daemon=True)
        self.watchdog.start()
        if self.confirmed_path.exists():
            threading.Thread(target=self.restore_confirmed,daemon=True).start()

    def active(self):
        with self.lock:
            return self.current

    def persist(self):
        state = {'schema':1, 'profile_id':self.current.profile['id'] if self.current else None,
                 'pending':self.pending, 'last_action':self.last_action,
                 'native_resources':[b.resource for b in (self.current,self.previous) if b and hasattr(b,'resource')]}
        temporary = self.path.with_suffix('.tmp')
        with temporary.open('w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(state,stream)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,self.path)
        fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def repair_wifi(self,manual=False):
        with self.lock:
            if self.pending:raise ConnectionError('Confirm or roll back Safe Apply before Retry Wi-Fi')
            if not self.ap.active or not self.router.current or not self.current:
                raise ConnectionError('Start the saved router with Apply before Retry Wi-Fi')
            if self.ap.retry_after():raise ConnectionError('Wi-Fi retry cooldown: '+str(self.ap.retry_after())+' seconds')
            if not self.ap.interface_present():raise ConnectionError('Wi-Fi adapter disconnected; reconnect it before Retry Wi-Fi')
            if not manual and self.ap.recovery.get('auto_attempts',0)>=1:raise ConnectionError('Automatic recovery exhausted; use Retry Wi-Fi')
            generation=self.router.current
            self.router.install(generation.config)  # LAN-only block; Ethernet management is independent.
            ap_repaired=False
            try:
                self.ap.recover(manual);ap_repaired=True
                self.router.check(self.current)
                self.router.install(generation.config,generation)
                self.last_error=None;self.last_action='WIFI_RECOVERY_CONTROL_VERIFIED';self.persist()
            except (OSError,ValueError,ConnectionError):
                self.last_error='AP control restored, but selected upstream/DNS is unavailable; LAN remains BLOCKED. Check Connections.' if ap_repaired else 'Wi-Fi unavailable. Retry Wi-Fi; if it repeats, reconnect the adapter or check driver compatibility.'
                self.last_action='WIFI_RECOVERY_FAILED_BLOCKED';self.persist();raise
            return self.status()

    def wifi_tick(self):
        if not self.ap.active:return
        report=self.ap.refresh_health()
        if self.pending and (report.get('confirmed_fault') or report.get('state')=='Degraded'):
            self.ap.recovery['reason']=report.get('reason')
            try:
                self.rollback('AP_FAILED_ROLLBACK_CONTROL_VERIFIED')
                self.last_error='Wi-Fi apply failed; previous AP control restored. Beacon transmission remains unverified.'
            except (OSError,ValueError,ConnectionError):
                if self.router.blocked_config:self.router.install(self.router.blocked_config)
                self.last_error='Wi-Fi rollback could not verify driver/control health; LAN BLOCKED'
                self.last_action='RECOVERY_REQUIRED';self.persist()
            return
        if not report.get('confirmed_fault'):return
        reason=report.get('reason') or self.ap.recovery.get('reason') or 'AP driver/control failure'
        self.ap.failure={'code':'driver_health','message':'Wi-Fi unavailable — '+reason+'. Try Retry Wi-Fi; if it repeats, reconnect the adapter or check driver compatibility.','detail':reason}
        self.last_error=self.ap.failure['message']
        if self.router.current and self.router.policy_active:self.router.install(self.router.current.config)
        if self.ap.recovery.get('auto_attempts',0)>=1:
            if not self.ap.recovery.get('latched'):
                self.ap.recovery.update(latched=True,reason=reason);self.ap.save();self.last_action='WIFI_RECOVERY_EXHAUSTED';self.persist()
            return
        if not self.ap.interface_present() or self.ap.retry_after() or not self.router.current:return
        try:self.repair_wifi()
        except (OSError,ValueError,ConnectionError):pass  # Budget was durably consumed before restarting.

    def retry_wifi(self):
        with self.lock:
            if self.pending:raise ConnectionError('Confirm or roll back Safe Apply before Retry Wi-Fi')
            if self.ap.active and self.router.current and self.current:return self.repair_wifi(manual=True)
            return self.restore_confirmed(manual=True)

    def watch(self):
        next_probe=time.monotonic()+30
        while not self.closed:
            with self.lock:
                if self.pending and time.monotonic() >= self.deadline_monotonic:
                    try:self.rollback('TIMEOUT_ROLLBACK')
                    except (OSError,ValueError,ConnectionError):
                        self.last_error='Rollback cleanup incomplete; inspect local backend resources'
                        self.last_action='RECOVERY_REQUIRED'
                elif self.current and not self.pending and time.monotonic()>=next_probe:
                    try:
                        self.router.check(self.current)
                        self.current.last_check=self.current.request(self.current.last_check.get('url',self.check_url))
                    except (OSError,ValueError,ConnectionError) as exc:
                        backend_evidence(self,self.current,'periodic connection failure')
                        record(self,self.current.profile['type'],'Periodic check: '+str(exc),'error',self.current.profile)
                        record(self,'firewall','Periodic check failed; no direct fallback','warning',self.current.profile)
                        self.current.last_check={'status':'FAIL','error':'Periodic connection check failed; no direct fallback','url':self.check_url,'checked_at':time.time()}
                    self.last_check=self.current.last_check
                    next_probe=time.monotonic()+30
                try:self.wifi_tick()
                except (OSError,ValueError,ConnectionError):
                    self.last_error='Wi-Fi health observations unavailable; inspect diagnostics. No automatic restart without confirmed evidence.'
            time.sleep(.2)

    @connection_event
    def connect(self, identifier, timeout=60, check_url=None, gateway_config=None, ap_config=None, manual_wifi_retry=True, *, _confirmed_ap=False):
        if type(timeout) is not int or not 5 <= timeout <= 300:
            raise ProfileError('Confirmation timeout must be 5–300 seconds')
        with self.lock:
            if getattr(self,'closed',False):raise ConnectionError('Controller stopping')
            if self.pending:
                raise ProfileError('Confirm or roll back the pending connection first')
            profile = self.profiles.get(identifier)
            reuse=bool(self.current and self.current.profile['id']==identifier and ap_config is not None)
            if self.current and profile['type'] in ('wireguard','openvpn'):
                from .tunnels import same_native_identity
                if not reuse and same_native_identity(profile,self.current.profile):
                    raise ProfileError('Safe Apply requires a separate VPN identity; disconnect before reconnecting the same credentials')
            self.last_error = None
            candidate = None;ap_preparing=False
            try:
                if gateway_config is None and self.router.current is not None:
                    gateway_config=dict(self.router.current.config)
                management=self.ap.management.config
                management_interface=management.get('management_interface') if management else None
                if management_interface and gateway_config is not None and gateway_config.get('lan_interface')==management_interface:
                    raise ConnectionError('Trusted management Ethernet cannot be used as AP/LAN; choose a dedicated LAN interface')
                if self.ap.active and ap_config is None and gateway_config is not None:
                    import ipaddress
                    gateway_config=dict(gateway_config,ap_dns_address=str(ipaddress.IPv4Interface(self.ap.active['subnet']).ip))
                    if self.ap.management.config:gateway_config['management_port']=8766
                if ap_config is not None:
                    if gateway_config is None:raise ConnectionError('AP Apply requires LAN gateway configuration')
                    ap_preparing=True
                    if isinstance(getattr(self.ap,'recovery',None),dict) and self.ap.recovery.get('latched'):
                        if not manual_wifi_retry:raise ConnectionError('Wi-Fi recovery latched; use Retry Wi-Fi after checking the adapter')
                        self.ap.claim_recovery(manual=True)
                    gateway_config=self.ap.prepare(ap_config,gateway_config)
                    # Restoring already-confirmed settings is independent of VPN
                    # availability. Keep AP management if the upstream fails.
                    # New Apply still commits AP only with the full transaction.
                    if _confirmed_ap:self.ap.confirm()
                    ap_preparing=False
                if gateway_config is not None:
                    gateway_config=self.router.arm(gateway_config)
                if reuse:
                    candidate=self.current
                elif profile['type'] in ('direct','http','socks5'):
                    candidate = DirectBackend(profile) if profile['type']=='direct' else ProxyBackend(profile)
                    if gateway_config is not None:
                        candidate.outbound_interface=gateway_config['wan_interface']
                    elif self.router.current:
                        candidate.outbound_interface=self.router.current.config['wan_interface']
                else:
                    from .tunnels import TunnelBackend
                    candidate = TunnelBackend(profile,self.directory,gateway_config['wan_interface'] if gateway_config else None)
                    # Record ownership before any native resource is created.
                    state = {'native_resources':[candidate.resource]+[b.resource for b in (self.current,) if b and hasattr(b,'resource')]}
                    with (self.directory/'native-pending.json').open('w') as stream:
                        os.fchmod(stream.fileno(),0o600);json.dump(state,stream);stream.flush();os.fsync(stream.fileno())
                    from .support import ATTEMPT
                    candidate.attempt_id=ATTEMPT.get()
                    candidate.start()
                if gateway_config is not None and gateway_config.get('dns_auto'):
                    from .dns_auto import select
                    gateway_config,dns_check=select(candidate,gateway_config,gateway_config.get('dns_candidates') if gateway_config.get('dns_manual') else None)
                    if hasattr(candidate,'set_resolver') and not reuse:candidate.set_resolver(dns_check['resolver'])
                from .support import ATTEMPT
                candidate.attempt_id=ATTEMPT.get()
                check = candidate.request(check_url or self.check_url)
                self.last_check = check
                candidate.last_check = check
                if gateway_config is not None:
                    self.router.prepare(gateway_config,candidate)
                elif self.router.current:
                    self.router.check(candidate)
            except (OSError, ValueError, ConnectionError) as exc:
                backend_evidence(self,candidate,'connection failed')
                record(self,profile['type'],str(exc),'error',profile,known=secret_values(ap_config))
                import re
                if re.search(r'DNS|resolver',str(exc),re.I):record(self,'dns',str(exc),'error',profile,known=secret_values(ap_config))
                if re.search(r'route|routing|nft|firewall',str(exc),re.I):record(self,'firewall',str(exc),'error',profile,known=secret_values(ap_config))
                self.router.rollback()
                if candidate and candidate is not self.current:
                    candidate.stop()
                    backend_evidence(self,candidate,'connection cleanup')
                try:self.ap.rollback()
                except (OSError,ValueError,ConnectionError) as rollback_error:
                    if self.router.blocked_config:self.router.install(self.router.blocked_config)
                    from .wifi_performance import diagnose
                    self.ap.failure=diagnose(exc);self.ap.failure['rollback_error']=str(rollback_error)[:1000]
                    self.ap.latch_recovery('AP rollback failed; driver/control health unverified')
                    self.last_error='AP rollback incomplete; LAN BLOCKED; '+str(exc)
                    self.last_action='RECOVERY_REQUIRED';self.persist()
                    raise ConnectionError(self.last_error) from None
                self.last_error = str(exc) if isinstance(exc,(ProfileError,ConnectionError)) else 'Backend unavailable or connectivity check failed'
                if ap_preparing:
                    from .wifi_performance import diagnose
                    self.ap.failure=diagnose(self.last_error)
                    operation=getattr(exc,'operation',None)
                    if operation:
                        self.ap.failure['operation']=operation
                        label={'mac_change':'MAC change','interface_down':'interface down','interface_up':'interface up','interface_mode':'interface mode change'}.get(operation['operation'],operation['operation'])
                        advice=' Try Keep current MAC or Restore hardware MAC; the requested MAC was not replaced.' if operation['operation']=='mac_change' else ' Check interface ownership and driver support; no global network service was stopped.'
                        if operation.get('errno') in (16,95):self.ap.failure.update(code='operation_busy' if operation['errno']==16 else 'operation_unsupported',message='Wi-Fi driver '+('refused ' if operation['errno']==16 else 'does not support ')+label+' on '+str(operation['interface'])+(' (EBUSY).' if operation['errno']==16 else ' (EOPNOTSUPP).')+advice)
                    self.ap.save()
                    self.last_error=self.ap.failure['message']
                self.last_check = {'status':'FAIL','error':self.last_error}
                (self.directory/'native-pending.json').unlink(missing_ok=True)
                self.last_action = 'APPLY_FAILED_PREVIOUS_PRESERVED'
                self.persist()
                error=ConnectionError(self.last_error)
                if not ap_preparing and hasattr(exc,'category'):error.category=exc.category
                raise error from None
            self.previous = self.current
            self.current = candidate
            self.pending = {'profile_id':identifier, 'deadline':time.time()+timeout}
            self.deadline_monotonic = time.monotonic()+timeout
            self.last_action = 'AWAITING_CONFIRMATION'
            try:
                self.persist()
            except OSError:
                self.router.rollback()
                self.current,self.previous=self.previous,None
                self.pending=None
                if candidate is not self.current:candidate.stop()
                self.ap.rollback()
                self.last_action='STORAGE_FAILED_PREVIOUS_PRESERVED'
                raise ConnectionError('Could not save connection state; previous connection restored') from None
            (self.directory/'native-pending.json').unlink(missing_ok=True)
            return self.status()

    def restore_confirmed(self,manual=False):
        """Restore confirmed AP independently of upstream availability.

        Boot confirms the upstream automatically; Retry retains Safe Apply.
        Only previously confirmed AP settings may be committed before VPN checks.
        """
        with self.lock:
            # A user transition/shutdown wins over the asynchronous boot worker.
            # Read persisted intent under the same lock as disconnect/confirm.
            if not manual and (self.closed or self.current or self.pending):return
            started=False
            try:
                if not self.confirmed_path.exists():raise ConnectionError('No confirmed router; choose Wi-Fi settings and Apply')
                saved=json.loads(self.confirmed_path.read_text())
                if not saved.get('enabled'):
                    if manual:raise ConnectionError('Saved router is disabled; use Apply to start it')
                    self.restore_state='DISABLED';return
                if manual and not saved.get('ap'):raise ConnectionError('Saved router is disabled; use Apply to start it')
                if manual:self.ap.claim_recovery(manual=True)
                started=True;self.restore_state='RESTORING'
                result=self.connect(saved['profile_id'],90 if manual else 60,
                    gateway_config=saved.get('gateway'),ap_config=saved.get('ap'),
                    manual_wifi_retry=False,_confirmed_ap=True)
                if manual:return result
                self.confirm();self.restore_state='RESTORED'
            except (OSError,ValueError,ConnectionError,ProfileError) as exc:
                if manual and not started:raise
                self.restore_state='BLOCKED';self.last_error='Восстановление роутера: '+str(exc)
                self.last_action='RESTORE_FAILED_BLOCKED'
                if self.router.blocked_config:self.router.install(self.router.blocked_config)
                self.persist()
                if manual:raise

    def test_dns(self,identifier,manual=None,wan=None,doh_url=None):
        from .dns_auto import select
        from .router import configuration
        from .admin import atomic_json
        import re
        if wan and (not isinstance(wan,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,15}',wan) or wan=='lo'):raise ConnectionError('Invalid WAN interface')
        with self.lock:
            profile=self.profiles.get(identifier);candidate=None;created=False
            current_wan=(getattr(self.current,'outbound_interface',None) or getattr(self.current,'resource',{}).get('wan')) if self.current else None
            if self.current and self.current.profile['id']==identifier and (not wan or current_wan==wan):candidate=self.current
            try:
                if candidate is None:
                    if self.current and profile['type'] in ('wireguard','openvpn'):
                        from .tunnels import same_native_identity
                        if same_native_identity(profile,self.current.profile):raise ConnectionError('Тестируй активный VPN или сначала отключи его: credentials совпадают')
                    if profile['type'] in ('direct','http','socks5'):
                        candidate=DirectBackend(profile) if profile['type']=='direct' else ProxyBackend(profile)
                        candidate.outbound_interface=wan
                    else:
                        from .tunnels import TunnelBackend
                        candidate=TunnelBackend(profile,self.directory,wan)
                        resources=[candidate.resource]+[self.current.resource] if self.current and hasattr(self.current,'resource') else [candidate.resource]
                        atomic_json(self.directory/'native-pending.json',{'native_resources':resources})
                    created=True
                    if hasattr(candidate,'start'):candidate.start()
                if doh_url:
                    from .router import DNSPolicy
                    check=DNSPolicy(configuration({'dns_mode':'doh','doh_url':doh_url}),lambda:candidate).check(candidate)
                    return dict(check,via=profile['type'])
                _,check=select(candidate,configuration({}),manual)
                return check
            except (OSError,ValueError,ConnectionError) as exc:
                return {'status':'FAIL','reason':str(exc),'attempts':getattr(exc,'attempts',[]),'resolver':None,'via':profile['type']}
            finally:
                if created and candidate:
                    candidate.stop();(self.directory/'native-pending.json').unlink(missing_ok=True)

    @connection_event
    def confirm(self):
        with self.lock:
            if not self.pending:
                raise ProfileError('No pending connection')
            if time.monotonic() >= self.deadline_monotonic:
                self.rollback('TIMEOUT_ROLLBACK')
                raise ProfileError('Confirmation deadline expired; rolled back')
            # Confirm only after another real probe; failures restore the previous backend.
            try:
                if self.ap.active:
                    self.ap.refresh_health(force=True)
                    if not self.ap.healthy():raise ConnectionError('AP driver/control health does not permit confirmation')
                self.last_check = self.current.request(self.current.last_check.get('url',self.check_url))
                self.current.last_check = self.last_check
                self.router.check(self.current)
                previous_record=self.confirmed_path.read_bytes() if self.confirmed_path.exists() else None
                from .admin import atomic_json
                confirmed_ap=dict(self.ap.active) if self.ap.active else None
                if confirmed_ap and confirmed_ap.get('mac_mode')=='keep' and confirmed_ap.get('mac_address'):
                    confirmed_ap['mac_mode']='manual' # Freeze the observed confirmed identity across reboot.
                atomic_json(self.confirmed_path,{'enabled':True,'profile_id':self.current.profile['id'],
                    'gateway':self.router.current.config if self.router.current else None,'ap':confirmed_ap})
                self.ap.confirm()
            except (OSError,ValueError,ConnectionError):
                if 'previous_record' in locals():
                    if previous_record is None:self.confirmed_path.unlink(missing_ok=True)
                    else:
                        from .admin import atomic_json
                        atomic_json(self.confirmed_path,json.loads(previous_record))
                self.rollback('CHECK_FAILED_ROLLBACK')
                raise ConnectionError('Confirmation probe failed; previous connection restored') from None
            self.router.confirm()
            if self.previous and self.previous is not self.current:
                self.previous.stop()
            self.previous = None
            self.pending = None
            self.last_action = 'CONFIRMED'
            self.persist()
            self.restore_state='SAVED'
            return self.status()

    @connection_event
    def rollback(self, reason='MANUAL_ROLLBACK'):
        with self.lock:
            if not self.pending:
                raise ProfileError('No pending connection')
            self.router.rollback()
            candidate = self.current
            self.current, self.previous = self.previous, None
            if candidate and candidate is not self.current:
                candidate.stop()
            try:
                self.ap.rollback()
                if self.ap.active and not self.ap.healthy():
                    raise ConnectionError('AP rollback control/driver health unverified')
            except (OSError,ValueError,ConnectionError):
                self.router.install(self.router.blocked_config)
                self.pending=None;self.last_action='RECOVERY_REQUIRED'
                self.ap.latch_recovery('AP rollback failed; driver/control health unverified')
                self.last_error='AP recovery failed; LAN BLOCKED';self.persist()
                raise ConnectionError(self.last_error) from None
            self.pending = None
            self.last_action = reason
            self.persist()
            return self.status()

    @connection_event
    def disconnect(self,preserve=False):
        with self.lock:
            if not preserve and getattr(self,'confirmed_path',None) and self.confirmed_path.exists():
                from .admin import atomic_json
                saved=json.loads(self.confirmed_path.read_text());saved['enabled']=False;atomic_json(self.confirmed_path,saved)
                self.restore_state='DISABLED'
            self.router.rollback()
            self.router.stop()
            for backend in (self.current,self.previous):
                if backend:
                    backend_evidence(self,backend,'disconnect requested')
                    backend.stop()
                    backend_evidence(self,backend,'disconnect completed')
            self.current = self.previous = None
            self.pending = None
            self.ap.stop()
            self.last_action = 'DISCONNECTED'
            self.persist()
            return self.status()

    def status(self):
        with self.lock:
            observed = self.current.observed() if self.current else {}
            live = self.current is not None
            unhealthy = live and not observed.get('alive',True)
            router_state=self.router.status()
            return {'restore':getattr(self,'restore_state','NOT CONFIGURED'),'ap':self.ap.public(),'state':('DEGRADED' if (unhealthy or self.ap.active and not self.ap.healthy() or getattr(self.current,'last_check',{}).get('status')=='FAIL' or router_state['state'] in ('DEGRADED','UNPROTECTED')) else 'CONNECTED') if live else 'DISCONNECTED', 'profile_id':self.current.profile['id'] if self.current else None,
                    'pending':self.pending, 'seconds_remaining':max(0,int(self.deadline_monotonic-time.monotonic())) if self.pending else None,
                    'last_action':self.last_action, 'last_error':self.last_error, 'last_check':self.last_check,
                    'observed':observed, 'router':router_state, 'active_check':getattr(self.current,'last_check',{'status':'NOT TESTED'}), 'proxy_url':f'http://127.0.0.1:{self.gateway.server_address[1]}',
                    'dns':{'mode':('LAN DNS '+self.router.current.config['dns_mode']+' via upstream') if self.router.current else 'remote destination resolution; no direct fallback',
                           'scope':'LAN DNS53 intercepted; host DNS unchanged' if self.router.current else 'Only applications using the PiRate proxy; host/LAN DNS unchanged' if not self.current or self.current.scope=='LOCAL_PROXY' else 'Tunnel namespace only; configured DNS and egress filter',
                           'whole_router_protection':self.router.current is not None, 'lan_gateway_enabled':self.router.current is not None, 'lan_kill_switch':self.router.blocked_config is not None,
                           'client_policy':('Explicit Direct NAT on selected LAN/WAN only' if self.current and self.current.profile['type']=='direct' else 'LAN DNS via selected upstream; direct LAN WAN forwarding DROP') if self.router.current else None},
                    'bytes_received':self.gateway.bytes_sent}

    def diagnostics(self, probe=False):
        with self.lock:
            if probe:
                if not self.current:
                    raise ProfileError('Connect a profile first')
                try:
                    self.router.check(self.current)
                    self.last_check = self.current.request(self.check_url)
                    self.current.last_check = self.last_check
                except (OSError,ValueError,ConnectionError):
                    self.last_check = {'status':'FAIL','error':'Active route probe failed; no direct fallback'}
                    self.current.last_check = self.last_check
            return {'connection':self.status(), 'host_routes':command('ip','-j','route','show'),
                    'host_addresses':command('ip','-j','address','show'),
                    'host_dns':[line.strip() for line in Path('/etc/resolv.conf').read_text().splitlines() if line.strip().startswith('nameserver')],
                    'router_scope':'LAN IPv4 TCP gateway with DNS interception/kill-switch' if self.router.current else 'Explicit proxy clients; AP addressing unchanged',
                    'fingerprint':{'host_ttl':Path('/proc/sys/net/ipv4/ip_default_ttl').read_text().strip(),
                                   'tcp_settings':{key:Path('/proc/sys/net/ipv4/'+key).read_text().strip() for key in ('tcp_timestamps','tcp_sack','tcp_window_scaling')},
                                   'observed_mac':{path.parent.name:path.read_text().strip() for path in Path('/sys/class/net').glob('*/address')},
                                   'scope':'Host observations; forwarded clients retain their own TCP/IP fingerprint',
                                   'claim':'Wi-Fi identity settings retained in Wi-Fi/LAN preview; no claim of matching a home PC'}}

    def close(self):
        if self.closed:return
        self.closed = True
        self.disconnect(preserve=True)
        self.router.close()
        if getattr(getattr(self,'support',None),'preflight',None):self.support.preflight.close()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.process_lock.close()
