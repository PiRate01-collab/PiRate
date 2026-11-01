"""Conservative AP radio plans and observed station telemetry."""
import re
import subprocess


def parse_radio(text):
    """Parse iw's split band dumps without treating a missing section as denial."""
    modes=re.search(r'Supported interface modes:[ \t]*\n((?:[ \t]+\*[^\n]*\n?)+)',text,re.I)
    ap=bool(re.search(r'^\s*\*\s+AP\s*$',modes[1],re.M)) if modes else None
    radios={};restricted=[]
    # Do not split on arbitrary whitespace: band/phy headings delimit scope.
    sections=re.split(r'(?mi)^[ \t]*Band[ \t]+\d+:[ \t]*$',text)[1:]
    if not sections:sections=[text]  # partial dump containing frequencies only
    for body in sections:
        ht=bool(re.search(r'HT20|HT RX|HT TX|HT Capabilities',body))
        known_ht=ht or bool(re.search(r'Capabilities:|Bitrates \(non-HT\)',body))
        entries=list(re.finditer(r'(?mi)^[ \t]*\*\s+(\d+(?:\.\d+)?)\s+MHz\s*\[\s*(\d+)\s*\]([^\n]*)',body))
        for i,entry in enumerate(entries):
            frequency=float(entry[1]);band='2.4' if 2400<=frequency<2500 else '5' if 4900<=frequency<5925 else None
            if not band:continue
            caps=radios.setdefault(band,{'ht':ht if known_ht else None,'ht40':'HT20/HT40' in body,'vht':'VHT Capabilities' in body,'legacy_b':bool(re.search(r'\*\s+(?:1\.0|2\.0|5\.5|11\.0)\s+Mbps',body)),'channels':[]})
            # Some iw versions put regulatory flags below the frequency line.
            tail=body[entry.end():entries[i+1].start() if i+1<len(entries) else len(body)]
            continuation=[]
            for line in tail.splitlines()[1:]:
                if not line.strip():continue
                if not re.match(r'\s*(?:\(|no[ -]|disabled|radar|DFS|passive)',line,re.I):break
                continuation.append(line.strip())
            flags=(entry[3]+' '+' '.join(continuation)).lower()
            row={'number':int(entry[2]),'frequency':frequency,'flags':flags}
            if re.search(r'disabled|no[ -]ir|radar|\bdfs\b|passive|no\s+20\s*mhz',flags):
                restricted.append(dict(row,band=band));caps['channels']=[c for c in caps['channels'] if c['number']!=row['number']];continue
            if not any(c['number']==row['number'] for c in caps['channels']):caps['channels'].append(row)
    ht=radios.get('2.4',{}).get('ht')
    return {'security':(['wpa2'] if '00-0f-ac:4' in text else [])+(['wpa3'] if 'SAE' in text and re.search(r'00-0f-ac:(6|11)\b',text) else []),'bands':radios,'restricted_channels':restricted,'ap_mode':ap,
            'capability_state':'supported' if ap is True and any(b['channels'] for b in radios.values()) else 'unsupported' if ap is False else 'incomplete',
            'ht_24ghz':ht,'driver_widths_24ghz_mhz':([20,40] if radios.get('2.4',{}).get('ht40') else [20]) if '2.4' in radios else [],
            'driver_advertised_modes':[mode for mode,marker in [('HT',r'HT20|HT RX|HT Capabilities'),('VHT','VHT Capabilities'),('HE',r'HE Iftypes|HE Capabilities')] if re.search(marker,text)],
            'configured_width_mhz':None,'hostapd_vht_he_verified':False}


def phy_interfaces(text):
    result={};phy=None
    for line in text.splitlines():
        found=re.match(r'\s*phy#(\d+)',line)
        if found:phy='phy'+found[1]
        found=re.match(r'\s*Interface\s+(\S+)',line)
        if found and phy:result[found[1]]=phy
    return result


def inspect_radio(interface,run):
    from pathlib import Path
    def read(*args):
        try:
            result=run(*args)
            return result.stdout if getattr(result,'returncode',0)==0 and isinstance(result.stdout,str) else ''
        except (OSError,RuntimeError,ValueError,AttributeError,subprocess.SubprocessError):return ''
    info=read('iw','dev',interface,'info')
    match=re.search(r'\bwiphy\s+(?:index:\s*)?(\d+)',info)
    phy='phy'+match[1] if match else None
    if not phy:
        try:
            target=(Path('/sys/class/net')/interface/'phy80211').resolve(strict=True).name
            if re.fullmatch(r'phy\d+',target):phy=target
        except OSError:pass
    devices=None
    if not phy:
        listing=read('iw','dev');devices=phy_interfaces(listing) if listing else None;phy=(devices or {}).get(interface)
    text=read('iw','phy',phy,'info') if phy else ''
    if phy and not text:
        # iw list may contain several radios. Never borrow another adapter's caps.
        dump=read('iw','list')
        match=re.search(r'(?ms)^Wiphy\s+'+re.escape(phy)+r'\s*\n(.*?)(?=^Wiphy\s|\Z)',dump)
        text=match[1] if match else ''
    radio=parse_radio(text)
    radio.update(phy=phy,interface=interface,observed_at=__import__('time').time(),
                 present=(True if info or phy else None) if devices is None else interface in devices,
                 inspection_error=None if text else 'Radio inspection incomplete; hostapd will validate a conservative AP attempt')
    return radio


def diagnose(error):
    detail=str(error)
    cases=[('resource_ownership',r'pirate_gateway table.*(?:another runtime|not owned)|Router saved ownership invalid',
            'LAN firewall ownership conflict. Existing resources were left unchanged; use the owning PiRate data directory and stop its previous process before recovery.'),
           ('missing',r'No such device|disappeared|not present','Wi-Fi adapter disconnected. Connect it or select another interface.'),
           ('operation_busy',r'Device or resource busy|\bEBUSY\b','Wi-Fi driver refused an interface operation. See operation details; check ownership or use a supported MAC/mode.'),
           ('busy',r'owned by|ownership is unconfirmed|busy|already has IPv4|уже имеет IPv4|используется|carries SSH','Wi-Fi interface is busy. Select a free adapter or release its existing connection.'),
           ('ap_unsupported',r'does not support AP|AP mode.*not supported','AP mode is not supported by this Linux driver. Try another adapter or driver/firmware.'),
           ('regulatory',r'regulat|no.ir|restricted|DFS|country','Channel is restricted by the current country/driver. Choose Auto or another permitted channel.'),
           ('unsupported_mode',r'Unsupported.*(?:width|channel|band)|HT|VHT|frequency|channel','Cannot start the selected Wi-Fi mode. Try Auto or another permitted band/channel.'),
           ('driver_firmware',r'firmware|nl80211|driver','Wi-Fi driver/firmware could not start AP. Reconnect the adapter or check the driver.'),
           ('incomplete',r'capabilities|inspection|ACS','Radio information is incomplete. Try Auto; hostapd must confirm an allowed AP mode.')]
    for code,pattern,message in cases:
        if re.search(pattern,detail,re.I):return {'code':code,'message':message,'detail':detail}
    return {'code':'startup_failure','message':'Wi-Fi could not start. Check the adapter and try Auto.','detail':detail}


def stations(text):
    result=[]
    for mac,body in re.findall(r'Station ([0-9a-fA-F:]{17})[^\n]*\n(.*?)(?=Station |\Z)',text,re.S):
        signal=re.search(r'signal:\s*(-?\d+)',body)
        item={'mac':mac.lower(),'signal_dbm':int(signal[1]) if signal else None}
        for direction in ('tx','rx'):
            rate=re.search(direction+r' bitrate:\s*([\d.]+)\s*MBit/s([^\n]*)',body)
            flags=rate[2] if rate else ''
            mode='HE' if 'HE-MCS' in flags else 'VHT' if 'VHT-MCS' in flags else 'HT' if re.search(r'\bMCS\s+\d+',flags) else None
            width=re.search(r'\b(20|40|80|160|320)MHz\b',flags)
            item.update({direction+'_mbps':float(rate[1]) if rate else None,direction+'_mode':mode,
                         direction+'_width_mhz':int(width[1]) if width else None})
        result.append(item)
    return result


def _band_plans(value, reported):
    """Conservative non-DFS plans. All constituent channels must allow initiation."""
    from .proxy import ConnectionError
    bands=reported.get('bands',{})
    band=value.get('band','auto')
    channel=value['channel']
    if band=='auto':
        band=('2.4' if channel and channel<=14 else '5') if channel else ('5' if bands.get('5',{}).get('channels') else '2.4')
    caps=bands.get(band)
    if not caps:
        # Unknown is not unsupported. ACS delegates selection to hostapd/nl80211;
        # never invent a permitted channel or enable wide modes from missing data.
        if bands:raise ConnectionError('Unsupported band '+band+' GHz')
        if str(value.get('width','auto')) not in ('auto','20'):raise ConnectionError('Unsupported width with incomplete capabilities')
        lines=f"hw_mode={'a' if band=='5' else 'g'}\nchannel={channel}\n"
        return [{'band':band,'channel':channel,'width_mhz':20,'configuration_mode':'legacy','directives':lines}]

    allowed={c['number']:c['flags'] for c in caps['channels']}
    if not channel:channel=36 if band=='5' and 36 in allowed else next(iter(allowed),0)
    if channel not in allowed:raise ConnectionError('Unsupported or restricted AP channel for '+band+' GHz')
    widths=[20]
    secondary=None;center=None
    if caps['ht'] and caps['ht40']:
        pairs=[(base,base+4) for base in (36,44,52,60,100,108,116,124,132,140,149,157,165)]
        candidates=[channel+4,channel-4] if band=='2.4' else [b if channel==a else a for a,b in pairs if channel in (a,b)]
        for other in candidates:
            sign='+' if other>channel else '-'
            if other in allowed and 'no ht40'+sign not in allowed[channel] and 'no ht40'+('+' if sign=='-' else '-') not in allowed[other]:
                secondary=sign;widths.append(40);break
    if band=='5' and caps['vht'] and secondary:
        for base in (36,52,100,116,132,149):
            block=list(range(base,base+13,4))
            if channel in block and all(c in allowed and 'no 80mhz' not in allowed[c] for c in block):center=base+6;widths.append(80);break
    if band=='2.4' and channel==14:
        if str(value.get('width','auto')) not in ('auto','20'):raise ConnectionError('Unsupported width on channel 14')
        return [{'band':band,'channel':channel,'width_mhz':20,'configuration_mode':'legacy-b','directives':'hw_mode=b\nchannel=14\n'}]
    requested=value.get('width','auto')
    if requested!='auto' and int(requested) not in widths:raise ConnectionError('Unsupported channel width for selected AP channel')
    maximum=max(widths) if requested=='auto' else int(requested)
    result=[]
    for width in sorted((w for w in widths if w<=maximum),reverse=True):
        ht=caps['ht'] is not False;vht=band=='5' and caps['vht'] and ht
        modes=[(ht,vht)]
        if vht and width<=40:modes.append((True,False))
        if ht and width==20:modes.append((False,False))
        for use_ht,use_vht in modes:
            lines=f"hw_mode={'a' if band=='5' else 'g'}\nchannel={channel}\n"
            if use_ht:lines+='ieee80211n=1\n'
            if width>=40:lines+='ht_capab=[HT40'+secondary+']\n'
            if use_vht:
                lines+='ieee80211ac=1\nvht_oper_chwidth='+('1' if width==80 else '0')+'\n'
                if width==80:lines+='vht_oper_centr_freq_seg0_idx='+str(center)+'\n'
            result.append({'band':band,'channel':channel,'width_mhz':width,'configuration_mode':('VHT' if use_vht else 'HT' if use_ht else 'legacy')+(str(width) if use_ht else ''),'directives':lines})
    if band=='2.4' and caps.get('legacy_b'):
        result.append({'band':band,'channel':channel,'width_mhz':20,'configuration_mode':'legacy-b','directives':f'hw_mode=b\nchannel={channel}\n'})
    return result


def plans(value,reported):
    from .proxy import ConnectionError
    if reported.get('ap_mode') is False:raise ConnectionError('AP mode is not supported by this Linux driver')
    if reported.get('present') is False:raise ConnectionError('Wi-Fi adapter not present or inspection unavailable; reconnect or refresh')
    band=value.get('band','auto');channel=value['channel'];bands=reported.get('bands',{})
    names=[band] if band!='auto' else [('2.4' if channel<=14 else '5')] if channel else ['5','2.4']
    result=[];errors=[]
    for name in names:
        caps=bands.get(name)
        if band=='auto' and bands and (not caps or not caps.get('channels')):continue
        channels=[channel] if channel or not caps else [c['number'] for c in caps['channels']]
        if name=='5' and not channel:channels.sort(key=lambda c:(c!=36,c))
        for selected in channels:
            try:result.extend(_band_plans(dict(value,band=name,channel=selected),reported))
            except ConnectionError as exc:errors.append(exc)
    if not result:raise errors[0] if errors else ConnectionError('No permitted AP channel; regulatory restrictions or incomplete channel data')
    return result  # finite: one pass over current channels/modes, no repeated plan


def observed_ap(text):
    match=re.search(r'channel\s+(\d+)\s+\((\d+(?:\.\d+)?) MHz\),\s*width:\s*(\d+) MHz',text)
    return {'channel':int(match[1]),'band':'5' if float(match[2])>=4900 else '2.4','width_mhz':int(match[3])} if match else {}
