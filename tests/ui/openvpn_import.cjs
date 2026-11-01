'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const ui=require('../../web/openvpn_import.js');
function node(){return {value:'',textContent:'',disabled:false,hidden:false,checked:false,children:[],childNodes:[],options:[],dataset:{},classList:{toggle(){},add(){},remove(){}},listeners:{},addEventListener(k,v){this.listeners[k]=v;},replaceChildren(...v){this.children=v;this.options=v;},append(...v){this.children.push(...v);},click(){},querySelector:()=>node(),selectedOptions:[],ownerDocument:{createElement:()=>node()},scrollIntoView(){},checkValidity:()=>true,reportValidity(){}};}
function form(){const f=node();f.elements={};for(const k of ['name','type','server','port','username','password','config','ovpn_proto','ovpn_remote','ovpn_server_name','dns_servers','wg_address','wg_peer_key','wg_allowed_ips','wg_private_key','wg_preshared_key','wg_mtu','wg_keepalive'])f.elements[k]=node();f.reset=()=>{for(const n of Object.values(f.elements))n.value='';f.elements.type.value='direct';};return f;}
const draft={draft_id:'opaque-owner-draft',version:1,status:'needs_user_input',connectivity:'NOT_TESTED',confirmation_required:false,required_fields:['username','password'],profile:{name:'Customer',type:'openvpn',server:'a.test',port:1194,config:'client\n<key>\n[PiRate secret retained]\n</key>\n',profile_version:1,import_encoding:'utf-8',dns_servers:['10.8.0.1'],ovpn_remote:0,ovpn_proto:'udp'},remotes:[{server:'a.test',port:1194,proto:'udp'},{server:'b.test',port:443,proto:'tcp-client'}],diagnostics:[{line:8,directive:'float',classification:'safely_normalized',message:'Endpoint pinned.'}]};
function environment(result=draft){
 const nodes={};const get=id=>nodes[id]||(nodes[id]=node());nodes['profile-form']=form();nodes['profile-type']=nodes['profile-form'].elements.type;
 const calls=[],timers=[];const context={location:{hash:''},confirm:()=>true,document:{getElementById:get,querySelectorAll:()=>[],createElement:()=>node()},PiRateOpenVPN:ui,console,setInterval(fn,ms){timers.push({fn,ms});},clearInterval(){},setTimeout,URL,TextDecoder,btoa,Uint8Array,fetch:()=>new Promise(()=>{})};
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../web/mvp.js'),'utf8'),context);
 const actualRefresh=vm.runInContext('refresh',context);vm.runInContext('refresh=async()=>{}',context);
 context.fetch=async(url,options={})=>{calls.push([url,options]);return {ok:true,json:async()=>url.endsWith('/convert-config')?result:url.endsWith('/editor')?{config:draft.profile.config,ovpn_server_name:'server'}:{id:'saved-id'}};};
 async function upload(name='a.ovpn'){get('import-file').listeners.change({target:{files:[{name,size:2,arrayBuffer:async()=>Buffer.from([65,66])}],value:name}});await new Promise(setImmediate);}
 async function submit(){const f=get('profile-form');f.listeners.submit({preventDefault(){},currentTarget:f});await new Promise(setImmediate);}
 return {get,context,calls,timers,upload,submit,actualRefresh};
}

test('public connection list excludes removed protocol',()=>{
 const markup=fs.readFileSync('web/mvp.html','utf8');assert.ok(!markup.includes('value="pptp"'));
 assert.ok(markup.includes('https://t.me/pirate_open'));assert.ok(markup.includes('rel="noopener noreferrer"'));
});

test('upload sends exact bytes and encoding to unified analyze without saving',async()=>{
 const calls=[];const bytes=Buffer.from([255,254,99,0]);await ui.upload({name:'input.ovpn',size:bytes.length,arrayBuffer:async()=>bytes},'utf-16',async(...a)=>calls.push(a));
 assert.equal(calls[0][0],'convert-config');assert.deepEqual(Buffer.from(calls[0][2].file_base64,'base64'),bytes);assert.equal(calls[0][2].encoding,'utf-16');
});
test('upload autofills -> missing credentials -> Save only -> explicit Connect -> Confirm',async()=>{
 const e=environment();await e.upload();assert.equal(e.calls.length,1);assert.equal(e.get('profile-form').elements.config.value,draft.profile.config);assert.equal(e.get('profile-save').textContent,'Сохранить профиль');
 assert.equal(e.get('username-field').hidden,false);assert.equal(e.get('password-field').hidden,false);assert.equal(e.get('form-title').textContent,'Добавить подключение');
 const f=e.get('profile-form');await e.submit();assert.equal(e.calls.length,1);assert.match(e.get('message').textContent,/логин/);
 f.elements.username.value='owner';await e.submit();assert.equal(e.calls.length,1);assert.match(e.get('message').textContent,/пароль/);
 f.elements.password.value='provided';e.get('ovpn-remote-select').value='1';e.get('ovpn-remote-select').listeners.change();await e.submit();
 const body=JSON.parse(e.calls[1][1].body);assert.equal(body.converter_draft,draft.draft_id);assert.equal(body.server,'b.test');assert.equal(body.ovpn_remote,1);assert.equal(body.password,'provided');
 assert.equal(e.calls.length,2);e.get('connect').listeners.click();await new Promise(setImmediate);assert.equal(e.calls[2][0],'/api/mvp/router-apply');assert.equal(JSON.parse(e.calls[2][1].body).profile_id,'saved-id');
 e.get('confirm').listeners.click();await new Promise(setImmediate);assert.equal(e.calls[3][0],'/api/mvp/confirm');
});
test('incompatible input shows the precise reason and never saves or connects',async()=>{
 const e=environment({...draft,status:'incompatible_server',required_fields:[],reason:'В файле нет безопасного TLS-шифра.'});await e.upload();assert.equal(e.get('profile-form').elements.config.value,draft.profile.config);assert.match(e.get('message').textContent,/TLS/);await e.submit();assert.equal(e.calls.length,1);
});
test('complete inline credentials are retained privately without asking again',async()=>{
 const e=environment({...draft,status:'convertible',required_fields:[],profile:{...draft.profile,username_saved:true,password_saved:true}});await e.upload();assert.equal(e.get('username-field').hidden,true);assert.equal(e.get('password-field').hidden,true);await e.submit();assert.equal(e.calls[1][0],'/api/mvp/profiles');assert.equal(e.calls.length,2);
});
test('WireGuard remains upload/autofill -> save with editable MTU and keys retained server-side',async()=>{
 const wg={...draft,status:'convertible',required_fields:[],remotes:[],profile:{name:'WG',type:'wireguard',server:'wg.test',port:51820,wg_peer_key:'public-key',wg_address:['10.7.0.2/24'],wg_allowed_ips:['0.0.0.0/0'],wg_mtu:1380,wg_keepalive:25,dns_servers:['10.7.0.1'],config:''}};
 const e=environment(wg);await e.upload('wg.conf');const f=e.get('profile-form');assert.equal(f.elements.wg_private_key.value,'');assert.equal(f.elements.wg_mtu.value,'1380');await e.submit();const body=JSON.parse(e.calls[1][1].body);assert.equal(body.wg_mtu,1380);assert.equal(body.wg_private_key,undefined);assert.equal(e.calls.length,2);
});
test('failed save preserves redacted draft and user supplied secrets',async()=>{
 const e=environment();await e.upload();e.context.fetch=async()=>({ok:false,json:async()=>({error:'Explicit credentials required'})});e.get('profile-form').elements.username.value='owner';e.get('profile-form').elements.password.value='supplied';await e.submit();assert.equal(e.get('profile-form').elements.config.value,draft.profile.config);assert.equal(e.get('profile-form').elements.password.value,'supplied');assert.match(e.get('message').textContent,/логин|пароль/);
});
test('private editor uses opaque blocks; dashboard polling cannot overwrite active editor',async()=>{
 const e=environment();await vm.runInContext("edit({id:'existing',name:'saved',type:'openvpn',server:'a.test',port:1194})",e.context);assert.equal(e.get('profile-form').elements.config.value,draft.profile.config);
 e.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/profiles')?{profiles:[]}:url.endsWith('/dashboard')?{state:'DISCONNECTED',internet:{status:'UNKNOWN'},system:{},error:'Old runtime failure'}:{interfaces:[],wifi:{}}});
 vm.runInContext("loaded=true;devicesDigest='[]';refreshing=false;message('Current draft')",e.context);await e.actualRefresh();assert.equal(e.get('message').textContent,'Current draft');
});
test('oversize uploads and decode errors remain explicit',async()=>{
 await assert.rejects(()=>ui.upload({size:ui.MAX_UPLOAD+1},'',async()=>{}),/256 KiB/);
 await assert.rejects(()=>ui.upload({size:1,name:'bad.ovpn',arrayBuffer:async()=>Buffer.from([255])},'',async()=>{throw Error('Known encoding required');}),/encoding/);
});

test('editing saved WireGuard retains editable MTU/keepalive and cannot test an unsaved draft',async()=>{
 const e=environment();await vm.runInContext("edit({id:'saved',name:'WG',type:'wireguard',server:'wg.test',port:51820,wg_mtu:1380,wg_keepalive:25,wg_address:['10.7.0.2/24'],wg_allowed_ips:['0.0.0.0/0'],wg_peer_key:'public-key'})",e.context);
 e.get('profile-form').elements.wg_mtu.value='1400';e.get('profile-form').elements.wg_keepalive.value='30';await e.submit();
 const body=JSON.parse(e.calls[0][1].body);assert.equal(body.wg_mtu,1400);assert.equal(body.wg_keepalive,30);assert.equal(e.calls[0][1].method,'PUT');
});

test('connection failure leaves saved profile selected and never falls back to Direct',async()=>{
 const e=environment({...draft,status:'convertible',required_fields:[]});await e.upload();await e.submit();assert.equal(e.calls.length,2);
 e.context.fetch=async(url,options={})=>{e.calls.push([url,options]);return {ok:false,json:async()=>({error:'private diagnostic code',message:'VPN-сервер недоступен.'})};};
 e.get('connect').listeners.click();await new Promise(setImmediate);assert.match(e.get('message').textContent,/недоступен/);assert.equal(vm.runInContext('chosen',e.context),'saved-id');assert.equal(e.calls.length,3);assert.equal(e.get('connection-error-detail').textContent,'private diagnostic code');
 e.get('connect').listeners.click();await new Promise(setImmediate);assert.equal(e.calls[3][0],'/api/mvp/router-apply');assert.equal(JSON.parse(e.calls[3][1].body).profile_id,'saved-id');
});
test('primary markup has no converter wizard controls and retains expandable details',()=>{
 const html=fs.readFileSync(path.join(__dirname,'../../web/mvp.html'),'utf8');assert.doesNotMatch(html,/id="converter-(auto|confirm|test)"/);assert.doesNotMatch(html,/Auto-convert|Upload → Analyze|Show changes/);assert.match(html,/<details[^>]*>[\s\S]*connection-error-detail/);assert.match(html,/id="profile-save"/);
});

test('local OpenVPN policy rejection requires input and cannot save or connect',async()=>{
 const e=environment({...draft,status:'needs_user_input',save_allowed:false,error_kind:'local_security_policy',required_fields:['username','password'],reason:'Локальный предел PiRate; сервер ещё не проверен.'});
 await e.upload();assert.match(e.get('message').textContent,/Локальный/);assert.match(e.get('ovpn-import-info').textContent,/отклонён локально/);await e.submit();assert.equal(e.calls.length,1);assert.match(e.get('message').textContent,/Локальный/);
});

test('proxy credentials reappear after importing OpenVPN with inline authentication',async()=>{
 const e=environment({...draft,required_fields:[]});await e.upload();assert.equal(e.get('username-field').hidden,true);
 e.get('profile-type').value='socks5';e.get('profile-type').listeners.change();assert.equal(e.get('username-field').hidden,false);assert.equal(e.get('password-field').hidden,false);assert.equal(e.get('profile-type').value,'socks5');
 const f=e.get('profile-form');f.elements.name.value='Proxy';f.elements.server.value='offline.test';f.elements.port.value='1080';f.elements.username.value='owner';f.elements.password.value='secret';await e.submit();assert.equal(e.calls.length,2);const body=JSON.parse(e.calls[1][1].body);assert.equal(body.type,'socks5');assert.equal(body.username,'owner');assert.equal(body.password,'secret');assert.equal(body.converter_draft,undefined);
});
test('editing proxy with blank password preserves server-side secret by omission',async()=>{
 const e=environment();await vm.runInContext("edit({id:'proxy',name:'Proxy',type:'http',server:'offline.test',port:8080,password_saved:true})",e.context);await e.submit();const body=JSON.parse(e.calls[0][1].body);assert.equal(body.password,undefined);assert.equal(e.calls[0][1].method,'PUT');assert.equal(e.calls.length,1);
});
test('pending confirmation blocks repeated connection requests',async()=>{
 const e=environment();vm.runInContext("pending=true",e.context);e.get('connect').listeners.click();await new Promise(setImmediate);assert.equal(e.calls.length,0);assert.match(e.get('message').textContent,/Подтвердите/);
});
test('security normalization requires explicit consent before saving the imported draft',async()=>{
 const e=environment({...draft,required_fields:[],confirmation_required:true});await e.upload();await e.submit();assert.equal(e.calls.length,1);e.get('import-consent').checked=true;await e.submit();assert.equal(e.calls.length,2);assert.equal(JSON.parse(e.calls[1][1].body).converter_confirmed,true);
});

test('reload uses server state for pending confirmation and unverified client internet',async()=>{
 const e=environment();
 e.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/profiles')?{profiles:[{id:'saved',name:'VPN',type:'openvpn'}]}:url.endsWith('/dashboard')?{state:'CONNECTED',profile:{name:'VPN',type:'openvpn'},internet:{status:'UNVERIFIED'},system:{},ap:'DISABLED',pending:'pending-token',seconds_remaining:40,restore:'SAVED'}:{interfaces:[],wifi:{},profile_id:'saved'}});
 vm.runInContext("refreshing=false",e.context);await e.actualRefresh();assert.equal(e.get('live-state').textContent,'Ожидает подтверждения');assert.equal(e.get('internet-state').textContent,'Интернет клиентов не проверен');assert.equal(vm.runInContext('chosen',e.context),'saved');assert.equal(e.get('connect').disabled,true);assert.match(e.get('countdown').textContent,/40/);
});
test('loss of backend clears stale positive internet and IP readings',()=>{
 const e=environment();e.get('internet-state').textContent='Есть подключение';e.get('external-ip').textContent='198.51.100.1';vm.runInContext("offline(new Error('Нет связи'))",e.context);assert.equal(e.get('internet-state').textContent,'Нет актуальных данных');assert.equal(e.get('external-ip').textContent,'Нет актуальных данных');assert.equal(e.get('live-state').textContent,'Нет связи с роутером');
});
test('clear proxy authentication is explicit and sends null only when requested',async()=>{
 const e=environment();await vm.runInContext("edit({id:'proxy',name:'Proxy',type:'http',server:'offline.test',port:8080,username:'owner',password_saved:true})",e.context);e.get('clear-auth').checked=true;await e.submit();const body=JSON.parse(e.calls[0][1].body);assert.equal(body.username,'');assert.equal(body.password,null);
});
test('rollback and disconnect call the existing safe management operations',async()=>{
 const e=environment();for(const name of ['rollback','disconnect']){e.get(name).listeners.click();await new Promise(setImmediate);}assert.deepEqual(e.calls.map(x=>x[0]),['/api/mvp/rollback','/api/mvp/disconnect']);
});

test('dashboard reflects backend checking, failure and blocked states without positive internet claims',async()=>{
 for(const [state,internet,restore,expected] of [['CHECKING','UNKNOWN','NOT CONFIGURED','Подключаемся…'],['DEGRADED','FAIL','SAVED','Ошибка подключения'],['DISCONNECTED','DISCONNECTED','BLOCKED','Трафик заблокирован'],['CONNECTED','UNKNOWN','SAVED','Подключение активно · интернет не подтверждён']]){
  const e=environment();e.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/profiles')?{profiles:[]}:url.endsWith('/dashboard')?{state,internet:{status:internet},restore,system:{},ap:'DISABLED'}:{interfaces:[],wifi:{}}});vm.runInContext('refreshing=false',e.context);await e.actualRefresh();assert.equal(e.get('live-state').textContent,expected);assert.notEqual(e.get('internet-state').textContent,'Есть подключение');
 }
});

test('new profile reset clears saved-secret placeholders from a previous editor',async()=>{
 const e=environment();await vm.runInContext("edit({id:'old',name:'Old',type:'http',server:'a.test',port:8080,password_saved:true})",e.context);
 assert.match(e.get('profile-form').elements.password.placeholder,/Сохранён/);
 e.get('cancel-edit').listeners.click();assert.doesNotMatch(e.get('profile-form').elements.password.placeholder,/Сохранён/);
});

test('pending actions lock forms and buttons, then restore interaction',async()=>{
 const e=environment();const f=e.get('profile-form'),button=e.get('connect');
 e.context.document.querySelectorAll=selector=>selector==='form'?[f]:selector==='button'?[button]:[];
 const pending=vm.runInContext('action(()=>new Promise(resolve=>{globalThis.releaseAction=resolve;}))',e.context);
 assert.equal(f.inert,true);assert.equal(button.disabled,true);assert.match(e.get('message').textContent,/Выполняем/);
 e.context.releaseAction();await pending;assert.equal(f.inert,false);
});

test('Wi-Fi Save persists AP settings only, independently of VPN selection',async()=>{
 const e=environment();vm.runInContext("chosen='vpn-original'",e.context);
 for(const [id,value] of Object.entries({'ap-name':'Home','wifi-interface':'wlan1','wifi-ssid':'Home SSID','wifi-password':'private-wifi','wifi-security':'wpa2','wifi-country':'DE','wifi-band':'2.4','wifi-channel':'6','wifi-width':'20','mac-mode':'keep','mac-address':'','wifi-fingerprint':'default'}))e.get(id).value=value;
 e.get('wifi-form').listeners.submit({preventDefault(){}});await new Promise(setImmediate);
 assert.equal(e.calls.length,1);assert.equal(e.calls[0][0],'/api/mvp/ap-profiles');
 const body=JSON.parse(e.calls[0][1].body);assert.equal(body.name,'Home');assert.equal(body.wifi.ssid,'Home SSID');assert.equal(body.wifi.password,'private-wifi');assert.equal(body.profile_id,undefined);
 assert.equal(vm.runInContext('chosen',e.context),'vpn-original');assert.equal(e.get('wifi-password').value,'');
});
test('Wi-Fi Apply uses its own saved ID and no VPN or draft settings',async()=>{
 const e=environment();vm.runInContext("chosen='different-vpn';apSelected='saved-ap'",e.context);
 e.get('ap-apply').listeners.click();await new Promise(setImmediate);
 assert.equal(e.calls[0][0],'/api/mvp/ap-profiles/saved-ap/apply');assert.deepEqual(JSON.parse(e.calls[0][1].body),{});assert.equal(vm.runInContext('chosen',e.context),'different-vpn');
});
test('AP editor retains hidden password and offline adapter/channel values',async()=>{
 const e=environment();vm.runInContext("editAP({id:'saved-ap',name:'Offline AP',password_saved:true,wifi:{interface:'unplugged0',ssid:'Offline',security:'wpa3',country:'DE',channel:149,band:'5',width:'80',mac_mode:'manual',mac_address:'02:11:22:33:44:55',fingerprint:'ttl64'}})",e.context);
 assert.equal(e.get('wifi-password').value,'');assert.equal(e.get('wifi-interface').value,'unplugged0');assert.equal(e.get('wifi-channel').value,'149');assert.equal(e.get('wifi-width').value,'80');
 e.get('wifi-form').listeners.submit({preventDefault(){}});await new Promise(setImmediate);
 assert.equal(e.calls[0][1].method,'PUT');assert.equal(e.calls[0][0],'/api/mvp/ap-profiles/saved-ap');assert.equal(JSON.parse(e.calls[0][1].body).wifi.password,'');
});
test('switching VPN retains active AP and ignores selected inactive AP and unsaved Wi-Fi draft',async()=>{
 const e=environment();vm.runInContext("chosen='new-vpn';apSelected='inactive-ap';apState={active_present:true,active_id:'active-ap'};serverWifi={interface:'wlan1',ssid:'Live'}",e.context);
 e.get('wifi-ssid').value='Unsaved edit';e.get('connect').listeners.click();await new Promise(setImmediate);
 const body=JSON.parse(e.calls[0][1].body);assert.equal(body.profile_id,'new-vpn');assert.equal(body.wifi_profile_id,'active-ap');assert.equal(body.wifi,undefined);
});
test('legacy active AP keeps observed settings on VPN switch instead of inactive saved profile',async()=>{
 const e=environment();vm.runInContext("chosen='new-vpn';apSelected='inactive';apState={active_present:true};serverWifi={interface:'wlan1',ssid:'Live'}",e.context);
 e.get('connect').listeners.click();await new Promise(setImmediate);const body=JSON.parse(e.calls[0][1].body);assert.equal(body.wifi_profile_id,undefined);assert.equal(body.wifi.ssid,'Live');
});
test('AP protected edit/delete buttons remain disabled after loading ends',()=>{
 const e=environment();const b=node();b.dataset.apProtected='true';e.context.document.querySelectorAll=selector=>selector==='button'?[b]:[];
 vm.runInContext('buttons()',e.context);assert.equal(b.disabled,true);
});

test('new AP resets inherited live manual radio settings to real Auto values and suggests capable interface',async()=>{
 const e=environment();vm.runInContext("serverWifi={interface:'wlan0',ssid:'Live',country:'DE',band:'2.4',channel:6,width:'40'};wifiDevices=[{name:'wlan0',kind:'wifi',capabilities:{ap_mode:false}},{name:'uplink',kind:'wifi',default_route:true,capabilities:{ap_mode:true}},{name:'wlan1',kind:'wifi',capabilities:{ap_mode:true,radio:{present:true,bands:{}}}}]",e.context);
 e.get('ap-new').listeners.click();assert.equal(e.get('wifi-interface').value,'wlan1');assert.equal(e.get('wifi-band').value,'auto');assert.equal(e.get('wifi-channel').value,'0');assert.equal(e.get('wifi-width').value,'auto');assert.equal(e.get('wifi-country').value,'DE');assert.equal(e.calls.length,0);
 e.get('ap-name').value='Auto AP';e.get('wifi-password').value='private-wifi';e.get('wifi-form').listeners.submit({preventDefault(){}});await new Promise(setImmediate);
 const body=JSON.parse(e.calls[0][1].body);assert.equal(e.calls[0][0],'/api/mvp/ap-profiles');assert.equal(body.wifi.band,'auto');assert.equal(body.wifi.channel,0);assert.equal(body.wifi.width,'auto');assert.equal(e.calls.length,1);
});
test('initial new-profile form uses Auto instead of live settings and a capable adapter',async()=>{
 const e=environment();const caps={ap_mode:true,radio:{present:true,bands:{'5':{channels:[{number:36,widths:[20]}]}}}};
 e.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/profiles')?{profiles:[]}:url.endsWith('/dashboard')?{state:'DISCONNECTED',internet:{status:'DISCONNECTED'},system:{},ap:'DISABLED'}:url.endsWith('/ap-profiles')?{profiles:[]}:url.endsWith('/ap-capabilities')?caps:{interfaces:[{name:'wlan0',kind:'wifi',capabilities:{ap_mode:false}},{name:'wlan1',kind:'wifi',capabilities:caps},{name:'eth0',kind:'ethernet',default_route:true}],wan_interface:'eth0',wifi:{interface:'wlan0',country:'DE',band:'2.4',channel:6,width:'40'}}});
 vm.runInContext('refreshing=false',e.context);await e.actualRefresh();assert.equal(e.get('wifi-interface').value,'wlan1');assert.equal(e.get('wifi-band').value,'auto');assert.equal(e.get('wifi-channel').value,'0');assert.equal(e.get('wifi-width').value,'auto');assert.equal(e.get('wifi-country').value,'DE');
});
test('new AP never suggests a known unsupported, absent, or WAN adapter',()=>{
 const e=environment();vm.runInContext("serverWifi={interface:'absent',country:'DE'};wifiDevices=[{name:'absent',kind:'wifi',capabilities:{ap_mode:true,radio:{present:false}}},{name:'unsupported',kind:'wifi',capabilities:{ap_mode:false}},{name:'wan',kind:'wifi',default_route:true,capabilities:{ap_mode:true}}];newAP()",e.context);
 assert.equal(e.get('wifi-interface').value,'');assert.equal(e.get('wifi-band').value,'auto');
 vm.runInContext("wifiDevices.push({name:'unknown',kind:'wifi'});newAP()",e.context);assert.equal(e.get('wifi-interface').value,'unknown');
});
test('editing and capability refresh preserve saved manual radio settings instead of resetting Auto',()=>{
 const e=environment();const width=e.get('wifi-width');width.options=['auto','20','40','80'].map(value=>Object.assign(node(),{value}));width.querySelector=selector=>width.options.find(o=>selector.includes('"'+o.value+'"'));Object.defineProperty(width,'selectedOptions',{get(){return width.options.filter(o=>o.value===width.value);}});
 vm.runInContext("wifiDevices=[{name:'wlan1',kind:'wifi',capabilities:{ap_mode:true,radio:{bands:{'2.4':{channels:[{number:6,widths:[20]}]}}}}}];editAP({id:'manual',name:'Saved',wifi:{interface:'wlan1',country:'DE',ssid:'Manual',band:'5',channel:149,width:'80'}})",e.context);
 vm.runInContext("renderRadio({ap_mode:true,radio:{bands:{'2.4':{channels:[{number:6,widths:[20]}]}}}})",e.context);
 assert.equal(e.get('wifi-band').value,'5');assert.equal(e.get('wifi-channel').value,'149');assert.equal(e.get('wifi-width').value,'80');assert.equal(e.get('wifi-country').value,'DE');
 assert.ok(e.get('wifi-channel').options.some(o=>o.value==='149'));assert.equal(e.calls.length,0);
});

test('creating an AP before discovery finishes still receives a capable interface without losing Auto',async()=>{
 const e=environment();e.get('ap-new').listeners.click();const caps={ap_mode:true,radio:{present:true,bands:{}}};
 e.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/profiles')?{profiles:[]}:url.endsWith('/dashboard')?{state:'DISCONNECTED',internet:{status:'DISCONNECTED'},system:{},ap:'DISABLED'}:url.endsWith('/ap-profiles')?{profiles:[]}:{interfaces:[{name:'wlan0',kind:'wifi',capabilities:{ap_mode:false}},{name:'wlan1',kind:'wifi',capabilities:caps}],wifi:{interface:'wlan0',band:'2.4',channel:6,width:'40'}}});
 vm.runInContext('refreshing=false',e.context);await e.actualRefresh();assert.equal(e.get('wifi-interface').value,'wlan1');assert.equal(e.get('wifi-band').value,'auto');assert.equal(e.get('wifi-channel').value,'0');assert.equal(e.get('wifi-width').value,'auto');
});


test('Check/Check All/cancel call only preflight endpoints and render honest statuses',async()=>{
 const e=environment();const calls=[];
 e.context.fetch=async(url,opts={})=>{calls.push([url,opts]);return {ok:true,json:async()=>({running:1,results:{saved:{status:'checking',reason:'Queued / checking',checks:[]}}})};};
 vm.runInContext("profiles=[{id:'saved',name:'PPTP test',type:'socks5'}];renderProfiles()",e.context);
 const actions=e.get('profile-list').children[0].children[1];
 await actions.children.find(n=>n.textContent==='Проверить').listeners.click();
 assert.deepEqual(JSON.parse(calls[0][1].body),{profile_id:'saved'});
 await e.get('check-all').listeners.click();assert.deepEqual(JSON.parse(calls[1][1].body),{all:true});
 await e.get('check-cancel').listeners.click();
 assert.ok(calls.every(([url])=>url.includes('/support/preflight')));
 assert.equal(calls[2][0],'/api/mvp/support/preflight-cancel');
 assert.equal(e.get('check-all').disabled,true);
 assert.ok(e.get('profile-list').children[0].children[0].children.some(n=>n.textContent.includes('Проверяется...')));
});

test('Open Logs selects component/profile and renders errors as text, refresh only on open tab',async()=>{
 const e=environment();const calls=[];
 e.context.fetch=async(url,opts={})=>{calls.push([url,opts]);return {ok:true,json:async()=>({limit:300,entries:[{id:'failure',time:1,component:'socks5',severity:'error',profile:'PPTP test',message:'CHAP failed; exit 19; <script>unsafe</script>'}]})};};
 vm.runInContext("openLogs('socks5','saved')",e.context);await new Promise(setImmediate);
 assert.equal(e.context.location.hash,'logs');
 assert.deepEqual(JSON.parse(calls[0][1].body),{component:'socks5',severity:'all',search:'',profile_id:'saved'});
 assert.ok(e.get('logs-latest').textContent.includes('exit 19'));
 assert.ok(e.get('logs-entries').textContent.includes('<script>'));
 const timer=e.timers.find(t=>t.ms===5000);assert.ok(timer);
 vm.runInContext("activeScreen='dashboard'",e.context);timer.fn();await new Promise(setImmediate);assert.equal(calls.length,1);
 vm.runInContext("activeScreen='logs'",e.context);timer.fn();await new Promise(setImmediate);assert.equal(calls.length,2);
 let copied='';e.context.navigator={clipboard:{writeText:async text=>{copied=text;}}};
 await e.get('logs-copy').listeners.click();assert.equal(copied,e.get('logs-latest').textContent);
});

test('filtered log and ZIP downloads use fixed authenticated support routes',async()=>{
 const e=environment(),calls=[],links=[];
 e.context.document.createElement=tag=>{const n=node();if(tag==='a')links.push(n);return n;};
 e.context.URL={createObjectURL:()=> 'blob:fixture',revokeObjectURL(){}};
 e.context.fetch=async(url,opts)=>{calls.push([url,opts]);return {ok:true,blob:async()=>new Blob(['sanitized fixture'])};};
 e.get('logs-component').value='socks5';e.get('logs-severity').value='error';
 await e.get('logs-download').listeners.click();await e.get('diagnostics-download').listeners.click();
 assert.equal(calls[0][0],'/api/mvp/support/logs.log');assert.equal(calls[1][0],'/api/mvp/support/diagnostics.zip');
 assert.deepEqual(JSON.parse(calls[0][1].body),{component:'socks5',severity:'error',search:''});
 assert.ok(calls.every(([,opts])=>opts.credentials==='same-origin'&&opts.method==='POST'));
 assert.equal(links[0].download,'pirate-filtered.log');assert.equal(links[1].download,'pirate-diagnostics.zip');
});


test('terminal preserves scroll position and uses one text area',async()=>{
 const e=environment(),terminal=e.get('logs-entries');
 terminal.textContent='previous';terminal.scrollTop=100;terminal.scrollHeight=1000;terminal.clientHeight=200;
 e.context.fetch=async()=>({ok:true,json:async()=>({limit:300,entries:[{severity:'info',line:'Nov 01 12:00:00 pi openvpn[42]: real source message',message:'real source message'}]})});
 await vm.runInContext('refreshLogs()',e.context);
 assert.equal(terminal.scrollTop,100);assert.equal(terminal.children.length,0);assert.ok(terminal.textContent.includes('openvpn[42]'));
});
