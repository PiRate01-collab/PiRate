const labels = {dashboard:['Dashboard','Состояние системы'],connections:['Connections','Профили подключений'],dns:['DNS Control','Текущие системные резолверы'],wifi:['Wi-Fi / LAN','Wi-Fi Identity & Radio · Preview Only'],system:['System','О версии']};
const e = id => document.getElementById(id);
const text = (tag, value, cls='') => {const n=document.createElement(tag);n.textContent=String(value ?? '—');if(cls)n.className=cls;return n;};
const clear = node => node.replaceChildren();
for(const b of document.querySelectorAll('.nav')) b.addEventListener('click',()=>{for(const x of document.querySelectorAll('.nav'))x.classList.toggle('active',x===b);for(const p of document.querySelectorAll('.panel'))p.classList.toggle('hidden',p.id!==b.dataset.panel);e('heading').textContent=labels[b.dataset.panel][0];e('subtitle').textContent=labels[b.dataset.panel][1];});
async function get(url){const r=await fetch(url,{cache:'no-store'});const d=await r.json();if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);return d;}
async function update(){try{const d=await get('/api/status');clear(e('services'));for(const [k,v] of Object.entries(d.services))e('services').append(text('p',`${k}: ${v}`,v==='active'?'ok':'warn'));e('route').textContent=d.route||'Недоступно';e('forwarding').textContent=d.forwarding??'—';clear(e('interfaces'));for(const [k,v] of Object.entries(d.interfaces))e('interfaces').append(text('p',`${k}: ${v||'Неизвестно'}`,'mono'));clear(e('resolvers'));for(const x of d.dns.resolvers)e('resolvers').append(text('p',x,'mono'));if(!d.dns.resolvers.length)e('resolvers').append(text('p','Нет данных'));clear(e('wifi-config'));for(const [k,v] of Object.entries(d.config))e('wifi-config').append(text('p',`${k}: ${v}`));if(!Object.keys(d.config).length)e('wifi-config').append(text('p','Настройки gate недоступны в этой среде'));e('updated').textContent=`Обновлено: ${new Date().toLocaleTimeString()}`;}catch(err){e('updated').textContent=`Не удалось обновить статус: ${err.message}`;}}
async function loadProfiles(){try{const d=await get('/api/profiles');clear(e('profiles'));if(!d.profiles.length){e('profiles').append(text('p','Пока нет профилей','muted'));return;}for(const p of d.profiles){const row=document.createElement('div');row.className='profile';const info=document.createElement('div');info.append(text('strong',p.name),text('p',`${p.type.toUpperCase()} · ${p.server||'сервер не задан'} · DNS: ${p.dns_mode}`,'muted'));const edit=document.createElement('button');edit.textContent='Редактировать';edit.addEventListener('click',()=>{
 const form=e('create-profile');editingId=p.id;for(const key of ['name','type','server','port','dns_mode','notes']) form.elements[key].value=p[key]??'';
 refreshAuth(true);e('auth-username').value='';e('auth-password').value='';e('profile-form-title').textContent='Редактирование: '+p.name;e('save-profile').textContent='Сохранить изменения';e('cancel-edit').classList.remove('hidden');form.scrollIntoView({behavior:'smooth',block:'center'});
});const del=document.createElement('button');del.textContent='Удалить';del.className='danger';del.addEventListener('click',async()=>{if(!confirm(`Удалить профиль «${p.name}»?`))return;try{const r=await fetch(`/api/profiles/${encodeURIComponent(p.id)}`,{method:'DELETE'});if(!r.ok)throw new Error('Ошибка удаления');await loadProfiles();}catch(err){e('profile-message').textContent=err.message;}});const actions=document.createElement('div');actions.className='profile-actions';actions.append(edit,del);row.append(info,actions);e('profiles').append(row);}}catch(err){e('profiles').textContent=`Ошибка: ${err.message}`;}}
let editingId=null;
const authDefaults = {openvpn:'password',wireguard:'key',socks5:'password',http:'password'};
const authDescriptions = {openvpn:'OpenVPN: логин/пароль или сертификаты — зависит от конфигурации.',wireguard:'WireGuard: обычно приватный ключ, а не пара логин/пароль.',socks5:'SOCKS5: логин и пароль для авторизации на прокси.',http:'HTTP Proxy: логин и пароль, если прокси требует авторизацию.'};
function refreshAuth(reset=false){
  const form=e('create-profile');const type=form.elements.type.value;
  const mode=e('auth-mode');
  if(reset)mode.value=authDefaults[type];
  e('auth-explanation').textContent=authDescriptions[type]+' Пароли в 0.2.10-dev не сохраняются.';
  e('auth-hint').textContent=mode.value==='key'?'Загрузка ключей и сертификатов появится в следующем этапе.':mode.value==='none'?'Авторизация не требуется.':'Учётные данные будут доступны для ввода, но не будут отправлены на сервер.';
  for(const label of document.querySelectorAll('.auth-password-field')){
    const show=mode.value==='password';label.classList.toggle('hidden',!show);
    label.querySelector('input').disabled=!show;
    if(!show)label.querySelector('input').value='';
  }
}
e('create-profile').elements.type.addEventListener('change',()=>refreshAuth(true));
e('auth-mode').addEventListener('change',()=>refreshAuth());
refreshAuth(true);
function profilePayload(){const f=new FormData(e('create-profile'));return {name:String(f.get('name')),type:String(f.get('type')),server:String(f.get('server')),port:f.get('port')?Number(f.get('port')):null,dns_mode:String(f.get('dns_mode')),notes:String(f.get('notes'))};}
function resetEdit(){editingId=null;e('create-profile').reset();refreshAuth(true);e('profile-form-title').textContent='Новый профиль';e('save-profile').textContent='Сохранить профиль';e('cancel-edit').classList.add('hidden');}
e('cancel-edit').addEventListener('click',resetEdit);
e('test-profile').addEventListener('click',async()=>{try{const r=await fetch('/api/profiles/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(profilePayload())});const d=await r.json();if(!r.ok)throw new Error(d.error);e('profile-message').textContent=(d.complete?'Структура OK.':'Черновик допустим. ')+d.messages.join('; ')+' (соединение НЕ проверялось)';}catch(err){e('profile-message').textContent='Ошибка: '+err.message;}});
e('import-config').addEventListener('change',async ev=>{const file=ev.target.files[0];if(!file)return;try{if(file.size>65536)throw new Error('Максимум 64 КБ');const type=file.name.toLowerCase().endsWith('.ovpn')?'openvpn':file.name.toLowerCase().endsWith('.conf')?'wireguard':null;if(!type)throw new Error('Нужен .ovpn или .conf');const content=await file.text();const r=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,content})});const d=await r.json();if(!r.ok)throw new Error(d.error);resetEdit();const form=e('create-profile');for(const [k,v] of Object.entries(d.profile)){if(form.elements[k])form.elements[k].value=v??'';}refreshAuth(true);e('import-message').textContent='Параметры извлечены. '+d.warnings.join('; ')+'. Проверь и сохрани профиль.';}catch(err){e('import-message').textContent='Ошибка импорта: '+err.message;}finally{ev.target.value='';}});
e('create-profile').addEventListener('submit',async ev=>{ev.preventDefault();const data=profilePayload();try{const r=await fetch(editingId?`/api/profiles/${encodeURIComponent(editingId)}`:'/api/profiles',{method:editingId?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const d=await r.json();if(!r.ok)throw new Error(d.error||'Ошибка сохранения');resetEdit();e('profile-message').textContent='Профиль сохранён (без секретов и без подключения)';await loadProfiles();}catch(err){e('profile-message').textContent=err.message;}});
update();loadProfiles();setInterval(update,10000);

async function loadCapabilities(){try{const d=await get('/api/connection-capabilities');clear(e('connection-capabilities'));for(const [type,c] of Object.entries(d.capabilities)){e('connection-capabilities').append(text('p',`${type.toUpperCase()}: ${c.binary||'backend not selected'} · ${c.installed?'binary found':'not installed / unavailable'} · connection disabled`,'mono'));}}catch(err){e('connection-capabilities').textContent=err.message;}}
e('inspect-profile').addEventListener('click',async()=>{try{const r=await fetch('/api/profiles/inspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(profilePayload())});const d=await r.json();if(!r.ok)throw new Error(d.error||'Inspection error');e('profile-message').textContent=`Inspection only · launch blocked · missing: ${d.missing.join(', ')}`;}catch(err){e('profile-message').textContent=err.message;}});
loadCapabilities();

// Plan-only API: never starts a VPN process or modifies the network.
e('plan-tunnel').addEventListener('click', async()=>{
 try{const r=await fetch('/api/profiles/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(profilePayload())});
 const d=await r.json(); if(!r.ok) throw new Error(d.error||'Plan unavailable');
 e('profile-message').textContent=`Plan only · no connection started · ${d.planned_checks.join(' → ')} · blockers: ${d.blockers.join(', ')}`;
 }catch(err){e('profile-message').textContent='Ошибка: '+err.message;}
});

// Read-only namespace capability detection. No privilege elevation from browser.
e('namespace-preflight').addEventListener('click',async()=>{
 try{const d=await get('/api/namespace-preflight');e('namespace-output').textContent=
 `Linux: ${d.platform}\nip: ${d.ip_binary||'not installed'}\nSupported: ${d.namespace_possible?'yes':'no'}\nWeb execution: disabled\n\nCLI smoke test (manual):\n${d.run_command}\n\n${d.note}`;}
 catch(err){e('namespace-output').textContent='Ошибка: '+err.message;}
});

// 0.2.10-dev transport preflight is read-only. Privileged tests remain CLI-only.
e('transport-preflight').addEventListener('click',async()=>{
 try {const d=await get('/api/transport-preflight');
 e('transport-output').textContent=`ip: ${d.ip_binary||'missing'}\nping: ${d.ping_binary||'missing'}\nReady: ${d.ready_for_test?'yes':'no'}\nWAN uplink: disabled\nWeb execution: disabled\n\nManual CLI test:\n${d.run_command}\n\n${d.note}`;}
 catch(err){e('transport-output').textContent='Ошибка: '+err.message;}
});

// Read-only uplink diagnostics. Never allow privileged invocation from web.
e('uplink-preflight').addEventListener('click', async () => {
 try { const d=await get('/api/uplink-preflight');
 e('uplink-output').textContent = `Ready: ${d.ready_for_cli_test?'yes':'no'}\nWeb execution: disabled\nBinaries: ${Object.entries(d.binaries).map(([k,v])=>k+'='+ (v||'missing')).join(', ')}\n\nCLI (manual):\n${d.run_command}\n\n${d.warning}`;
 } catch(err) { e('uplink-output').textContent='Ошибка: '+err.message; }
});
