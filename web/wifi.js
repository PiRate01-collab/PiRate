// PiRate Wi-Fi Manager: metadata and preview only. Real apply is unavailable; Safe Apply uses separate mock endpoints.
(() => {
  const byId = id => document.getElementById(id);
  const form = byId('wifi-form');
  const features = ['wmm','ht','vht','he','eht','isolate_clients','short_gi'];
  const fields = ['name','ssid','announcement','mac_mode','custom_mac','band','channel','width','security','beacon_interval','dtim','password_ref'];
  let editingId = null, caps = null;
  const node = (tag, value, cls='') => { const n=document.createElement(tag);n.textContent=value ?? '—';if(cls)n.className=cls;return n; };
  async function api(path, method='GET', data) {
    const opts = {method,cache:'no-store'};
    if(data!==undefined){opts.headers={'Content-Type':'application/json'};opts.body=JSON.stringify(data);}
    const r=await fetch(path,opts);const value=await r.json();if(!r.ok)throw new Error(value.error||`HTTP ${r.status}`);return value;
  }
  function message(value) { byId('wifi-message').textContent=value; }
  function payload() {
    const result={};for(const name of fields)result[name]=form.elements[name].value;
    for(const name of ['channel','width','beacon_interval','dtim'])result[name]=Number(result[name]);
    result.custom_mac=result.mac_mode==='custom'?result.custom_mac:null;
    result.password_ref=result.password_ref||null;
    result.features=features.filter(name=>form.elements[name].checked);return result;
  }
  function identity() {
    const mode=form.elements.mac_mode.value;form.elements.custom_mac.disabled=mode!=='custom';
    byId('wifi-mac-hint').textContent=mode==='stable-local'?'Стабильный адрес закрепляется за ID сохранённого профиля. Дубликат получит другой адрес.':mode==='custom'?'Только локально администрируемый unicast MAC. Поддержка драйвера должна быть подтверждена.':'Используется hardware MAC адаптера.';
  }
  function channels(selected=null) {
    const select=form.elements.channel, band=form.elements.band.value;
    const desired=String(selected??select.value??'1');select.replaceChildren();
    const observed=(caps?.channels||[]).filter(c=>c.band===band);
    if(!observed.length){const o=node('option',`${desired==='0'?'1':desired} · draft, не проверен`);o.value=desired==='0'?'1':desired;select.append(o);}
    for(const c of observed){const blocked=c.disabled||c.no_ir||c.dfs;const o=node('option',`${c.number} · ${c.frequency} MHz${blocked?' · запрещён / DFS':''}`);o.value=String(c.number);o.disabled=blocked;select.append(o);}
    if(observed.length && !observed.some(c=>String(c.number)===desired)) {
      const o=node('option',`${desired} · не поддерживается`);o.value=desired;o.disabled=true;select.append(o);
    }
    select.value=desired;
    if(selected===null && ![...select.options].some(o=>o.value===desired&&!o.disabled)){const allowed=[...select.options].find(o=>!o.disabled);if(allowed)select.value=allowed.value;}
  }
  function reset() { editingId=null;form.reset();identity();channels('1');byId('wifi-form-title').textContent='Новый Wi-Fi-профиль';byId('wifi-issues').replaceChildren();byId('wifi-preview-output').classList.add('hidden'); }
  async function loadProfiles() {
    const data=await api('/api/wifi/profiles'), list=byId('wifi-profiles');list.replaceChildren();
    document.dispatchEvent(new CustomEvent('wifi-profiles-loaded', {detail:data.profiles}));
    if(!data.profiles.length)list.append(node('p','Пока нет Wi-Fi-профилей','muted'));
    for(const profile of data.profiles){
      const row=document.createElement('div');row.className='profile';const info=document.createElement('div');
      info.append(node('strong',profile.name),node('p',`${profile.ssid} · ${profile.band} GHz / ${profile.channel} · ${profile.security.toUpperCase()}`,'muted'));
      if(profile.stable_mac)info.append(node('p',`Stable local: ${profile.stable_mac}`,'mono'));
      const actions=document.createElement('div');actions.className='profile-actions';
      for(const [label,action] of [['Редактировать','edit'],['Дублировать','duplicate'],['Удалить','delete']]) {
        const button=node('button',label);button.type='button';if(action==='delete')button.className='danger';
        button.addEventListener('click',async()=>{try{
          if(action==='edit'){editingId=profile.id;for(const name of fields)form.elements[name].value=profile[name]??'';for(const name of features)form.elements[name].checked=profile.features.includes(name);identity();channels(profile.channel);byId('wifi-form-title').textContent='Редактирование: '+profile.name;byId('wifi-issues').replaceChildren();byId('wifi-preview-output').classList.add('hidden');message('Редактируется сохранённый профиль; сеть не изменяется.');form.scrollIntoView({behavior:'smooth',block:'start'});}
          if(action==='duplicate'){await api(`/api/wifi/profiles/${profile.id}/duplicate`,'POST',{});await loadProfiles();message('Дубликат сохранён с новым ID.');}
          if(action==='delete'&&confirm(`Удалить Wi-Fi-профиль «${profile.name}»?`)){await api(`/api/wifi/profiles/${profile.id}`,'DELETE');if(editingId===profile.id)reset();await loadProfiles();message('Профиль удалён.');}
        }catch(err){message(err.message);}});actions.append(button);
      }
      row.append(info,actions);list.append(row);
    }
  }
  function renderReport(report) {
    const labels={compatible:'Совместимость подтверждена моделью',unknown:'Совместимость неизвестна',unsupported:'Есть несовместимые настройки'};
    message(`${labels[report.status]||report.status}. Preview Only — применение недоступно.`);
    const list=byId('wifi-issues');list.replaceChildren();for(const issue of report.issues)list.append(node('li',`${issue.field}: ${issue.message} [${issue.status}]`,'warn'));
    if(report.effective_mac)list.append(node('li',`MAC в модели: ${report.effective_mac}`,'mono'));
  }
  async function validate(preview=false) {
    try{const report=await api(preview?'/api/wifi/preview':'/api/wifi/validate','POST',{profile:payload(),profile_id:editingId});renderReport(report);const output=byId('wifi-preview-output');output.classList.toggle('hidden',!preview);if(preview)output.textContent=report.configuration||'Preview заблокирован из-за несовместимых настроек.';}catch(err){message(err.message);}
  }
  async function inspect() {
    try{const data=await api('/api/wifi/status');caps=data.capabilities;const current=byId('wifi-current');current.replaceChildren();
      for(const [label,value] of [['SSID из конфигурации',data.current_ap.configured_ssid],['Интерфейс',data.current_ap.interface],['Адрес',data.current_ap.address],['Hardware MAC',data.current_ap.hardware_mac],['Observed MAC',data.current_ap.observed_mac],['Работа AP',data.current_ap.operational_status]])current.append(node('p',`${label}: ${value||'Unknown'}`));
      const block=byId('wifi-capabilities');block.replaceChildren();
      for(const value of [`Adapter inspected: ${caps.interface||'Unknown'}`,`AP: ${caps.compatibility}`,`BSSID change: ${caps.bssid_compatibility}`,`Regulatory domain: ${caps.regulatory_domain||'Unknown'}`,`AP features verified: ${caps.features.join(', ')||'Unknown'}`,`Advertised HT/VHT/HE/EHT: ${(caps.advertised_features||[]).join(', ')||'Unknown'}`,`Security: ${caps.security.join(', ')||'Unknown'}`,`Channels observed: ${caps.channels.length}`,`Source: ${caps.source}`,...caps.limitations])block.append(node('p',value,'muted'));
      channels();
    }catch(err){byId('wifi-capabilities').textContent='Диагностика недоступна: '+err.message;}
  }
  form.addEventListener('submit',async event=>{event.preventDefault();try{const data=payload();const saved=await api(editingId?`/api/wifi/profiles/${editingId}`:'/api/wifi/profiles',editingId?'PUT':'POST',data);editingId=saved.id;byId('wifi-form-title').textContent='Редактирование: '+saved.name;await loadProfiles();message('Профиль сохранён. Настройки AP и пароль не изменены.');}catch(err){message(err.message);}});
  form.elements.mac_mode.addEventListener('change',identity);form.elements.band.addEventListener('change',()=>channels());
  byId('wifi-validate').addEventListener('click',()=>validate());byId('wifi-preview').addEventListener('click',()=>validate(true));byId('wifi-cancel').addEventListener('click',reset);byId('wifi-inspect').addEventListener('click',inspect);
  identity();inspect();loadProfiles().catch(err=>message(err.message));
})();
