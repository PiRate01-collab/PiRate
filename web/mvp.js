'use strict';

const el = id => document.getElementById(id),
  split = value => value.split(',').map(v => v.trim()).filter(Boolean);
let apProfiles = [],
  apEditing = null,
  apSelected = '',
  apState = {},
  serverWifi = null,
  wifiDevices = [];
let canDisconnect = false,
  canProbe = false;
let ovpnDraft = null,
  simpleImport = false;
let activeScreen = 'dashboard',
  pending = false,
  wifiDirty = false,
  dnsDirty = false,
  setupDigest = '';
let profiles = [],
  editing = null,
  busy = false,
  loaded = false,
  chosen = '',
  refreshing = false,
  profilesDigest = '',
  retryBlocked = false;
const labels = {
  direct: 'Direct',
  http: 'HTTP CONNECT',
  socks5: 'SOCKS5',
  openvpn: 'OpenVPN',
  wireguard: 'WireGuard'
};
function friendlyError(data, code) {
  const raw = data.message || data.error || '';
  if (/[А-Яа-яЁё]/.test(raw)) return raw;
  if (/AP password/.test(raw)) return 'Пароль Wi-Fi должен содержать 8–63 печатных символа латиницей.';
  if (code === 401) return 'Войдите в панель с актуальным паролем администратора.';
  if (code === 403) return 'Доступ запрещён. Откройте панель по доверенному локальному адресу.';
  if (code >= 500) return 'Служба временно недоступна. Повторите попытку; подробности доступны в диагностике.';
  if (/credential|username|password/i.test(raw)) return 'Проверьте логин и пароль подключения.';
  if (/not found/i.test(raw)) return 'Профиль больше не существует. Обновите список.';
  if (/pending|confirm/i.test(raw)) return 'Сначала подтвердите или отмените предыдущее подключение.';
  if (/timeout|refused|unreachable|connect/i.test(raw)) return 'Не удалось подключиться. Проверьте сервер, порт и доступ в интернет, затем повторите попытку.';
  return 'Не удалось выполнить действие. Проверьте поля формы. Техническая причина доступна в подробностях ошибки.';
}
async function api(path, method = 'GET', body) {
  const options = {
    method,
    cache: 'no-store',
    credentials: 'same-origin'
  };
  if (body !== undefined) {
    options.headers = {
      'Content-Type': 'application/json'
    };
    options.body = JSON.stringify(body);
  }
  let response, data;
  try {
    response = await fetch('/api/mvp/' + path, options);
    data = await response.json();
  } catch (error) {
    throw new Error('Нет связи с PiRate. Проверьте подключение к роутеру и повторите попытку.');
  }
  if (!response.ok) {
    el('connection-error-detail').textContent = data.error || '';
    throw new Error(friendlyError(data, response.status));
  }
  return data;
}
function message(text, error = false) {
  el('message').textContent = text;
  el('message').className = error ? 'error' : '';
  el('support').classList.toggle('hidden', !error);
}
function screen(name) {
  activeScreen = name;
  for (const panel of document.querySelectorAll('.panel')) panel.classList.toggle('hidden', panel.id !== name);
  for (const button of document.querySelectorAll('[data-screen]')) button.classList.toggle('active', button.dataset.screen === name);
  location.hash = name;
  el('heading').textContent = {
    dashboard: 'Обзор',
    wifi: 'Wi-Fi',
    connections: 'Подключения',
    system: 'Система',
    logs: 'Логи и диагностика'
  }[name];
  if (name === 'logs') refreshLogs();
}
for (const button of document.querySelectorAll('[data-screen]')) button.addEventListener('click', () => screen(button.dataset.screen));
function buttons() {
  for (const form of document.querySelectorAll('form')) form.inert = busy;
  for (const button of document.querySelectorAll('button')) button.disabled = busy && !button.dataset.screen || button.dataset.apProtected === 'true' || button.dataset.apApply === 'true' && pending;
  for (const id of ['connect', 'quick-connect']) el(id).disabled = busy || pending || !chosen;
  el('disconnect').disabled = busy || !canDisconnect;
  el('wifi-off').disabled = busy || !canDisconnect;
  el('check-internet').disabled = busy || !canProbe;
  el('retry-wifi').disabled = busy || retryBlocked;
  el('wifi-retry').disabled = busy || retryBlocked;
  const apProtected = Boolean(apEditing && (apState.protected_ids || []).includes(apEditing));
  el('ap-save').disabled = busy || apProtected;
  el('ap-editor-note').textContent = apProtected ? 'Этот профиль защищён. Создайте копию для изменения настроек.' : 'Сохранение не меняет работающую сеть.';
  el('ap-apply').disabled = busy || pending || !apSelected;
  el('profile-save').disabled = busy || Boolean(ovpnDraft && ovpnDraft.save_allowed === false);
}
async function action(fn) {
  if (busy) return;
  busy = true;
  buttons();
  message('Выполняем действие…');
  try {
    await fn();
    await refresh();
  } catch (error) {
    message(error.message, true);
  } finally {
    busy = false;
    buttons();
  }
}
function option(value, text) {
  const item = document.createElement('option');
  item.value = value;
  item.textContent = text;
  return item;
}
function renderProfiles() {
  for (const id of ['selected-profile', 'quick-profile']) {
    el(id).replaceChildren(...profiles.map(profile => option(profile.id, profile.name + ' · ' + labels[profile.type])));
    if (profiles.some(profile => profile.id === chosen)) el(id).value = chosen;
  }
  el('profile-list').replaceChildren();
  for (const profile of profiles) {
    const row = document.createElement('div');
    row.className = 'profile';
    const text = document.createElement('div'),
      name = document.createElement('strong'),
      kind = document.createElement('span');
    name.textContent = profile.name;
    kind.textContent = ' · ' + labels[profile.type];
    text.append(name, kind);
    const actions = document.createElement('div');
    actions.className = 'actions';
    for (const [label, fn] of [['Подключиться', () => {
      chosen = profile.id;
      renderProfiles();
      start();
    }], ['Изменить', () => action(() => edit(profile))], ['Дублировать', () => action(async () => {
      const result = await api('profiles', 'POST', {
        duplicate_from: profile.id
      });
      chosen = result.id;
      message('Копия сохранена. Приватные ключи и пароли перенесены без раскрытия.');
    })], ['Удалить', () => action(async () => {
      if (confirm('Удалить ' + profile.name + '?')) {
        await api('profiles/' + profile.id, 'DELETE');
        message('Профиль удалён');
      }
    })]]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.addEventListener('click', fn);
      actions.append(button);
    }
    if (profile.type !== 'direct') {
      const check = document.createElement('button'), logs = document.createElement('button'), detail = document.createElement('p');
      const result = preflightState.results[profile.id] || {status:'not_checked',reason:'',checks:[]};
      check.type = logs.type = 'button';
      check.textContent = 'Проверить'; check.disabled = preflightState.running > 0;
      check.addEventListener('click',()=>checkProfile(profile.id));
      logs.textContent = 'Открыть логи';
      logs.addEventListener('click',()=>openLogs(profile.type,profile.id));
      detail.textContent = preflightLabels[result.status] || '';
      if (result.status === 'failed') detail.className = 'error';
      text.append(detail); actions.append(check,logs);
    }
    row.append(text, actions);
    el('profile-list').append(row);
  }
  if (!profiles.length) el('profile-list').textContent = 'Создай первый профиль.';
}
for (const id of ['selected-profile', 'quick-profile']) el(id).addEventListener('change', () => {
  chosen = el(id).value;
  for (const other of ['selected-profile', 'quick-profile']) el(other).value = chosen;
});
function typeFields() {
  const kind = el('profile-type').value;
  el('username-caption').textContent = kind === 'openvpn' ? 'Логин VPN (если требует сервер)' : 'Логин (необязательно)';
  el('password-caption').textContent = kind === 'openvpn' ? 'Пароль VPN (если требует сервер)' : 'Пароль (необязательно)';
  el('endpoint-fields').classList.toggle('hidden', kind === 'direct');
  el('openvpn-fields').classList.toggle('hidden', kind !== 'openvpn');
  el('wireguard-fields').classList.toggle('hidden', kind !== 'wireguard');
  const form = el('profile-form');
  form.elements.server.required = kind !== 'direct';
  form.elements.port.required = kind !== 'direct';
  el('port-field').hidden = false;
  form.elements.username.required = false;
  el('credentials-fields').classList.toggle('hidden', kind === 'direct' || kind === 'wireguard');
  el('username-field').hidden = false;
  el('password-field').hidden = false;
  for (const key of ['server', 'port']) form.elements[key].disabled = kind === 'direct';
}
function reset() {
  el('profile-form').reset();
  editing = null;
  el('profile-type').disabled = false;
  ovpnDraft = null;
  simpleImport = false;
  el('connection-advanced').open = false;
  PiRateOpenVPN.remotes(el('ovpn-remote-select'), [], 0);
  el('ovpn-import-info').textContent = '';
  el('converter-analysis').textContent = '';
  el('connection-error-detail').textContent = '';
  el('connection-summary').textContent = 'Импортируйте файл VPN или заполните поля ниже. Сохранение не меняет текущее подключение.';
  el('clear-auth').checked = false;
  el('clear-auth-label').classList.add('hidden');
  el('profile-form').elements.username.disabled = false;
  el('profile-form').elements.password.disabled = false;
  el('profile-form').elements.password.placeholder = 'Не задан';
  el('profile-form').elements.wg_private_key.placeholder = 'Не задан';
  el('profile-form').elements.wg_preshared_key.placeholder = 'Не задан';
  el('import-consent').checked = false;
  el('import-consent-label').classList.add('hidden');
  el('profile-save').textContent = 'Сохранить профиль';
  el('username-field').hidden = false;
  el('password-field').hidden = false;
  el('form-title').textContent = 'Добавить подключение';
  el('secret-note').textContent = 'Ключи и пароли сохраняются приватно. Пустой secret при редактировании сохраняет прежний.';
  typeFields();
  buttons();
}
async function edit(profile) {
  reset();
  editing = profile.id;
  el('profile-type').disabled = true;
  const form = el('profile-form');
  for (const key of ['name', 'type', 'server', 'port', 'username', 'wg_peer_key', 'wg_mtu', 'wg_keepalive']) form.elements[key].value = profile[key] ?? '';
  for (const key of ['dns_servers', 'wg_address', 'wg_allowed_ips']) form.elements[key].value = (profile[key] || []).join(', ');
  ovpnDraft = null;
  form.elements.ovpn_remote.value = String(profile.ovpn_remote || 0);
  form.elements.ovpn_proto.value = profile.ovpn_proto || '';
  PiRateOpenVPN.remotes(el('ovpn-remote-select'), profile.ovpn_remotes || [], profile.ovpn_remote || 0);
  el('ovpn-import-info').textContent = '';
  el('form-title').textContent = 'Редактировать ' + profile.name;
  el('clear-auth-label').classList.toggle('hidden', !(['http', 'socks5'].includes(profile.type) && profile.password_saved));
  for (const key of ['password', 'wg_private_key', 'wg_preshared_key']) form.elements[key].placeholder = profile[key + '_saved'] ? 'Сохранён — оставьте пустым для сохранения' : 'Не задан';
  typeFields();
  screen('connections');
  if (profile.type === 'openvpn') {
    const identifier = profile.id;
    const saved = await api('profiles/' + identifier + '/editor');
    if (editing === identifier) {
      form.elements.config.value = saved.config;
      form.elements.ovpn_server_name.value = saved.ovpn_server_name || '';
    }
  }
}
el('profile-type').addEventListener('change', () => {
  const kind = el('profile-type').value,
    name = el('profile-form').elements.name.value;
  reset();
  el('profile-type').value = kind;
  el('profile-form').elements.name.value = name;
  el('connection-advanced').open = kind === 'wireguard';
  typeFields();
});
el('cancel-edit').addEventListener('click', reset);
el('new-profile').addEventListener('click', () => {
  reset();
  el('profile-form').scrollIntoView({
    behavior: 'smooth'
  });
});
el('profile-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  action(async () => {
    const kind = form.elements.type.value;
    const payload = {
      name: form.elements.name.value,
      type: kind,
      server: kind === 'direct' ? '' : form.elements.server.value,
      port: kind === 'direct' ? null : Number(form.elements.port.value),
      username: kind === 'direct' ? '' : form.elements.username.value,
      dns_servers: kind === 'direct' ? [] : split(form.elements.dns_servers.value),
      wg_address: split(form.elements.wg_address.value),
      wg_peer_key: form.elements.wg_peer_key.value,
      wg_allowed_ips: split(form.elements.wg_allowed_ips.value)
    };
    if (kind === 'openvpn') {
      payload.ovpn_server_name = form.elements.ovpn_server_name.value;
      payload.ovpn_remote = Number(form.elements.ovpn_remote.value);
      payload.ovpn_proto = form.elements.ovpn_proto.value;
    }
    if (kind === 'wireguard') {
      payload.wg_mtu = Number(form.elements.wg_mtu.value);
      payload.wg_keepalive = Number(form.elements.wg_keepalive.value);
    }
    if (ovpnDraft) {
      if (ovpnDraft.save_allowed === false || ovpnDraft.status === 'incompatible_server') throw new Error(ovpnDraft.reason || 'Этот файл не подходит для безопасного подключения.');
      if ((ovpnDraft.required_fields || []).includes('username') && !form.elements.username.value) throw new Error('Введи логин VPN.');
      if ((ovpnDraft.required_fields || []).includes('password') && !form.elements.password.value) throw new Error('Введи пароль VPN.');
      payload.converter_draft = ovpnDraft.draft_id;
      payload.converter_confirmed = !ovpnDraft.confirmation_required || el('import-consent').checked;
      if (!payload.converter_confirmed) throw new Error('Откройте подробности импорта и подтвердите предложенные изменения безопасности.');
    }
    for (const key of ['password', 'config', 'wg_private_key', 'wg_preshared_key']) if (form.elements[key].value) payload[key] = form.elements[key].value;
    if (kind === 'openvpn' && !payload.config && !editing && !ovpnDraft) throw new Error('Импортируй .ovpn или заполни OpenVPN config перед сохранением');
    if (el('clear-auth').checked && ['http', 'socks5'].includes(kind)) {
      payload.username = '';
      payload.password = null;
    }
    const result = await api(editing ? 'profiles/' + editing : 'profiles', editing ? 'PUT' : 'POST', payload);
    chosen = result.id;
    reset();
    renderProfiles();
    message('Профиль сохранён. Для запуска выберите его и нажмите «Подключиться».');
  });
});
el('ovpn-remote-select').addEventListener('change', () => PiRateOpenVPN.selectRemote(el('profile-form'), el('ovpn-remote-select')));
el('import-file').addEventListener('change', event => {
  const file = event.target.files[0];
  if (!file) return;
  action(async () => {
    try {
      if (!/\.(ovpn|conf)$/i.test(file.name)) throw new Error('Нужен файл .ovpn или WireGuard .conf');
      const draft = await PiRateOpenVPN.upload(file, el('ovpn-encoding').value, api);
      reset();
      ovpnDraft = draft;
      simpleImport = draft.profile.type === 'openvpn';
      el('connection-advanced').open = draft.profile.type === 'wireguard' || (draft.required_fields || []).includes('ovpn_server_name');
      el('import-consent-label').classList.toggle('hidden', !draft.confirmation_required);
      PiRateOpenVPN.populate(el('profile-form'), draft, el('ovpn-remote-select'), el('ovpn-import-info'));
      typeFields();
      el('converter-analysis').textContent = (draft.diagnostics || []).map(d => `Строка ${d.line} · ${d.directive}: ${d.message}`).join('\n');
      el('connection-summary').textContent = draft.reason || 'Профиль загружен.';
      if (simpleImport) {
        el('profile-save').textContent = 'Сохранить профиль';
        el('username-field').hidden = !(draft.required_fields || []).includes('username');
        el('password-field').hidden = !(draft.required_fields || []).includes('password');
        el('credentials-fields').classList.toggle('hidden', el('username-field').hidden && el('password-field').hidden);
      }
      screen('connections');
      message(draft.reason || 'Файл загружен. Проверьте поля и сохраните профиль.', draft.save_allowed === false || draft.status === 'incompatible_server');
    } finally {
      event.target.value = '';
    }
  });
});
const apFields = [['wifi-interface', 'interface'], ['wifi-ssid', 'ssid'], ['wifi-security', 'security'], ['wifi-country', 'country'], ['wifi-band', 'band'], ['wifi-width', 'width'], ['wifi-channel', 'channel'], ['mac-mode', 'mac_mode'], ['mac-address', 'mac_address'], ['wifi-fingerprint', 'fingerprint']];
function fillAP(record) {
  if (record.wifi.interface && ![...el('wifi-interface').options].some(o => o.value === record.wifi.interface)) el('wifi-interface').append(option(record.wifi.interface, record.wifi.interface + ' · сохранённый адаптер'));
  for (const [id, key] of apFields) if (record.wifi[key] != null) el(id).value = record.wifi[key];
  renderRadio(wifiDevices.find(device => device.name === record.wifi.interface)?.capabilities || null);
  if (record.wifi.channel != null) {
    if (![...el('wifi-channel').options].some(o => o.value === String(record.wifi.channel))) el('wifi-channel').append(option(String(record.wifi.channel), record.wifi.channel + ' · сохранённый канал'));
    el('wifi-channel').value = String(record.wifi.channel);
  }
  if (record.wifi.width != null) {
    const width = el('wifi-width').querySelector('[value="' + record.wifi.width + '"]');
    if (width) width.disabled = false;
    el('wifi-width').value = String(record.wifi.width);
  }
  el('ap-name').value = record.name || '';
  el('wifi-password').value = '';
  el('wifi-password').placeholder = record.password_saved ? 'Сохранён — оставьте пустым для сохранения' : 'Задайте пароль, 8–63 символа';
}
function suggestedAPInterface() {
  const available = wifiDevices.filter(device => device.kind === 'wifi' && device.capabilities?.radio?.present !== false && !device.default_route && device.name !== el('wan-interface').value && device.capabilities?.ap_mode !== false);
  const capable = available.filter(device => device.capabilities?.ap_mode === true);
  const candidates = capable.length ? capable : available;
  return candidates.find(device => device.name === serverWifi?.interface)?.name || candidates[0]?.name || '';
}
function newAP() {
  apEditing = null;
  wifiDirty = true;
  fillAP({
    wifi: {
      ssid: 'PiRate',
      security: 'wpa2',
      country: '',
      mac_mode: 'keep',
      mac_address: '',
      fingerprint: 'default',
      ...serverWifi,
      interface: suggestedAPInterface(),
      band: 'auto',
      channel: 0,
      width: 'auto'
    }
  });
  el('wifi-password').placeholder = 'Задайте пароль нового профиля, 8–63 символа';
  el('ap-form-title').textContent = 'Создать профиль Wi-Fi';
  el('wifi-draft-note').classList.add('hidden');
}
function editAP(profile) {
  apEditing = profile.id;
  wifiDirty = true;
  fillAP(profile);
  el('ap-form-title').textContent = 'Редактировать ' + profile.name;
  el('wifi-form').scrollIntoView({
    behavior: 'smooth'
  });
}
function renderAPProfiles() {
  el('ap-selected').replaceChildren(...apProfiles.map(p => option(p.id, p.name + ' · ' + p.wifi.ssid)));
  if (apSelected) el('ap-selected').value = apSelected;
  const active = apProfiles.find(p => p.id === apState.active_id);
  const confirmed = apProfiles.find(p => p.id === apState.confirmed_id);
  el('ap-active-state').textContent = active ? 'Активный профиль: ' + active.name + (apState.pending ? ' · ожидает подтверждения' : '') : confirmed ? 'Последний подтверждённый: ' + confirmed.name : 'Активный сохранённый профиль не выбран';
  el('ap-profile-list').replaceChildren();
  for (const profile of apProfiles) {
    const row = document.createElement('div');
    row.className = 'profile';
    const title = document.createElement('strong');
    title.textContent = profile.name + ' · ' + profile.wifi.ssid + (profile.id === apState.active_id ? ' · Активен' : '') + (profile.id === apState.confirmed_id ? ' · Подтверждён' : '');
    const actions = document.createElement('div');
    actions.className = 'actions';
    const protectedProfile = (apState.protected_ids || []).includes(profile.id);
    for (const [label, fn, protectedAction] of [['Применить', () => applyAP(profile.id), false], ['Изменить', () => editAP(profile), true], ['Дублировать', () => action(async () => {
      const copy = await api('ap-profiles/' + profile.id + '/duplicate', 'POST', {});
      apSelected = copy.id;
      message('Копия Wi-Fi сохранена. Работающая сеть не изменена.');
    }), false], ['Удалить', () => action(async () => {
      if (confirm('Удалить профиль Wi-Fi «' + profile.name + '»?')) {
        await api('ap-profiles/' + profile.id, 'DELETE');
        if (apEditing === profile.id) newAP();
        message('Профиль Wi-Fi удалён.');
      }
    }), true]]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.dataset.apProtected = String(protectedAction && protectedProfile);
      button.dataset.apApply = String(label === 'Применить');
      button.disabled = busy || protectedAction && protectedProfile || label === 'Применить' && pending;
      if (protectedAction && protectedProfile) button.title = 'Защищён активный или подтверждённый профиль. Создайте копию.';
      button.addEventListener('click', fn);
      actions.append(button);
    }
    row.append(title, actions);
    el('ap-profile-list').append(row);
  }
  if (!apProfiles.length) el('ap-profile-list').textContent = 'Сохраните первый профиль Wi-Fi. Это не изменит работающую сеть.';
}
function applyAP(identifier) {
  if (pending) {
    message('Сначала подтвердите или отмените предыдущие изменения.', true);
    return;
  }
  apSelected = identifier;
  action(async () => {
    message('Применяем Wi-Fi. Подключитесь к новому SSID, снова откройте панель и подтвердите изменения.');
    await api('ap-profiles/' + identifier + '/apply', 'POST', {});
    screen('dashboard');
    message('Подключитесь к выбранной сети и подтвердите изменения за 90 секунд. Иначе прежняя сеть восстановится автоматически.');
  });
}
el('ap-new').addEventListener('click', () => {
  newAP();
  el('wifi-form').scrollIntoView({
    behavior: 'smooth'
  });
});
el('ap-cancel').addEventListener('click', newAP);
el('ap-selected').addEventListener('change', () => {
  apSelected = el('ap-selected').value;
  buttons();
});
el('ap-apply').addEventListener('click', () => applyAP(apSelected));
el('wifi-form').addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    const result = await api(apEditing ? 'ap-profiles/' + apEditing : 'ap-profiles', apEditing ? 'PUT' : 'POST', {
      name: el('ap-name').value,
      wifi: wifi()
    });
    apEditing = result.id;
    apSelected = result.id;
    wifiDirty = true;
    el('wifi-password').value = '';
    el('wifi-password').placeholder = 'Сохранён — оставьте пустым для сохранения';
    el('ap-form-title').textContent = 'Редактировать ' + result.name;
    el('wifi-draft-note').classList.add('hidden');
    message('Профиль Wi-Fi сохранён. Работающая сеть не изменена. Для переключения нажмите «Применить».');
  });
});
function wifi() {
  return {
    interface: el('wifi-interface').value,
    ssid: el('wifi-ssid').value,
    password: el('wifi-password').value,
    security: el('wifi-security').value,
    country: el('wifi-country').value.toUpperCase(),
    channel: Number(el('wifi-channel').value),
    band: el('wifi-band').value,
    width: el('wifi-width').value,
    mac_mode: el('mac-mode').value,
    mac_address: el('mac-address').value,
    fingerprint: el('wifi-fingerprint').value
  };
}
function dns() {
  const value = el('dns-servers').value.trim();
  return {
    mode: el('dns-mode').value,
    ...(value.startsWith('https://') ? {
      doh_url: value
    } : {
      servers: split(value)
    })
  };
}
async function applySelected() {
  if (!chosen) throw new Error('Добавьте профиль на экране «Подключения»');
  el('live-state').textContent = 'Подключаемся…';
  message('Подключаемся и проверяем соединение…');
  const savedAP = apState.active_id || (!apState.active_present ? apState.confirmed_id || apSelected : '');
  await api('router-apply', 'POST', {
    profile_id: chosen,
    ...(savedAP ? {
      wifi_profile_id: savedAP
    } : {
      wifi: serverWifi || wifi()
    }),
    wan_interface: el('wan-interface').value,
    dns: dns(),
    timeout: 90
  });
  el('wifi-password').value = '';
  wifiDirty = false;
  el('wifi-draft-note').classList.add('hidden');
  dnsDirty = false;
  setupDigest = '';
  screen('dashboard');
  message('Проверка соединения выполнена. Проверь Интернет на клиенте и подтверди настройку.');
}
function start() {
  if (pending) {
    message('Подтвердите или отмените текущее подключение.', true);
    return;
  }
  action(applySelected);
}
el('connect').addEventListener('click', start);
el('quick-connect').addEventListener('click', start);
el('dashboard-start').addEventListener('click', () => screen('wifi'));
for (const name of ['confirm', 'rollback', 'disconnect']) el(name).addEventListener('click', () => action(async () => {
  await api(name, 'POST', {});
  message({
    confirm: 'Настройка сохранена. Роутер восстановит её после перезапуска.',
    rollback: 'Предыдущая настройка восстановлена.',
    disconnect: 'Роутер отключён. Трафик клиентов заблокирован.'
  }[name]);
}));
el('dns-mode').addEventListener('change', () => el('manual-dns-label').classList.toggle('hidden', el('dns-mode').value !== 'manual'));
el('dns-test').addEventListener('click', () => action(async () => {
  if (!chosen) throw new Error('Выбери профиль');
  el('dns-test-result').textContent = 'Проверяем DNS…';
  const payload = {
    profile_id: chosen,
    wan_interface: el('wan-interface').value
  };
  if (el('dns-mode').value === 'manual') {
    const value = dns();
    if (value.doh_url) payload.doh_url = value.doh_url;else payload.servers = value.servers;
  }
  const result = await api('dns-test', 'POST', payload);
  el('dns-test-result').textContent = (result.status === 'PASS' ? 'DNS доступен' : result.status === 'FAIL' ? 'DNS недоступен' : 'Проверка DNS не завершена') + (result.resolver ? ' · ' + result.resolver : '');
  if (result.status === 'FAIL') {
    el('connection-error-detail').textContent = result.reason || '';
    message('DNS не отвечает через выбранное подключение. Проверьте профиль и настройки DNS.', true);
  }
}));
el('mac-generate').addEventListener('click', () => action(async () => {
  el('mac-address').value = (await api('mac-generate', 'POST', {})).mac;
  el('mac-mode').value = 'generate';
  wifiDirty = true;
  el('wifi-draft-note').classList.remove('hidden');
  message('MAC подготовлен; применится при запуске.');
}));
el('mac-hardware').addEventListener('click', () => action(async () => {
  el('mac-address').value = (await api('hardware-mac', 'POST', {
    interface: el('wifi-interface').value
  })).mac;
  el('mac-mode').value = 'hardware';
  wifiDirty = true;
  el('wifi-draft-note').classList.remove('hidden');
  message('Заводской MAC подготовлен; применится при запуске.');
}));
let radioBands = {};
function renderRadio(info) {
  radioBands = info?.radio?.bands || {};
  radioChannels();
  el('radio-info').textContent = info?.radio?.present === false ? 'Адаптер отключён. Подключите его или выберите другой интерфейс.' : info?.ap_mode === false ? 'Драйвер адаптера не поддерживает режим точки доступа.' : (info?.ap_mode === true ? 'Режим точки доступа поддерживается' : 'Возможности адаптера пока не подтверждены') + ' · ' + (Object.keys(radioBands).join(' / ') || 'Диапазон не определён') + ' GHz · Совместимость будет проверена при применении.';
}
async function radioRefresh() {
  if (!el('wifi-interface').value) {
    renderRadio(null);
    return;
  }
  const interfaceName = el('wifi-interface').value;
  const info = await api('ap-capabilities', 'POST', {
    interface: interfaceName
  });
  if (el('wifi-interface').value === interfaceName) renderRadio(info);
}
let devicesDigest = '';
function updateDevices(setup) {
  wifiDevices = setup.interfaces;
  const digest = JSON.stringify(setup.interfaces, (key, value) => key === 'observed_at' ? undefined : value);
  if (digest === devicesDigest) return;
  devicesDigest = digest;
  for (const [id, kind] of [['wifi-interface', 'wifi'], ['wan-interface', 'ethernet']]) {
    const select = el(id),
      prior = select.value || (id === 'wifi-interface' ? setup.wifi.interface : setup.wan_interface);
    const items = setup.interfaces.filter(x => id === 'wan-interface' || x.kind === kind);
    select.replaceChildren(...items.map(x => option(x.name, x.name + ' · ' + (x.adapter || x.kind) + (x.capabilities ? ' · Точка доступа ' + (x.capabilities.ap_mode === true ? 'поддерживается' : x.capabilities.ap_mode === false ? 'не поддерживается' : 'не проверена') + ' · ' + Object.keys(x.capabilities.radio?.bands || {}).join('/') + ' GHz' : '') + (x.default_route ? ' · WAN' : ''))));
    if (prior && !items.some(x => x.name === prior)) select.append(option(prior, prior + ' · отключён'));
    if (prior) select.value = prior;
  }
  if (!loaded && !apEditing) el('wifi-interface').value = suggestedAPInterface();
  const selected = setup.interfaces.find(x => x.name === el('wifi-interface').value);
  renderRadio(selected?.capabilities || {
    radio: {
      present: false
    }
  });
}
function radioChannels(preserve = Boolean(apEditing || wifiDirty)) {
  const prior = el('wifi-channel').value,
    band = el('wifi-band').value;
  const channels = Object.entries(radioBands).filter(([b]) => band === 'auto' || b === band).flatMap(([b, c]) => c.channels.map(x => option(String(x.number), x.number + ' · ' + b + ' ГГц (вручную)')));
  el('wifi-channel').replaceChildren(option('0', 'Автоматически'), ...channels);
  if (preserve && prior && ![...el('wifi-channel').options].some(x => x.value === prior)) {
    el('wifi-channel').append(option(prior, prior + ' · сохранено, сейчас не подтверждено адаптером'));
  }
  if ([...el('wifi-channel').options].some(x => x.value === prior)) el('wifi-channel').value = prior;
  const selected = Number(el('wifi-channel').value);
  const widths = new Set(Object.entries(radioBands).filter(([b]) => band === 'auto' || b === band).flatMap(([, c]) => c.channels.filter(x => !selected || x.number === selected).flatMap(x => x.widths || [20])));
  for (const width of ['20', '40', '80']) el('wifi-width').querySelector('[value="' + width + '"]').disabled = !widths.has(Number(width));
  const selectedWidth = el('wifi-width').selectedOptions[0];
  if (selectedWidth?.disabled) {
    if (preserve) {
      selectedWidth.disabled = false;
      selectedWidth.title = 'Сохранённое значение; совместимость проверяется при применении.';
    } else el('wifi-width').value = 'auto';
  }
}
el('radio-check').addEventListener('click', () => action(radioRefresh));
el('wifi-band').addEventListener('change', () => radioChannels(false));
el('wifi-channel').addEventListener('change', () => radioChannels(false));
el('wifi-interface').addEventListener('change', () => action(radioRefresh));
el('retry-wifi').addEventListener('click', () => action(async () => {
  message('Пробуем безопасно перезапустить только Wi-Fi…');
  await api('retry-wifi', 'POST', {});
  message('Wi-Fi перезапущен. Проверьте видимость сети и подключение устройств.');
}));
el('check-internet').addEventListener('click', () => action(async () => {
  await api('probe', 'POST', {});
  message('Проверка завершена. Смотри актуальный статус интернета.');
}));
el('support-load').addEventListener('click', () => action(async () => {
  el('support-data').textContent = JSON.stringify(await api('diagnostics'), null, 2);
}));
function system(info) {
  el('system-version').textContent = info.version;
  el('system-uptime').textContent = info.uptime_seconds == null ? 'Нет данных' : Math.floor(info.uptime_seconds / 3600) + ' ч ' + Math.floor(info.uptime_seconds % 3600 / 60) + ' мин';
  el('system-cpu').textContent = info.cpu_percent == null ? 'Нет замера' : info.cpu_percent.toFixed(1) + '%';
  el('system-ram').textContent = info.ram_used == null ? 'Нет данных' : Math.round(info.ram_used / 1048576) + ' / ' + Math.round(info.ram_total / 1048576) + ' MiB';
  el('system-temperature').textContent = info.temperature_c == null ? 'Нет данных' : info.temperature_c.toFixed(1) + ' °C';
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const [saved, status, setup, aps] = await Promise.all([api('profiles'), api('dashboard'), api('setup'), api('ap-profiles')]);
    serverWifi = Object.fromEntries(apFields.map(([, key]) => [key, setup.wifi[key]]).filter(([, value]) => value !== undefined));
    apProfiles = aps.profiles || [];
    apState = aps;
    if (!apProfiles.some(p => p.id === apSelected)) apSelected = aps.active_id || aps.confirmed_id || apProfiles[0]?.id || '';
    renderAPProfiles();
    updateDevices(setup);
    const digest = JSON.stringify(saved.profiles),
      listChanged = digest !== profilesDigest;
    profiles = saved.profiles;
    system(status.system);
    el('live-state').textContent = status.state === 'CHECKING' ? 'Проверяем…' : status.state;
    const newSetupDigest = JSON.stringify(setup);
    if (!loaded) chosen = setup.profile_id || profiles[0]?.id || '';
    if (!loaded || setupDigest !== newSetupDigest) {
      if (!wifiDirty && !apEditing) {
        newAP();
        await radioRefresh();
      }
      if (!dnsDirty) {
        el('dns-mode').value = setup.dns_manual ? 'manual' : 'auto';
        el('manual-dns-label').classList.toggle('hidden', !setup.dns_manual);
        if (setup.dns_manual) el('dns-servers').value = setup.doh_url || (setup.dns_candidates || []).join(', ');
      }
      loaded = true;
      setupDigest = newSetupDigest;
    }
    if (!profiles.some(profile => profile.id === chosen)) chosen = profiles[0]?.id || '';
    if (listChanged || !el('selected-profile').options.length) renderProfiles();
    profilesDigest = digest;
    el('live-state').textContent = {
      CONNECTED: 'Подключение активно',
      DISCONNECTED: 'Отключён',
      DEGRADED: 'Ошибка подключения',
      CHECKING: 'Подключаемся…',
      BLOCKED: 'Трафик заблокирован'
    }[status.state] || status.state;
    el('internet-state').textContent = {
      PASS: 'Есть подключение',
      FAIL: 'Недоступен',
      'NOT TESTED': 'Не проверен',
      DISCONNECTED: 'Роутер выключен',
      UNKNOWN: 'Нет свежего замера',
      UNVERIFIED: 'Интернет клиентов не проверен'
    }[status.internet.status] || 'Нет данных';
    el('check-time').textContent = status.internet.checked_at ? 'Проверено ' + new Date(status.internet.checked_at * 1000).toLocaleTimeString() : '';
    el('external-ip').textContent = status.external_ip || 'Нет данных';
    el('active-name').textContent = status.profile?.name || (status.state === 'CHECKING' ? 'Проверяем соединение…' : 'Не подключено');
    el('active-kind').textContent = labels[status.profile?.type] || '';
    const vpn = status.vpn;
    el('vpn-status').textContent = vpn ? 'Interface: ' + (vpn.interface_active === true ? 'Active' : vpn.interface_active === false ? 'Down' : 'Unknown') + ' · handshake: ' + (vpn.handshake || 'Unknown') + ' · tunnel routing: ' + (vpn.tunnel_routing || 'Unknown') + ' · client connectivity: UNVERIFIED' : '';
    el('dns-state').textContent = {
      PASS: 'DNS доступен',
      FAIL: 'DNS недоступен',
      UNKNOWN: 'Нет свежих данных DNS',
      'NOT TESTED': 'DNS не проверен'
    }[status.dns?.status] || 'DNS не проверен';
    el('dns-resolver').textContent = status.dns?.resolver || '';
    el('ssid').textContent = status.ssid || (status.ap === 'DISABLED' ? 'Выключен' : 'Нет свежих данных');
    el('ap-status').textContent = (status.wifi_health?.state || {
      ACTIVE: 'Active',
      DISABLED: 'Ready / Stopped',
      DEGRADED: 'Degraded',
      UNKNOWN: 'Unknown'
    }[status.ap] || status.ap) + (status.mac ? ' · ' + status.mac : '') + (status.radio?.observed?.channel ? ' · ' + status.radio.observed.band + ' GHz / ch ' + status.radio.observed.channel + ' / ' + status.radio.observed.width_mhz + ' MHz (iw)' : ' · Ширина AP не измерена') + (status.radio?.configuration_mode ? ' · план: ' + status.radio.configuration_mode : '') + (status.radio?.fallback_reason ? ' · Выбран запасной режим после отказа драйвера' : '');
    el('wifi-active').textContent = 'Wi-Fi: ' + el('ap-status').textContent;
    const health = status.wifi_health || {};
    el('wifi-health-summary').textContent = 'PiRate: ' + (status.service || 'Unknown') + ' · hostapd: ' + (health.hostapd_process || 'Unknown') + ' · control: ' + (health.control_state || 'Unknown') + ' · interface: ' + (health.interface || 'Unknown') + ' · driver: ' + (health.driver?.state || 'Unknown') + ' · clients: ' + (status.clients == null ? 'Unknown' : status.clients.length);
    el('wifi-health-advice').textContent = status.wifi_failure ? 'Не удалось запустить Wi-Fi. Повторите запуск или проверьте адаптер.' : health.reason ? 'Проверьте адаптер и повторите запуск Wi-Fi.' : '';
    el('wifi-health-details').textContent = JSON.stringify({
      last_apply_failure: status.wifi_apply_failure,
      ownership: status.wifi_ownership,
      health: health,
      recovery: status.wifi_recovery,
      power_save: status.wifi_power_save,
      control_directory: status.wifi_control_directory
    }, null, 2);
    pending = Boolean(status.pending);
    const cooldown = status.wifi_recovery?.retry_after || 0;
    retryBlocked = Boolean(status.pending) || cooldown > 0 || status.ap === 'DISABLED';
    canDisconnect = Boolean(status.profile) || status.ap === 'ACTIVE' || pending;
    canProbe = Boolean(status.profile) && status.state !== 'CHECKING';
    el('disconnect').disabled = busy || !canDisconnect;
    el('wifi-off').disabled = busy || !canDisconnect;
    el('check-internet').disabled = busy || !canProbe;
    el('retry-wifi').disabled = busy || retryBlocked;
    el('wifi-retry').disabled = busy || retryBlocked;
    el('retry-wifi').textContent = 'Повторить запуск Wi-Fi' + (cooldown ? ' (' + cooldown + ' с)' : '');
    el('speed').textContent = status.speed ? '↓ ' + (status.speed.tx_bps / 1e6).toFixed(2) + ' · ↑ ' + (status.speed.rx_bps / 1e6).toFixed(2) + ' Мбит/с' : 'Нет замера';
    el('client-count').textContent = status.clients == null ? '' : String(status.clients.length);
    el('client-list').replaceChildren();
    if (status.clients == null) el('client-list').textContent = status.ap === 'DISABLED' ? 'Wi-Fi выключен' : 'Данные драйвера недоступны';else if (!status.clients.length) el('client-list').textContent = 'Нет подключённых клиентов';else for (const client of status.clients) {
      const row = document.createElement('p');
      row.textContent = (client.hostname || 'Клиент') + ' · ' + (client.ip || 'IP не предоставлен') + ' · ' + client.mac + (client.signal_dbm == null ? '' : ' · ' + client.signal_dbm + ' dBm') + ['tx', 'rx'].map(d => client[d + '_mbps'] == null ? '' : ' · ' + d.toUpperCase() + ' ' + client[d + '_mbps'] + ' Мбит/с' + (client[d + '_mode'] ? ' ' + client[d + '_mode'] : '') + (client[d + '_width_mhz'] ? ' ' + client[d + '_width_mhz'] + ' MHz' : '')).join('');
      if (client.warning) row.textContent += ' · ' + client.warning;
      el('client-list').append(row);
    }
    el('confirmation').classList.toggle('hidden', !status.pending);
    el('countdown').textContent = 'Подтверди работу клиентов за ' + status.seconds_remaining + ' сек. Иначе вернётся предыдущая настройка.';
    el('restore-state').textContent = {
      SAVED: 'Настройка сохранена для восстановления после перезапуска.',
      DISABLED: 'Автоматический запуск роутера выключен.',
      RESTORED: 'Подтверждённая настройка восстановлена.',
      RESTORING: 'Восстанавливаем подтверждённую настройку…',
      BLOCKED: 'Восстановление не удалось. Трафик заблокирован.',
      'NOT CONFIGURED': 'Настройка для восстановления ещё не подтверждена.'
    }[status.restore] || '';
    system(status.system);
    if (status.error && activeScreen === 'dashboard' && !editing && !ovpnDraft) {
      el('connection-error-detail').textContent = status.error;
      message(friendlyError({
        error: status.error
      }, 400), true);
    }
    el('wifi-error-detail').textContent = status.wifi_failure?.detail || status.radio?.fallback_reason || '';
    el('ap-status').textContent = {
      ACTIVE: 'Точка доступа включена',
      DISABLED: 'Точка доступа выключена',
      DEGRADED: 'Ошибка Wi-Fi',
      UNKNOWN: 'Состояние уточняется'
    }[status.ap] || 'Состояние уточняется';
    el('wifi-clients').replaceChildren(...Array.from(el('client-list').childNodes, node => node.cloneNode(true)));
    if (!el('client-list').childNodes.length) el('wifi-clients').textContent = el('client-list').textContent;
    el('service-state').textContent = 'PiRate: ' + (status.service === 'Running' ? 'работает' : 'нет подтверждения') + ' · Wi-Fi: ' + el('ap-status').textContent + ' · DNS: ' + el('dns-state').textContent;
    if (pending) el('live-state').textContent = 'Ожидает подтверждения';else if (status.restore === 'BLOCKED') el('live-state').textContent = 'Трафик заблокирован';else if (status.state === 'CONNECTED' && status.internet.status !== 'PASS') el('live-state').textContent = 'Подключение активно · интернет не подтверждён';
    buttons();
  } finally {
    refreshing = false;
  }
}
function offline(error) {
  if (pending) el('countdown').textContent = 'Нет связи с роутером. Если подтверждение не поступит вовремя, сервер вернёт прежние настройки.';
  el('live-state').textContent = 'Нет связи с роутером';
  el('internet-state').textContent = 'Нет актуальных данных';
  el('external-ip').textContent = 'Нет актуальных данных';
  el('dns-state').textContent = 'Нет актуальных данных';
  message(error.message, true);
}
el('wifi-form').addEventListener('input', () => {
  wifiDirty = true;
  el('wifi-draft-note').classList.remove('hidden');
});
for (const id of ['dns-mode', 'dns-servers']) el(id).addEventListener('input', () => {
  dnsDirty = true;
});
el('wifi-retry').addEventListener('click', () => el('retry-wifi').click());
el('clear-auth').addEventListener('change', () => {
  for (const key of ['username', 'password']) el('profile-form').elements[key].disabled = el('clear-auth').checked;
});
el('wifi-off').addEventListener('click', () => action(async () => {
  await api('disconnect', 'POST', {});
  message('Wi-Fi и роутер выключены. Трафик клиентов заблокирован.');
}));
el('system-diagnostics').addEventListener('click', () => action(async () => {
  el('system-diagnostics-data').textContent = JSON.stringify(await api('diagnostics'), null, 2);
}));
el('admin-form').addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    if (el('admin-new').value !== el('admin-repeat').value) throw new Error('Новые пароли не совпадают.');
    await api('system', 'POST', {
      current_password: el('admin-current').value,
      new_password: el('admin-new').value
    });
    el('admin-form').reset();
    message('Пароль изменён. При следующем запросе браузера войдите с новым паролем.');
  });
});
async function loadSystem() {
  try {
    const info = await api('system');
    el('admin-form').classList.toggle('hidden', !info.password_change_available);
    el('admin-availability').textContent = info.password_change_available ? 'От 8 до 20 символов. После смены войдите с новым паролем.' : 'В локальной панели без аутентификации смена пароля недоступна.';
  } catch (error) {
    el('admin-availability').textContent = error.message;
  }
}
const preflightLabels = {passed:'Работает', failed:'Не работает', inconclusive:'Не работает', not_checked:'', checking:'Проверяется...'};
let preflightState = {results:{}, running:0}, logsBusy = false, preflightBusy = false, logProfile = null;
function logFilters() {
  const filters = {component:el('logs-component').value || 'all', severity:el('logs-severity').value || 'all', search:el('logs-search').value || ''};
  if (logProfile) filters.profile_id = logProfile;
  return filters;
}
function openLogs(component='all', profile=null) {
  el('logs-component').value = component === 'direct' ? 'core' : component;
  el('logs-severity').value = 'all';
  logProfile = profile;
  screen('logs');
}
async function refreshLogs() {
  if (logsBusy) return;
  logsBusy = true;
  try {
    const data = await api('support/logs', 'POST', logFilters());
    const terminal = el('logs-entries');
    const oldTop = terminal.scrollTop || 0;
    const follow = !terminal.textContent || terminal.scrollHeight - oldTop - terminal.clientHeight < 30;
    const errors = data.entries.filter(row => row.severity === 'error');
    el('logs-latest').textContent = errors.length ? errors[errors.length-1].message : 'Нет ошибок в текущем фильтре.';
    el('logs-scope').textContent = 'UTC · ' + (logProfile ? 'Последняя попытка выбранного профиля · ' : '') + 'До ' + data.limit + ' событий. Неизвестные время/PID обозначены прочерком/?.';
    terminal.textContent = data.entries.map(row => row.line || row.message).join('\n');
    terminal.scrollTop = follow ? terminal.scrollHeight : oldTop;
  } catch (error) { el('logs-latest').textContent = error.message; }
  finally { logsBusy = false; }
}
async function refreshPreflight() {
  if (preflightBusy) return;
  preflightBusy = true;
  try {
    preflightState = await api('support/preflight');
    el('check-all').disabled = preflightState.running > 0;
    el('check-cancel').disabled = !preflightState.running;
    renderProfiles();
  } catch (error) { message(error.message, true); }
  finally { preflightBusy = false; }
}
async function checkProfile(id=null) {
  try {
    preflightState = await api('support/preflight','POST',id ? {profile_id:id} : {all:true});
    renderProfiles();
    el('check-all').disabled = preflightState.running > 0;
    el('check-cancel').disabled = !preflightState.running;
  } catch (error) { message(error.message,true); }
}
async function supportDownload(path, body, filename) {
  try {
    const response = await fetch('/api/mvp/support/'+path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if (!response.ok) throw new Error('Не удалось выгрузить диагностику. Проверьте авторизацию и повторите попытку.');
    const url = URL.createObjectURL(await response.blob()), link = document.createElement('a');
    link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url),1000);
  } catch (error) { message(error.message,true); }
}
el('logs-component').addEventListener('change',()=>{logProfile=null;refreshLogs();});
el('logs-severity').addEventListener('change',refreshLogs);
el('logs-search').addEventListener('input',refreshLogs);
el('logs-refresh').addEventListener('click',refreshLogs);
el('logs-clear-profile').addEventListener('click',()=>{logProfile=null;refreshLogs();});
el('logs-copy').addEventListener('click',async()=>{
  try { await navigator.clipboard.writeText(el('logs-latest').textContent); }
  catch (_) { message('Буфер обмена недоступен; выделите и скопируйте текст ошибки.',true); }
});
el('logs-download').addEventListener('click',()=>supportDownload('logs.log',logFilters(),'pirate-filtered.log'));
el('diagnostics-download').addEventListener('click',()=>supportDownload('diagnostics.zip',{},'pirate-diagnostics.zip'));
el('check-all').addEventListener('click',()=>checkProfile());
el('check-cancel').addEventListener('click',async()=>{
  try { preflightState=await api('support/preflight-cancel','POST',{});renderProfiles(); }
  catch(error){message(error.message,true);}
});
el('open-logs').addEventListener('click',()=>openLogs(profiles.find(p=>p.id===chosen)?.type || 'core',chosen || null));
setInterval(()=>{
  if (activeScreen==='logs') refreshLogs();
  if (activeScreen==='connections' || preflightState.running) refreshPreflight();
},5000);

reset();
if (['dashboard', 'connections', 'wifi', 'system', 'logs'].includes(location.hash.slice(1))) screen(location.hash.slice(1));
refresh().catch(offline);
loadSystem();
setInterval(() => {
  if (!busy) refresh().catch(offline);
}, 3000);
