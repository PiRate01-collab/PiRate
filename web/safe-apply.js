// Synthetic Safe Apply only. Browser timers never implement the watchdog.
(() => {
  const el = id => document.getElementById(id);
  let operation = null, pending = false, blocked = false;
  async function api(action, data) {
    const response = await fetch('/api/wifi/mock-apply/' + action, data === undefined ?
      {cache:'no-store'} : {method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    const result = await response.json();
    if (result.state === 'recovery_required') blocked = true;
    else if (response.ok && action === 'status') blocked = false;
    if (!response.ok) throw new Error(result.error || 'Mock request failed');
    return result;
  }
  function render() {
    el('mock-state').textContent = `${blocked ? 'recovery_required' : operation?.state || 'idle'} · Mock Only${operation ? ' · ' + operation.operation_id : ''}`;
    const waiting = operation?.state === 'awaiting_confirmation';
    el('mock-countdown').textContent = waiting ? `Confirmation Countdown: ${Math.max(0, operation.expires_at - Math.floor(Date.now()/1000))} s · simulation` : 'Confirmation Countdown: —';
    el('mock-confirm').disabled = pending || blocked || !waiting;
    el('mock-rollback').disabled = pending || !operation || ['confirmed','rolled_back'].includes(operation.state);
    el('mock-start').disabled = pending || blocked || !el('mock-profile').value || !!operation && !['confirmed','rolled_back'].includes(operation.state);
    if (operation?.diagnostics?.length) el('mock-message').textContent = operation.diagnostics.join(', ');
  }
  async function run(action, data) {
    pending = true;el('mock-message').textContent = '';render();
    try {
      const result = await api(action, data);
      if (action === 'preview') {
        el('mock-changes').textContent = JSON.stringify(result, null, 2);el('mock-changes').classList.remove('hidden');
      } else if (result.operations) {
        operation = result.operations.filter(x => x.interface === 'mock-wlan0').at(-1) || operation;
      } else if (result.operation_id) operation = result;
      if (result.state === 'recovery_required') el('mock-message').textContent = 'recovery_required: журнал требует проверки; реальное применение недоступно.';
    } catch (error) { el('mock-message').textContent = error.message; }
    finally { pending = false;render(); }
  }
  function profilesLoaded(profiles) {
    const select=el('mock-profile'), selected=select.value;select.replaceChildren();
    const empty=document.createElement('option');empty.value='';empty.textContent='Выберите сохранённый профиль';select.append(empty);
    for (const profile of profiles) {
      const option=document.createElement('option');option.value=profile.id;option.textContent=profile.name;select.append(option);
    }
    if ([...select.options].some(x => x.value === selected)) select.value=selected;
    render();
  }
  document.addEventListener('wifi-profiles-loaded', event => profilesLoaded(event.detail));
  // Also populate when wifi.js finished its first request before this script loaded.
  fetch('/api/wifi/profiles', {cache:'no-store'}).then(async response => {
    const result = await response.json();if (!response.ok) throw new Error(result.error || 'Profiles unavailable');
    profilesLoaded(result.profiles);
  }).catch(error => {el('mock-message').textContent = error.message;});
  el('mock-profile').addEventListener('change', render);
  el('mock-preview').addEventListener('click', () => run('preview',{profile_id:el('mock-profile').value}));
  el('mock-start').addEventListener('click', () => run('start',{profile_id:el('mock-profile').value,timeout:Number(el('mock-timeout').value),operation_id:crypto.randomUUID()}));
  el('mock-confirm').addEventListener('click', () => operation && run('confirm',{operation_id:operation.operation_id}));
  el('mock-rollback').addEventListener('click', () => operation && run('rollback',{operation_id:operation.operation_id}));
  el('mock-recover').addEventListener('click', async () => {await run('recover',{});await run('status');});
  setInterval(render, 1000);
  // Read-only polling: no apply or recovery action is driven by the browser countdown.
  setInterval(() => {if (!pending && operation?.state === 'awaiting_confirmation') run('status');}, 3000);
  render();run('status');
})();
