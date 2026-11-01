'use strict';
// Import drafts stay in memory. No localStorage, logging, or automatic saving.
(function(root){
  const MAX_UPLOAD=256*1024;
  async function upload(file,encoding,api){
    if(file.size>MAX_UPLOAD)throw new Error('Файл OpenVPN превышает 256 KiB; UTF-8 config после преобразования — максимум 512 KiB.');
    const bytes=new Uint8Array(await file.arrayBuffer());
    if(bytes.length>MAX_UPLOAD)throw new Error('Файл OpenVPN превышает 256 KiB.');
    let binary='';for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));
    const body={filename:file.name,file_base64:btoa(binary)};
    if(file.name.toLowerCase().endsWith('.ovpn'))body.automatic=true;
    if(encoding)body.encoding=encoding;
    return api('convert-config','POST',body);
  }
  function selectRemote(form,select){
    const index=Number(select.value),remote=select._pirateRemotes?.[index];
    if(!Number.isInteger(index)||!remote)return;
    for(const [key,value] of Object.entries({server:remote.server,port:remote.port,ovpn_proto:remote.proto,ovpn_remote:index}))form.elements[key].value=String(value);
    if(Array.isArray(remote.dns_servers))form.elements.dns_servers.value=remote.dns_servers.join(', ');
  }
  function populate(form,result,select,info){
    const p=result.profile;
    for(const key of ['name','type','server','port','username','password','config','ovpn_proto','ovpn_remote','wg_peer_key','wg_address','wg_allowed_ips','wg_mtu','wg_keepalive'])if(form.elements[key])form.elements[key].value=Array.isArray(p[key])?p[key].join(', '):String(p[key]??'');
    form.elements.dns_servers.value=(p.dns_servers||[]).join(', ');
    remotes(select,result.remotes,p.ovpn_remote||0);
    info.textContent=[result.save_allowed===false?'Файл отклонён локально. Сервер не проверялся.':'Синтаксис проверен локально. Доступность сервера проверяется при подключении.',
      ...(result.diagnostics||[]).map(d=>`Строка ${d.line} · ${d.directive} · ${d.classification}: ${d.message}`),
      result.required_fields?.length?'Заполни поля: '+result.required_fields.join(', '):'',
      
      p.password_saved?'Credentials уже сохранены приватно; пустое поле сохранит их.':''].filter(Boolean).join('\n');
  }
  function remotes(select,items,index){
    select._pirateRemotes=items||[];
    const options=select._pirateRemotes.map((r,i)=>{const option=select.ownerDocument.createElement('option');option.value=String(i);option.textContent=`${i+1}. ${r.server}:${r.port} · ${r.proto}`;return option;});
    select.replaceChildren(...options);select.value=String(index);select.disabled=!options.length;
  }
  const api={upload,populate,selectRemote,remotes,MAX_UPLOAD};root.PiRateOpenVPN=api;
  if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(globalThis);
