'use strict';
const base = location.pathname.startsWith('/debrescuestick') ? '/debrescuestick' : '';
const form = document.querySelector('#request');
const submit = document.querySelector('#submit');
const errorBox = document.querySelector('#error');
let current=null, lastJob=null, lastError=null, availability='checking';
function error(message) { lastError=message||'The request could not be completed.';errorBox.textContent=UI.error(lastError);errorBox.hidden=false; }
function renderJob(job) {
  document.querySelector('#result').hidden=false;
  document.querySelector('#state').textContent=UI.text(['queued','personalizing','compressing','ready','failed'].includes(job.state)?job.state:'checkingJob');
  document.querySelector('#fingerprint').textContent=UI.text('fingerprint',{fingerprint:job.fingerprint});
  document.querySelector('#expiry').textContent=UI.text('expires',{date:UI.date(job.expires*1000)});
  const link=document.querySelector('#download');link.hidden=job.state!=='ready';
  document.querySelector('#identity').hidden=job.state!=='ready';
  if(job.state==='ready') {
    link.href=base+'/download/'+job.id;
    document.querySelector('#checksum').textContent=job.sha256;
    document.querySelector('#size').textContent=UI.text('imageSize',{size:UI.size(job.bytes)});
  }
}
function renderText() {
  document.querySelector('#availability').textContent=UI.text(availability);
  if(lastJob&&current===lastJob.id)renderJob(lastJob);
  if(lastError!==null)errorBox.textContent=UI.error(lastError);
}
UI.subscribe(renderText);renderText();
async function request(path, options) {
  const response=await fetch(base+path,options);
  const data=await response.json();
  if(!response.ok) {
    const failure=new Error(data.error||'The request could not be completed.');
    failure.status=response.status;throw failure;
  }
  return data;
}
async function show(id) {
  if(current!==id)return;
  try {
    const job=await request('/api/jobs/'+id);
    if(current!==id)return;
    lastError=null;errorBox.hidden=true;sessionStorage.setItem('drs-job',id);
    lastJob=job;renderJob(job);
    if(job.state==='ready')setTimeout(()=>{if(current===id)show(id);},60000);
    else if(job.state==='failed')error(job.error);
    else setTimeout(()=>{if(current===id)show(id);},3000);
  } catch(e) {
    if(current!==id)return;
    error(e.message);
    if(e.status===404||e.status===410) {
      current=null;lastJob=null;sessionStorage.removeItem('drs-job');
      document.querySelector('#result').hidden=true;
      document.querySelector('#download').hidden=true;document.querySelector('#identity').hidden=true;
    } else setTimeout(()=>{if(current===id)show(id);},3000);
  }
}
form.addEventListener('submit',async event=>{
  event.preventDefault();lastError=null;errorBox.hidden=true;submit.disabled=true;
  try {
    const job=await request('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_key:document.querySelector('#key').value})});
    current=job.id;sessionStorage.setItem('drs-job',job.id);
    document.querySelector('#key').value='';await show(job.id);
  } catch(e) {error(e.message);submit.disabled=false;}
});
request('/api/status').then(data=>{
  submit.disabled=!data.available;
  const sourceLink=document.querySelector('#sources');
  if(sourceLink&&data.sources_url){sourceLink.href=data.sources_url;sourceLink.hidden=false;}
  availability=data.available?'available':'unavailable';renderText();
}).catch(()=>{availability='unreachable';renderText();});
const saved=sessionStorage.getItem('drs-job');if(saved&&saved.length===48&&Array.from(saved).every(c=>'0123456789abcdef'.includes(c))){current=saved;show(saved);}
