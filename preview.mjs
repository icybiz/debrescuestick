import fs from 'node:fs/promises';
import path from 'node:path';

const [port,url,out,mode,job]=process.argv.slice(2),live=mode==='live';
const expected=live?'Image preparation is available · no registration needed':'Image preparation is currently unavailable. Please try again later.';
if(!port||!url||!out)throw new Error('Own forwarded CDP port, preview URL and artifact directory required');
let target,lastError;
for(let attempt=0;attempt<50;attempt++){
  try{target=await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`,{method:'PUT'}).then(r=>r.json());break;}
  catch(error){lastError=error;await new Promise(resolve=>setTimeout(resolve,200));}
}
if(!target)throw lastError;
const endpoint=new URL(target.webSocketDebuggerUrl);endpoint.port=port;
const socket=new WebSocket(endpoint);
await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
let sequence=0;const pending=new Map(),errors=[];
socket.onmessage=event=>{
  const value=JSON.parse(event.data);
  if(value.method==='Runtime.exceptionThrown')errors.push(value.params);
  if(!value.id)return;
  const pair=pending.get(value.id);pending.delete(value.id);
  if(value.error)pair?.reject(new Error(JSON.stringify(value.error)));else pair?.resolve(value.result);
};
function call(method,params={}){
  return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
}
async function evaluate(expression){const value=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(value.exceptionDetails)throw new Error(JSON.stringify(value.exceptionDetails));return value.result.value;}
async function until(expression,timeout=20000){
  const end=Date.now()+timeout;
  while(Date.now()<end){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,100));}
  throw new Error('Browser condition timed out: '+expression);
}
async function click(selector){
  const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e||e.hidden)throw new Error('Visible control required');e.scrollIntoView({block:'nearest',behavior:'instant'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
  await call('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});
  await call('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point});
}
async function key(name,code){
  await call('Input.dispatchKeyEvent',{type:'keyDown',key:name,windowsVirtualKeyCode:code});
  await call('Input.dispatchKeyEvent',{type:'keyUp',key:name,windowsVirtualKeyCode:code});
}
async function select(selector,value){
  const count=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.focus({preventScroll:true});return Array.from(e.options).findIndex(o=>o.value===${JSON.stringify(value)});})()`);
  if(count<0)throw new Error('Native select option missing');
  await key('Home',36);for(let i=0;i<count;i++)await key('ArrowDown',40);
  const actual=await evaluate(`document.querySelector(${JSON.stringify(selector)}).value`);
  if(actual!==value)throw new Error('Keyboard select: '+selector+' expected '+value+' found '+actual);
}
async function settings(open=true){
  const current=await evaluate("document.querySelector('#settings-toggle').getAttribute('aria-expanded')==='true'");
  if(current!==open)await click('#settings-toggle');
}
async function shot(name){
  const image=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
  await fs.writeFile(path.join(out,name+'.png'),Buffer.from(image.data,'base64'));
}
let originalPreferences=null,onMain=false;
try{
  await call('Page.enable');await call('Runtime.enable');
  await call('Page.navigate',{url});
  await until("document.readyState==='complete'&&typeof UI!=='undefined'&&document.querySelector('#settings-toggle')");
  onMain=true;originalPreferences=await evaluate("localStorage.getItem('drs-settings-v1')");
  await evaluate("UI.choose({language:'en',appearance:'dark',width:'normal',size:'normal',smooth:false})");
  if(job){
    if(job.length!==48||Array.from(job).some(c=>!'0123456789abcdef'.includes(c)))throw new Error('Own canary token required');
    await evaluate(`sessionStorage.setItem('drs-job',${JSON.stringify(job)})`);await call('Page.reload');
  }
  await until(`document.querySelector('#availability')?.textContent===${JSON.stringify(expected)}&&${job?"document.querySelector('#state')?.textContent.includes('Your personal image is ready')":'true'}`);
  const snapshots=[];
  for(const [name,width,height] of [['desktop',1360,1000],['mobile',390,844]]){
    await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:name==='mobile'});
    await evaluate('scrollTo({top:0,behavior:"instant"})');
    await new Promise(resolve=>setTimeout(resolve,150));
    const state=await evaluate(`({lang:document.documentElement.lang,label:document.querySelector('label[for=key]').textContent,title:document.title,disabled:document.querySelector('#submit').disabled,status:document.querySelector('#availability').textContent,width:innerWidth,scroll:document.documentElement.scrollWidth,sources:{hidden:document.querySelector('#sources')?.hidden,href:document.querySelector('#sources')?.href},job:sessionStorage.getItem('drs-job'),ready:!document.querySelector('#download').hidden,checksum:document.querySelector('#checksum').textContent,assets:performance.getEntriesByType('resource').filter(e=>['style.css','app.js','ui.js'].some(name=>e.name.endsWith(name))).map(e=>({name:e.name,bytes:e.decodedBodySize}))})`);
    await shot(name);
    if(!state.title.includes('DebRescueStick')||state.disabled===live||state.status!==expected||state.lang!=='en'||state.label!=='Your public SSH key'||state.scroll>state.width||state.assets.length!==3||state.assets.some(a=>!a.bytes))throw new Error(name+': '+JSON.stringify(state));
    if(live&&(state.sources.hidden||!state.sources.href.includes('/sources/')))throw new Error('Corresponding-source link missing');
    if(job&&(state.job!==job||!state.ready||state.checksum.length!==64))throw new Error('Real ready job missing');
    snapshots.push({name,...state});
  }
  await call('Emulation.setDeviceMetricsOverride',{width:1680,height:1050,deviceScaleFactor:1,mobile:false});
  await settings();
  const widths={};
  for(const value of ['normal','wide','full']){await select('#page-width',value);widths[value]=await evaluate('document.querySelector("main").getBoundingClientRect().width');}
  if(!(widths.normal<widths.wide&&widths.wide<widths.full))throw new Error('Width controls ineffective: '+JSON.stringify(widths));
  await select('#page-width','normal');
  await select('#appearance','light');
  await select('#text-size','large');
  await call('Page.reload');
  await until("document.readyState==='complete'&&typeof UI!=='undefined'&&document.querySelector('#appearance').value==='light'");
  const persisted=await evaluate('UI.preferences');
  if(persisted.appearance!=='light'||persisted.size!=='large'||persisted.width!=='normal')throw new Error('Preferences did not survive reload');
  await settings();await shot('settings-light-desktop');
  await select('#text-size','normal');await select('#appearance','dark');
  await settings(false);
  await evaluate('document.querySelector("#key").focus({preventScroll:true})');
  await call('Input.insertText',{text:'ssh-ed25519 draft-kept-on-language-change'});
  const translations=[];
  for(const [language,label] of [['en','Your public SSH key'],['de','Dein öffentlicher SSH-Schlüssel'],['fr','Votre clé SSH publique'],['es','Tu clave SSH pública']]){
    await evaluate('scrollTo({top:0,behavior:"instant"})');await settings();await click(`[data-language="${language}"]`);
    await key('Escape',27);
    const keyboard=await evaluate("document.querySelector('#settings-panel').hidden&&document.activeElement===document.querySelector('#settings-toggle')");
    if(!keyboard)throw new Error('Escape did not restore focus to the gear');
    for(const [device,width,height] of [['desktop',1360,1000],['mobile',390,844]]){
      await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:device==='mobile'});
      await evaluate('scrollTo({top:0,behavior:"instant"})');
      const state=await evaluate(`({language:document.documentElement.lang,label:document.querySelector('label[for=key]').textContent,width:innerWidth,scroll:document.documentElement.scrollWidth,draft:document.querySelector('#key').value,job:sessionStorage.getItem('drs-job'),ready:!document.querySelector('#download').hidden,checksum:document.querySelector('#checksum').textContent,untranslated:Array.from(document.querySelectorAll('[data-i18n]')).filter(n=>{const e=document.createElement('div');e.innerHTML=UI.text(n.dataset.i18n);return n.innerHTML!==e.innerHTML;}).map(n=>n.dataset.i18n),badAria:Array.from(document.querySelectorAll('[data-i18n-aria]')).filter(n=>n.getAttribute('aria-label')!==UI.text(n.dataset.i18nAria)).map(n=>n.dataset.i18nAria)})`);
      if(state.language!==language||state.label!==label||state.scroll>state.width||state.untranslated.length||state.badAria.length||state.draft!=='ssh-ed25519 draft-kept-on-language-change')throw new Error('Translation: '+JSON.stringify(state));
      if(job&&(state.job!==job||!state.ready||state.checksum.length!==64))throw new Error('Language change lost the ready job');
      await shot(language+'-'+device);translations.push({device,...state});
    }
  }
  await click('[data-i18n=writeTitle]');
  const writeGuide=await evaluate("Object.fromEntries(['linux','mac','unix'].map(name=>[name,document.querySelector('#'+name+'-command').textContent]))");
  if(!writeGuide.linux.includes('conv=fsync,nocreat')||!writeGuide.mac.includes('diskutil unmountDisk')||!writeGuide.unix.includes('bs=1048576'))throw new Error('dd instructions missing');
  await evaluate("document.querySelector('#linux-command').scrollIntoView({block:'center',behavior:'instant'})");await shot('linux-write-mobile');
  await evaluate("document.querySelector('#mac-command').scrollIntoView({block:'center',behavior:'instant'})");await shot('mac-write-mobile');
  await evaluate('scrollTo({top:0,behavior:"instant"})');
  await settings();await select('#appearance','light');await select('#text-size','larger');
  const largeMobile=await evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})');
  if(largeMobile.scroll>largeMobile.width)throw new Error('Large text causes mobile overflow');
  await shot('settings-light-mobile');await select('#text-size','normal');
  await select('#appearance','dark');await shot('settings-dark-mobile');
  await key('Escape',27);
  // A page click outside the open panel also closes it without changing the draft.
  await settings();
  await call('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,x:5,y:5});
  await call('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,x:5,y:5});
  if(!await evaluate('document.querySelector("#settings-panel").hidden'))throw new Error('Outside click did not close the panel');
  const rejections=[];
  if(live){
    for(const [language,message] of [['en','Paste one public key line, never a private key.'],['de','Füge eine öffentliche Schlüsselzeile ein, niemals einen privaten Schlüssel.'],['fr','Collez une ligne de clé publique, jamais de clé privée.'],['es','Pega una línea de clave pública, nunca una clave privada.']]){
      await evaluate('scrollTo({top:0,behavior:"instant"})');await settings();await click(`[data-language="${language}"]`);await key('Escape',27);
      await evaluate("document.querySelector('#key').value='';document.querySelector('#key').focus({preventScroll:true})");
      await call('Input.insertText',{text:'-----BEGIN PRIVATE KEY-----\nsynthetic test marker'});
      await click('#submit');
      await until(`!document.querySelector('#error').hidden&&document.querySelector('#error').textContent===${JSON.stringify(message)}`);
      const state=await evaluate("({message:document.querySelector('#error').textContent,disabled:document.querySelector('#submit').disabled,job:sessionStorage.getItem('drs-job'),ready:!document.querySelector('#download').hidden})");
      if(state.disabled||(job&&(state.job!==job||!state.ready)))throw new Error('Rejected key blocked progress or removed a ready image');
      rejections.push({language,...state});
    }
    await evaluate("document.querySelector('#key').value='';document.querySelector('#error').scrollIntoView({block:'center',behavior:'instant'})");await shot('private-key-rejected');
  }
  await evaluate("sessionStorage.removeItem('drs-job')");
  await evaluate(originalPreferences===null?"localStorage.removeItem('drs-settings-v1')":`localStorage.setItem('drs-settings-v1',${JSON.stringify(originalPreferences)})`);
  onMain=false;
  const archiveUrl=live?'https://mindbytez.com/oss/':url+'archive/';
  await call('Page.navigate',{url:archiveUrl});
  await until("document.readyState==='complete'&&document.querySelector('h1')?.textContent==='The rescue project has a new home.'");
  const archive=[];
  for(const [name,width,height] of [['desktop',1360,1000],['mobile',390,844]]){
    await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:name==='mobile'});
    const state=await evaluate("({lang:document.documentElement.lang,title:document.title,heading:document.querySelector('h1')?.textContent,width:innerWidth,scroll:document.documentElement.scrollWidth,download:document.querySelector('a[download]')?.getAttribute('href'),next:document.querySelector('.button')?.href})");
    if(state.lang!=='en'||state.heading!=='The rescue project has a new home.'||state.scroll>state.width||state.download!=='usb_inst_Mod.sh'||state.next!=='https://eorls.com/debrescuestick/')throw new Error('Archive: '+JSON.stringify(state));
    await shot('archive-'+name);archive.push({name,...state});
  }
  if(errors.length)throw new Error(JSON.stringify(errors));
  await fs.writeFile(path.join(out,'browser.json'),JSON.stringify({success:true,snapshots,translations,widths,persisted,largeMobile,archive,rejections,writeGuide,errors},null,2)+'\n');
}finally{
  try{
    if(onMain){
      await evaluate("sessionStorage.removeItem('drs-job')");
      await evaluate(originalPreferences===null?"localStorage.removeItem('drs-settings-v1')":`localStorage.setItem('drs-settings-v1',${JSON.stringify(originalPreferences)})`);
    }
  }catch{}
  socket.close();
  await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`);
}
