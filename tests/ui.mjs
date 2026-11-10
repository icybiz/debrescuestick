import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs/promises';

const source=await fs.readFile(new URL('../static/app.js',import.meta.url),'utf8');
const uiSource=await fs.readFile(new URL('../static/ui.js',import.meta.url),'utf8');
const first='a'.repeat(48),second='b'.repeat(48);
const job=(id,state='queued')=>({id,state,fingerprint:'SHA256:'+id.slice(0,8),expires:9999999999,bytes:100,sha256:'c'.repeat(64)});
const reply=(status,data)=>({ok:status<400,status,json:async()=>data});
async function settle(){for(let n=0;n<5;n++)await new Promise(resolve=>setImmediate(resolve));}
function page(fetch){
  const nodes=new Map(),storage=new Map([['drs-job',first]]),timers=[];
  const node=selector=>{
    if(!nodes.has(selector))nodes.set(selector,{hidden:true,disabled:true,textContent:'',value:'public test key',listeners:{},addEventListener(name,fn){this.listeners[name]=fn;}});
    return nodes.get(selector);
  };
  node('#download').hidden=false;node('#identity').hidden=false;
  const context=vm.createContext({location:{pathname:'/debrescuestick/'},document:{querySelector:node},
    sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    fetch,setTimeout:(fn,delay)=>timers.push({fn,delay}),console,Date,Error,Array});
  vm.runInContext(uiSource,context);
  vm.runInContext(source,context);
  return {nodes,node,storage,timers,language:code=>vm.runInContext(`UI.choose({language:${JSON.stringify(code)}})`,context)};
}

test('temporary status failures retain the job and recover from authoritative progress',async()=>{
  for(const failure of [503,'network']){
    let attempt=0;
    const fixture=page(async url=>{
      if(url.endsWith('/api/status'))return reply(200,{available:true});
      if(++attempt===1){if(failure==='network')throw new Error('Temporary network loss');return reply(503,{error:'Busy'});}
      return reply(200,job(first));
    });
    await settle();
    assert.equal(fixture.storage.get('drs-job'),first);
    assert.equal(fixture.timers.length,1);
    await fixture.timers.shift().fn();await settle();
    assert.match(fixture.node('#state').textContent,/waiting/);
    assert.equal(fixture.node('#error').hidden,true);
  }
});

test('authoritative expiry removes the stale download and remembered token',async()=>{
  const fixture=page(async url=>url.endsWith('/api/status')?reply(200,{available:true}):reply(404,{error:'Expired'}));
  await settle();
  assert.equal(fixture.storage.has('drs-job'),false);
  assert.equal(fixture.node('#download').hidden,true);
  assert.equal(fixture.node('#identity').hidden,true);
});

test('a late response cannot replace a newer accepted job',async()=>{
  let release;
  const older=new Promise(resolve=>{release=resolve;});
  const fixture=page(async(url,options)=>{
    if(url.endsWith('/api/status'))return reply(200,{available:true});
    if(options?.method==='POST')return reply(202,job(second));
    if(url.endsWith(first))return older;
    return reply(200,job(second,'ready'));
  });
  await settle();
  await fixture.node('#request').listeners.submit({preventDefault(){}});
  release(reply(200,job(first)));await settle();
  assert.equal(fixture.storage.get('drs-job'),second);
  assert.equal(fixture.node('#fingerprint').textContent,'Your key fingerprint: '+job(second).fingerprint);
});

test('language changes preserve the ready job, key draft and checksum without another request',async()=>{
  let calls=0;
  const fixture=page(async url=>{calls++;return url.endsWith('/api/status')?reply(200,{available:true}):reply(200,job(first,'ready'));});
  await settle();const before=calls;
  for(const language of ['de','fr','es','en']){
    fixture.language(language);await settle();
    assert.equal(calls,before);assert.equal(fixture.node('#key').value,'public test key');
    assert.equal(fixture.storage.get('drs-job'),first);assert.equal(fixture.node('#download').hidden,false);
    assert.equal(fixture.node('#checksum').textContent,'c'.repeat(64));
  }
  fixture.language('de');assert.match(fixture.node('#state').textContent,/bereit/);
  fixture.language('fr');assert.match(fixture.node('#state').textContent,/prête/);
  fixture.language('es');assert.match(fixture.node('#state').textContent,/lista/);
});
test('language changes translate an API rejection without losing input or re-submitting it',async()=>{
  let posts=0;
  const fixture=page(async(url,options)=>{
    if(options?.method==='POST'){posts++;return reply(400,{error:'Paste one public key line, never a private key.'});}
    return url.endsWith('/api/status')?reply(200,{available:true}):reply(200,job(first,'ready'));
  });
  await settle();await fixture.node('#request').listeners.submit({preventDefault(){}});
  for(const [language,phrase] of [['de','privaten Schlüssel'],['fr','clé privée'],['es','clave privada']]){
    fixture.language(language);assert.ok(fixture.node('#error').textContent.includes(phrase));
    assert.equal(fixture.node('#key').value,'public test key');assert.equal(fixture.node('#submit').disabled,false);
  }
  assert.equal(posts,1);
});
test('language changes cannot revive an expired download and a new request can still progress',async()=>{
  const fixture=page(async(url,options)=>{
    if(url.endsWith('/api/status'))return reply(200,{available:true});
    if(options?.method==='POST')return reply(202,job(second));
    return url.endsWith(first)?reply(404,{error:'The download has expired.'}):reply(200,job(second,'ready'));
  });
  await settle();fixture.language('de');
  assert.equal(fixture.node('#result').hidden,true);assert.equal(fixture.node('#download').hidden,true);
  assert.ok(fixture.node('#error').textContent.includes('abgelaufen'));
  await fixture.node('#request').listeners.submit({preventDefault(){}});await settle();
  assert.equal(fixture.node('#result').hidden,false);assert.equal(fixture.node('#download').hidden,false);
  assert.equal(fixture.storage.get('drs-job'),second);assert.ok(fixture.node('#state').textContent.includes('bereit'));
});
test('an in-flight authoritative response is rendered in the newly selected language',async()=>{
  let release;
  const pending=new Promise(resolve=>{release=resolve;});
  const fixture=page(async url=>url.endsWith('/api/status')?reply(200,{available:true}):pending);
  await settle();fixture.language('fr');release(reply(200,job(first,'ready')));await settle();
  assert.ok(fixture.node('#state').textContent.includes('prête'));assert.equal(fixture.node('#download').hidden,false);
});
