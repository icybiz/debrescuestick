import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
const source=await fs.readFile(new URL('../static/ui.js',import.meta.url),'utf8');
function fixture({stored=null,url='https://example.test/debrescuestick/',blocked=false,dark=false,reduced=false}={}){
  const data=new Map(stored===null?[]:[['drs-settings-v1',stored]]),root={dataset:{}},events={};
  const media={dark:{matches:dark},reduced:{matches:reduced}};
  for(const item of Object.values(media))item.addEventListener=(name,fn)=>{item.change=fn;};
  const location={href:url};
  const context=vm.createContext({URL,location,document:{documentElement:root,readyState:'loading',addEventListener:(name,fn)=>{events[name]=fn;}},
    localStorage:{getItem:key=>{if(blocked)throw new Error('blocked');return data.get(key);},setItem:(key,value)=>{if(blocked)throw new Error('blocked');data.set(key,value);}},
    history:{state:null,replaceState(state,unused,url){location.href=url;}},matchMedia:query=>query.includes('color-scheme')?media.dark:media.reduced});
  vm.runInContext(source,context);
  const read=expression=>JSON.parse(vm.runInContext(`JSON.stringify(${expression})`,context));
  const choose=value=>vm.runInContext(`UI.choose(${JSON.stringify(value)})`,context);
  return {root,data,media,location,read,choose};
}
test('invalid, unavailable and blocked preference storage keeps a usable English default',()=>{
  for(const stored of ['{broken','null','[]','"string"','{"language":"../../bad","appearance":"neon","width":"50000","size":999,"smooth":"false"}']){
    const page=fixture({stored});assert.equal(page.read('UI.language'),'en');assert.equal(page.root.dataset.width,'normal');
  }
  const page=fixture({blocked:true});page.choose({language:'fr',appearance:'light'});
  assert.equal(page.read('UI.language'),'fr');assert.equal(page.root.dataset.theme,'light');
});
test('all four languages, layout and colour choices survive a fresh page without persisting form data',()=>{
  for(const language of ['en','de','fr','es']){
    const page=fixture();page.choose({language,appearance:'dark',width:'wide',size:'large',smooth:false,public_key:'NEVER STORE'});
    const raw=page.data.get('drs-settings-v1');assert.ok(!raw.includes('NEVER STORE'));
    const next=fixture({stored:raw});assert.equal(next.read('UI.language'),language);
    assert.equal(next.root.dataset.theme,'dark');assert.equal(next.root.dataset.width,'wide');assert.equal(next.root.dataset.size,'large');assert.equal(next.root.dataset.scroll,'direct');
    assert.ok(next.read('UI.text("ready")').length>10);
  }
});
test('a language URL overrides remembered language and keeps the current section',()=>{
  const page=fixture({stored:'{"language":"de"}',url:'https://example.test/debrescuestick/?lang=fr#image'});
  assert.equal(page.read('UI.language'),'fr');page.choose({language:'es'});
  assert.equal(new URL(page.location.href).searchParams.get('lang'),'es');assert.equal(new URL(page.location.href).hash,'#image');
});
test('system appearance follows the OS while an explicit appearance remains selected',()=>{
  const page=fixture();assert.equal(page.root.dataset.theme,'light');
  page.media.dark.matches=true;page.media.dark.change();assert.equal(page.root.dataset.theme,'dark');
  page.choose({appearance:'light'});page.media.dark.change();assert.equal(page.root.dataset.theme,'light');
});
test('reduced motion overrides smooth scrolling and restores the saved preference afterwards',()=>{
  const page=fixture({reduced:true});assert.equal(page.root.dataset.scroll,'direct');
  assert.equal(page.read('UI.preferences.smooth'),true);
  page.media.reduced.matches=false;page.media.reduced.change();assert.equal(page.root.dataset.scroll,'smooth');
  page.choose({smooth:false});page.media.reduced.change();assert.equal(page.root.dataset.scroll,'direct');
});
test('preferences cannot be mutated through the public snapshot and reset removes invalid values',()=>{
  const page=fixture();page.choose({language:'de',width:'full'});
  page.read('(UI.preferences.language="es",UI.language)');assert.equal(page.read('UI.language'),'de');
  page.choose({language:'en',appearance:'system',width:'normal',size:'normal',smooth:true});
  assert.equal(page.read('UI.language'),'en');assert.equal(page.root.dataset.width,'normal');
});
