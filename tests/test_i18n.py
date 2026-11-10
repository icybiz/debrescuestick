from html.parser import HTMLParser
import ast
import shlex
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
import urllib.request
import urllib.error

import rollout
import server
from support import workspace
from test_server import serving

ROOT=Path(__file__).resolve().parents[1]


class Markup(HTMLParser):
    def __init__(self):super().__init__();self.keys=set();self.commands={};self.command=None
    def handle_starttag(self,tag,attributes):
        values=dict(attributes)
        if tag=='code' and values.get('id','').endswith('-command'):
            self.command=values['id'];self.commands[self.command]=''
        for name,value in attributes:
            if name in ('data-i18n','data-i18n-aria'):self.keys.add(value)
    def handle_data(self,data):
        if self.command is not None:self.commands[self.command]+=data
    def handle_endtag(self,tag):
        if tag=='code':self.command=None


class LanguageTests(unittest.TestCase):
    def test_all_markup_and_api_errors_have_complete_translations(self):
        text=(ROOT/'static/ui.js').read_text()
        catalog=json.loads(text.partition('  const messages = ')[2].partition(';\n  const defaults')[0])
        self.assertEqual(set(catalog),{'en','de','fr','es'})
        markup=Markup();markup.feed((ROOT/'static/index.html').read_text())
        def spans(value,start,end):return [part.split(end,1)[0] for part in value.split(start)[1:]]
        for language,messages in catalog.items():
            self.assertEqual(set(messages),set(catalog['en']))
            self.assertLessEqual(markup.keys,set(messages))
            self.assertEqual(set(messages['errors']),set(catalog['en']['errors']))
            errors=set(server.ERROR_TEXT.values())
            for node in ast.walk(ast.parse((ROOT/'server.py').read_text())):
                if isinstance(node,ast.Dict):
                    for name,value in zip(node.keys,node.values):
                        if isinstance(name,ast.Constant) and name.value=='error':
                            pending=[value]
                            while pending:
                                child=pending.pop()
                                if isinstance(child,ast.Constant) and isinstance(child.value,str):errors.add(child.value)
                                elif isinstance(child,ast.IfExp):pending.extend((child.body,child.orelse))
            self.assertLessEqual(errors,set(messages['errors']))
            for key,value in messages.items():
                if key=='errors':continue
                self.assertIsInstance(value,str);self.assertTrue(value)
                reference=catalog['en'][key]
                for start,end in (('{','}'),('<code>','</code>'),('href="','"')):
                    self.assertEqual(spans(value,start,end),spans(reference,start,end),(language,key,start))

    def test_ui_asset_is_served_exactly_at_both_mounts_and_in_release_bundle(self):
        raw=(ROOT/'static/ui.js').read_bytes()
        with workspace() as state,serving(state) as (app,url):
            for route in ('/ui.js','/debrescuestick/ui.js'):
                with urllib.request.urlopen(url+route) as reply:
                    self.assertEqual(reply.read(),raw);self.assertIn('text/javascript',reply.headers['Content-Type'])
                    self.assertIn("default-src 'self'",reply.headers['Content-Security-Policy'])
            with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(url+'/static/ui.js')
            self.assertEqual(caught.exception.code,404)
        files,manifest,sha=rollout.bundle()
        self.assertEqual(files['static/ui.js'],raw)
        self.assertEqual(manifest['static/ui.js'],hashlib.sha256(raw).hexdigest())

    def test_persistent_preferences_and_accessibility_rules(self):
        result=subprocess.run(['node','--test',str(ROOT/'tests/i18n.mjs')],capture_output=True,text=True,timeout=15)
        log=ROOT/'artifacts/i18n-preferences.log';log.parent.mkdir(exist_ok=True);log.write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode,0,'Settings tests failed: '+str(log)+'\n'+result.stdout+result.stderr)

    def test_linux_write_example_copies_exact_bytes_and_refuses_missing_target(self):
        markup=Markup();markup.feed((ROOT/'static/index.html').read_text())
        args=shlex.split(markup.commands['linux-command'])
        self.assertEqual(args[:2],['sudo','dd'])
        self.assertIn('conv=fsync,nocreat',args);self.assertIn('status=progress',args)
        with workspace() as root:
            source=root/'input.dat';target=root/'output.dat'
            data=bytes(range(256))*257+b'last partial block'
            source.write_bytes(data);target.write_bytes(b'')
            actual=['dd']+['if='+str(source) if x.startswith('if=') else 'of='+str(target) if x.startswith('of=') else x for x in args[2:]]
            result=subprocess.run(actual,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(target.read_bytes(),data)
            target.unlink();result=subprocess.run(actual,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertFalse(target.exists())

    def test_macos_and_portable_examples_use_separate_flag_sets_and_stop_on_error(self):
        markup=Markup();markup.feed((ROOT/'static/index.html').read_text())
        mac=markup.commands['mac-command'];unix=markup.commands['unix-command']
        self.assertIn('diskutil unmountDisk /dev/diskN &&',mac)
        self.assertIn('of=/dev/rdiskN bs=4m &&',mac)
        self.assertIn('sync &&',mac);self.assertTrue(mac.endswith('diskutil eject /dev/diskN'))
        self.assertNotIn('status=progress',mac);self.assertNotIn('conv=',mac)
        self.assertIn('bs=1048576 && sync',unix)
        for command in (mac,unix):
            checked=subprocess.run(['sh','-n'],input=command,capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stderr)
