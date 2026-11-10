import os
from pathlib import Path
import shlex
import struct
import subprocess
import unittest

import mdns
from support import workspace


class MulticastTests(unittest.TestCase):
    def response(self, hostname=mdns.HOST_NAME, ttl=120, family=0x8001):
        question=mdns.request_packet(hostname)[12:]
        record=b'\xc0\x0c'+struct.pack('!HHIH',1,family,ttl,4)+b'\xc0\x00\x02\x01'
        return struct.pack('!6H',0,0x8400,1,1,0,0)+question+record

    def test_exact_name_address_class_and_live_ttl_are_required(self):
        self.assertEqual(mdns.addresses(self.response(),mdns.HOST_NAME),['192.0.2.1'])
        self.assertEqual(mdns.addresses(self.response('other.local'),mdns.HOST_NAME),[])
        self.assertEqual(mdns.addresses(self.response(ttl=0),mdns.HOST_NAME),[])
        self.assertEqual(mdns.addresses(self.response(family=3),mdns.HOST_NAME),[])
        with self.assertRaises(ValueError):mdns.addresses(mdns.request_packet(mdns.HOST_NAME),mdns.HOST_NAME)

    def test_compressed_names_refuse_cycles_truncation_and_bad_pointers(self):
        for packet in (b'\xc0\x00',b'\xc0',b'\xc0\xff',b'\x40',b'\x03ab'):
            with self.assertRaises(ValueError):mdns.read_name(packet,0)
        full=self.response()
        for length in range(len(full)):
            with self.assertRaises((ValueError,UnicodeError)):mdns.addresses(full[:length],mdns.HOST_NAME)
        with self.assertRaises(ValueError):mdns.addresses(struct.pack('!6H',0,0x8000,513,0,0,0),mdns.HOST_NAME)

    def test_peer_probe_is_guest_only_and_uses_the_tested_parser(self):
        source=mdns.client_source();compile(source,'<mdns-peer>','exec')
        self.assertIn('def read_name(',source);self.assertIn('def addresses(',source)
        self.assertIn("socket.create_connection((server, 22)",source)
        script=mdns.probe_script()
        self.assertIn('ip netns exec drs-mdns-peer',script)
        self.assertIn('trap cleanup EXIT',script)
        self.assertNotIn('root@prox',script);self.assertNotIn('aiserver',script)
        result=subprocess.run(['sh','-n'],input=script,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)


class ConsoleTests(unittest.TestCase):
    def run_info(self, root, ready=True, owner=True, mdns_active=True, name='debrstick.local'):
        tools=root/'bin';tools.mkdir(exist_ok=True)
        scripts={
          'systemctl':'#!/bin/sh\ncase "$*" in *avahi*) exit "$TEST_AVAHI";; *) exit 0;; esac\n',
          'busctl':'#!/bin/sh\ncase "$*" in *GetState) echo "i 2";; *) printf \'s "%s"\\n\' "$TEST_NAME";; esac\n',
          'ip':'#!/bin/sh\nif [ "$TEST_IP" != yes ]; then exit 0; fi\ncase "$1" in -brief) echo "eth0 UP 192.0.2.10/24";; *) echo "2: eth0 inet 192.0.2.10/24 scope global eth0";; esac\n',
          'ssh-keygen':'#!/bin/sh\necho "256 SHA256:PUBLIC-TEST no-comment (ED25519)"\n',
        }
        for command,text in scripts.items():
            target=tools/command;target.write_text(text);target.chmod(0o700)
        key=root/'owner.pub';key.write_text('ssh-ed25519 synthetic-public-key\n' if owner else '')
        hostkeys=root/'hostkeys';hostkeys.mkdir(exist_ok=True)
        (hostkeys/'ssh_host_ed25519_key.pub').write_text('synthetic public host key')
        env={**os.environ,'PATH':str(tools)+':/usr/bin:/bin','DRS_KEY_FILE':str(key),
             'DRS_HOSTKEY_DIR':str(hostkeys),'TEST_IP':'yes' if ready else 'no',
             'TEST_AVAHI':'0' if mdns_active else '1','TEST_NAME':name}
        return subprocess.run(['bash',str(Path(__file__).resolve().parents[1]/'image/info.sh')],
                              capture_output=True,text=True,env=env,timeout=5)

    def test_console_shows_ready_name_ip_and_public_fingerprints(self):
        with workspace() as root:
            result=self.run_info(root)
            self.assertEqual(result.returncode,0,result.stderr)
            for text in ('ssh root@debrstick.local','ssh root@192.0.2.10','SHA256:PUBLIC-TEST','Local rescue shell ready'):
                self.assertIn(text,result.stdout)
            self.assertNotIn('synthetic-public-key',result.stdout)

    def test_waiting_network_and_missing_key_are_reported_without_fake_access(self):
        with workspace() as root:
            result=self.run_info(root,ready=False,owner=False,mdns_active=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Waiting for a network address',result.stdout)
            self.assertIn('owner key has not been loaded',result.stdout)
            self.assertNotIn('  ssh root@',result.stdout)
            self.assertIn('Local rescue shell ready',result.stdout)

    def test_collision_name_is_used_for_the_connection_command(self):
        with workspace() as root:
            result=self.run_info(root,name='debrstick-2.local')
            self.assertIn('ssh root@debrstick-2.local',result.stdout)
