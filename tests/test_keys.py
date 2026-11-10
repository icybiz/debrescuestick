import base64
from pathlib import Path
import struct
import subprocess
import unittest
from keys import public_key,InvalidKey
from support import workspace,child


def string(value):return struct.pack('>I',len(value))+value


def sample(seed=0):
    return 'ssh-ed25519 '+base64.b64encode(string(b'ssh-ed25519')+string(bytes((n+seed)%256 for n in range(32)))).decode()


class KeyTests(unittest.TestCase):
    def test_security_key_accepted_by_api_also_passes_boot_type_policy(self):
        kind='sk-ssh-ed25519@openssh.com'
        raw=string(kind.encode())+string(bytes(range(32)))+string(b'ssh:')
        key,_=public_key(kind+' '+base64.b64encode(raw).decode())
        source=(Path(__file__).resolve().parents[1]/'image/keys.sh').read_text()
        policy=source[source.index('case "$1"'):source.index('ssh-keygen -l')]
        result=subprocess.run(['sh','-c','set -- "$1"; '+policy,'boot-type-policy',key.split()[0]])
        self.assertEqual(result.returncode,0)

    def test_fixture_refuses_root_empty_traversal_foreign_names(self):
        for value in ('',' ','.','..','/','../escape','a/b','a\\b','%2f','a'*31,'g'*32):
            with self.assertRaises(ValueError):child(value)

    def test_real_openssh_key_fingerprints_and_comments(self):
        with workspace() as folder:
            file=folder/'key'
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(file)],check=True)
            normalized,fingerprint=public_key(file.with_suffix('.pub').read_text())
            expected=subprocess.check_output(['ssh-keygen','-l','-E','sha256','-f',str(file.with_suffix('.pub'))],text=True)
            self.assertIn(fingerprint,expected);self.assertEqual(len(normalized.split()),2)
            self.assertEqual(public_key(normalized.strip()+' command="ignore me"')[0],normalized)

    def test_private_keys_options_truncation_extra_fields_and_weak_rsa_refused(self):
        raw=string(b'ssh-rsa')+string(b'\x01\x00\x01')+string(b'\0'+b'\xff'*128)
        cases=['-----BEGIN OPENSSH PRIVATE KEY-----','command="id" '+sample(),sample()+'\n'+sample(1),
               sample().replace('ssh-ed25519 ','ssh-rsa ',1),'ssh-ed25519 !!!',
               'ssh-rsa '+base64.b64encode(raw).decode()]
        blob=base64.b64decode(sample().split()[1]);cases.extend('ssh-ed25519 '+base64.b64encode(b).decode() for b in (blob[:-1],blob+b'\0'))
        for value in cases:
            with self.subTest(value=value[:35]),self.assertRaises(InvalidKey):public_key(value)


if __name__=='__main__':unittest.main()
