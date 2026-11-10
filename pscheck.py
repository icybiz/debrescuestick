"""Run tiny in-memory PowerShell guards on bounded browser.local, then clean up.

Only the pinned vendor runtime and synthetic fixtures are written there.
Project scripts are parsed and evaluated from memory, never installed as files.
This command cannot provide native Windows or Explorer GUI qualification.
"""
import argparse
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent


def key(token):
    if not isinstance(token, str) or len(token) != 10 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('Exact own PowerShell job key required')
    return token


def runtime(token):
    key(token)
    parent = Path('/tmp/debrescuestick-pscheck')
    target = parent / token
    if parent.resolve() != parent or target.resolve() != target or not target.is_relative_to(parent):
        raise ValueError('Foreign runtime path preserved')
    return target


def remove_runtime(token):
    import shutil
    target = runtime(token)
    if not target.exists():
        return
    if target.stat().st_uid != os.getuid() or target.stat().st_mode & 0o077:
        raise ValueError('Foreign runtime owner preserved')
    if json.loads((target / '.owner').read_text()) != {'key': token, 'schema': 'debrescuestick-pscheck-v1'}:
        raise ValueError('Foreign runtime marker preserved')
    # Literal narrow root, validated child and canonical descendant checked above.
    shutil.rmtree('/tmp/debrescuestick-pscheck/' + token)


def cleanup_source(token):
    key(token)
    return ('import os,json\nfrom pathlib import Path\n' +
            '\n'.join(inspect.getsource(fn) for fn in (key, runtime, remove_runtime)) +
            '\nremove_runtime(' + repr(token) + ')\n')


def bootstrap_source(token):
    key(token)
    return 'TOKEN=' + repr(token) + '\n' + inspect.cleandoc('''
        import base64,hashlib,io,json,os,socket,subprocess,sys,tarfile,urllib.request
        from pathlib import Path,PurePosixPath
        assert socket.gethostname().partition('.')[0]=='browser','Assigned browser host required'
        assert os.geteuid()==0,'Bounded root operator required'
        unit='debrescuestick-pscheck-'+TOKEN+'.service'
        assert '0::/system.slice/'+unit in Path('/proc/self/cgroup').read_text().splitlines()
        group=Path('/sys/fs/cgroup/system.slice')/unit
        quota,period=(group/'cpu.max').read_text().split()
        assert quota!='max' and int(quota)/int(period)<=1
        limit=(group/'memory.max').read_text().strip()
        assert limit!='max' and int(limit)<=768*1024**2 and (group/'memory.swap.max').read_text().strip()=='0'
        assert int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))>=1024**2
        payload=json.load(sys.stdin);pin=payload['pin']
        assert pin['url']=='https://github.com/PowerShell/PowerShell/releases/download/v'+pin['version']+'/powershell-'+pin['version']+'-linux-x64.tar.gz'
        parent=Path('/tmp/debrescuestick-pscheck');parent.mkdir(mode=0o700,exist_ok=True)
        assert parent.resolve()==parent and parent.stat().st_uid==0 and not parent.stat().st_mode & 0o077
        run=parent/TOKEN;run.mkdir(mode=0o700)
        (run/'.owner').write_text(json.dumps({'key':TOKEN,'schema':'debrescuestick-pscheck-v1'}))
        assert os.statvfs(run).f_bavail*os.statvfs(run).f_frsize>=600*1024**2
        archive=run/'runtime.tar.gz';digest=hashlib.sha256();amount=0
        with urllib.request.urlopen(pin['url'],timeout=60) as reply,archive.open('xb') as output:
            assert reply.url.startswith('https://')
            while block:=reply.read(1024**2):
                amount+=len(block);assert amount<=pin['bytes'];digest.update(block);output.write(block)
        assert amount==pin['bytes'] and digest.hexdigest()==pin['sha256'],'Pinned runtime bytes/hash differ'
        tool=run/'tool';tool.mkdir(mode=0o700);total=0
        with tarfile.open(archive,'r:gz') as bundle:
            for member in bundle:
                relative=PurePosixPath(member.name)
                assert not relative.is_absolute() and '..' not in relative.parts and '\\\\' not in member.name
                path=tool.joinpath(*relative.parts)
                if member.isdir():path.mkdir(parents=True,exist_ok=True);continue
                assert member.isfile(),'Unexpected runtime link/device preserved'
                total+=member.size;assert total<400*1024**2
                path.parent.mkdir(parents=True,exist_ok=True)
                with bundle.extractfile(member) as source,path.open('xb') as output:
                    while block:=source.read(1024**2):output.write(block)
        archive.unlink();(tool/'pwsh').chmod(0o700)
        env={**os.environ,'POWERSHELL_TELEMETRY_OPTOUT':'1','DOTNET_CLI_TELEMETRY_OPTOUT':'1',
             'XDG_CACHE_HOME':str(run/'cache'),'XDG_CONFIG_HOME':str(run/'config')}
        source=base64.b64encode(payload['source'].encode()).decode()
        tests=base64.b64encode(payload['tests'].encode()).decode()
        receiver=base64.b64encode(payload['receiver'].encode()).decode()
        receiver_tests=base64.b64encode(payload['receiver_tests'].encode()).decode()
        command="$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+source+"'));"
        command+="$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)};. ([scriptblock]::Create($s));"
        command+="$tests=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+tests+"'));& ([scriptblock]::Create($tests)) -FixtureRoot '"+str(run/'fixtures')+"'"
        command+=";$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+receiver+"'));$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($r,[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)};. ([scriptblock]::Create($r));"
        command+="$tests=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+receiver_tests+"'));& ([scriptblock]::Create($tests)) -FixtureRoot '"+str(run/'receiver-fixtures')+"'"
        result=subprocess.run([str(tool/'pwsh'),'-NoLogo','-NoProfile','-NonInteractive','-Command',command],env=env,capture_output=True,text=True)
        if result.returncode:raise RuntimeError(result.stdout+'\\n'+result.stderr)
        rows=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        assert len(rows)==2
        for row in rows:assert row['success'] is True and row['scope']=='portable-powershell-fixtures' and row['nativeWindowsTested'] is False and row['explorerUiTested'] is False
        proof=rows[0];proof['cases']+=rows[1]['cases']
        proof.update(source_sha256=hashlib.sha256(payload['source'].encode()).hexdigest(),tests_sha256=hashlib.sha256(payload['tests'].encode()).hexdigest(),receiver_sha256=hashlib.sha256(payload['receiver'].encode()).hexdigest(),receiver_tests_sha256=hashlib.sha256(payload['receiver_tests'].encode()).hexdigest())
        print(json.dumps(proof))
    ''')


def validate(proof, source, tests, receiver, receiver_tests):
    if proof.get('success') is not True or proof.get('scope') != 'portable-powershell-fixtures':
        raise ValueError('Complete portable test proof required')
    if proof.get('nativeWindowsTested') is not False or proof.get('explorerUiTested') is not False:
        raise ValueError('Portable tests must never claim native qualification')
    for field, value in (('source_sha256', source), ('tests_sha256', tests),
                         ('receiver_sha256', receiver), ('receiver_tests_sha256', receiver_tests)):
        if proof.get(field) != hashlib.sha256(value.encode()).hexdigest():
            raise ValueError('Tested source differs')
    expected = {'hashes-and-lengths', 'real-lock-and-unchanged-metadata', 'asynchronous-forward-progress', 'timeouts-and-false-green-refusal',
                'zip-layout-validation', 'nonrecursive-owned-cleanup', 'non-windows-refusal',
                'fresh-bound-handoff', 'bounded-download-and-reference-sha', 'bound-checker-report', 'receive-owned-cleanup'}
    if set(proof.get('cases', [])) != expected:
        raise ValueError('Missing mandatory portable guards')


def run():
    token = secrets.token_hex(5)
    folder = ROOT / 'artifacts' / ('pscheck-' + token)
    folder.mkdir(mode=0o700, parents=True)
    source = (ROOT / 'explorer.ps1').read_text()
    tests = (ROOT / 'tests/explorer.ps1').read_text()
    receiver = (ROOT / 'receive.ps1').read_text()
    receiver_tests = (ROOT / 'tests/receive.ps1').read_text()
    pin = json.loads((ROOT / 'ps.lock.json').read_text())
    cleanup = shlex.join(['/usr/bin/python3', '-c', cleanup_source(token)])
    command = ['systemd-run', '--unit=debrescuestick-pscheck-' + token, '--wait', '--pipe',
               '--property=CPUQuota=100%', '--property=MemoryMax=768M', '--property=MemorySwapMax=0',
               '--property=Nice=10', '--property=IOWeight=10', '--property=TasksMax=128',
               '--property=RuntimeMaxSec=300', '--property=TimeoutStopSec=20',
               '--property=KillMode=control-group', '--property=ExecStopPost=' + cleanup,
               '/usr/bin/python3', '-c', bootstrap_source(token)]
    result = subprocess.run(['ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
                             '-oConnectTimeout=10', '-oServerAliveInterval=10', '-oServerAliveCountMax=3',
                             'root@browser.local', shlex.join(command)],
                            input=json.dumps({'pin': pin, 'source': source, 'tests': tests,
                                              'receiver': receiver, 'receiver_tests': receiver_tests}),
                            text=True, capture_output=True)
    (folder / 'run.log').write_text(result.stdout + '\nSTDERR\n' + result.stderr)
    if result.returncode:
        raise RuntimeError('PowerShell guards failed: ' + str(folder / 'run.log'))
    proof = json.loads(result.stdout.strip())
    validate(proof, source, tests, receiver, receiver_tests)
    check = subprocess.run(['ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10', 'root@browser.local',
                            'test ! -e /tmp/debrescuestick-pscheck/' + key(token)], capture_output=True)
    if check.returncode:
        raise RuntimeError('Own runtime cleanup not confirmed')
    proof.update(resources_returned=True, key=token, runtime_pin=pin)
    (folder / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'success': True, 'cases': len(proof['cases']), 'nativeWindowsTested': False,
                      'resources_returned': True, 'artifacts': str(folder)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run',))
    parser.parse_args()
    run()
