"""Serial, bounded comparison of full compression and reused DEFLATE blocks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import zipfile
import zlib
import base
import fast
import jobs

FILES=('fastprobe.py','fast.py','jobs.py','base.py')


def return_tests(output,source,qa,qualification,failed):
    """Remove only recorded stopped QA disks/ephemeral keys after deployment."""
    parent=Path('/var/lib/debrescuestick');state=parent/'state'
    proof=json.loads((state/'base/template.json').read_text())
    if proof['sha256']!=qualification['sha256']:raise ValueError('Qualified candidate must be deployed first')
    active=subprocess.check_output(['systemctl','show','debrescuestick-qa-worker-'+qa+'.service','--property=ActiveState','--value'],text=True).strip()
    if active not in ('inactive','failed'):raise RuntimeError('Own QA still active')
    if not all(r.get('clean_shutdown') and r.get('qemu_exit')==0 for r in qualification['results']):
        raise RuntimeError('Clean guest shutdown proofs required')
    profile=parent/'qa'/qa;targets=[]
    for job in (profile/'jobs').iterdir():
        if len(job.name)!=48 or any(c not in '0123456789abcdef' for c in job.name):raise ValueError('Unknown QA job preserved')
        if json.loads((job/'.owner').read_text())!={'job':job.name,'schema':'drs-job-v1'}:raise ValueError('Foreign job preserved')
        targets.extend([job/'image.img',job/'image.tail'])
    targets.extend(profile/name for name in ('key-a','key-a.pub','key-b','key-b.pub','uefi/OVMF_VARS.fd'))
    if failed:
        base.key(failed);previous=parent/'fast'/('run-'+failed)
        record=json.loads((previous/'result.json').read_text())
        if record.get('success') is not False or record.get('error')!='RuntimeError: Template must have no authorized key, machine id, host private key or build marker':
            raise ValueError('Exact own cold failed build required')
        active=subprocess.check_output(['systemctl','show','debrescuestick-base-'+failed+'.service','--property=ActiveState','--value'],text=True).strip()
        if active not in ('inactive','failed'):raise RuntimeError('Own failed build still active')
        targets.append(base.REMOTE/('image-'+failed)/'base.img')
    checked=[]
    for path in targets:
        if path.resolve()!=path or not path.is_relative_to(parent):raise ValueError('Linked/foreign artifact preserved')
        if not path.exists():continue
        info=path.stat()
        if not path.is_file() or info.st_uid!=0 or info.st_nlink!=1:raise ValueError('Foreign/shared artifact preserved')
        checked.append({'path':str(path),'bytes':info.st_size})
    for row in checked:Path(row['path']).unlink()
    return {'success':True,'removed':checked,'production_template_preserved':True,'guests_stopped':True}


def complete(raw,slot,meta):
    started=time.perf_counter();cpu=time.process_time()
    sha=hashlib.sha256(fast.header());compressor=zlib.compressobj(3,zlib.DEFLATED,-15)
    count=0;crc=0
    def feed(data):
        nonlocal count,crc
        crc=zlib.crc32(data,crc);packed=compressor.compress(data);count+=len(packed);sha.update(packed)
    with raw.open('rb') as stream:
        remaining=meta['offset']
        while remaining:
            data=stream.read(min(1024**2,remaining))
            if not data:raise ValueError('Truncated reference image')
            feed(data);remaining-=len(data)
        stream.seek(len(slot),1);feed(slot)
        while data:=stream.read(1024**2):feed(data)
    end=compressor.flush();count+=len(end);sha.update(end)
    ending=fast.footer(crc,count,meta['raw_bytes']);sha.update(ending)
    return {'seconds':time.perf_counter()-started,'cpu_seconds':time.process_time()-cpu,
            'sha256':sha.hexdigest(),'bytes':len(fast.header())+count+len(ending),'crc32':crc}


def run(token,template,qa,retire=False,failed=None,latency=False):
    base.admitted(token);base.key(template);base.key(qa)
    output=jobs.REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'success':False,'started':time.time(),'template':template,'qa_job':qa}
    try:
        qualification=json.loads((Path('/var/lib/debrescuestick/qa')/qa/'result.json').read_text())
        source=base.REMOTE/('image-'+template);proof=json.loads((source/'template.json').read_text())
        if qualification.get('success') is not True or qualification['sha256']!=proof['sha256']:
            raise ValueError('Completed native qualification required before serial benchmark')
        if retire:
            record.update(return_tests(output,source,qa,qualification,failed))
            record['finished']=time.time();base.write(output/'result.json',record)
            return 0
        active=subprocess.check_output(['systemctl','show','debrescuestick-qa-worker-'+qa+'.service','--property=ActiveState','--value'],text=True).strip()
        if active not in ('inactive','failed'):raise ValueError('Native QA must be stopped first')
        started=time.perf_counter();candidate=fast.Template(source/'fast')
        record['prefix_warmup_seconds']=time.perf_counter()-started
        # Reuse the exact own ephemeral QA key, never an operator/user private key.
        key=(Path('/var/lib/debrescuestick/qa')/qa/'key-a.pub').read_text()
        from keys import public_key
        key,_=public_key(key)
        if latency:
            record['personalization']=[]
            for number in range(3):
                folder=output/('sample-'+str(number));folder.mkdir(mode=0o700)
                started=time.perf_counter();cpu=time.process_time()
                tail,size,sha=candidate.personalize(key,folder)
                record['personalization'].append({'seconds':time.perf_counter()-started,
                    'cpu_seconds':time.process_time()-cpu,'bytes':size,'sha256':sha,'tail_bytes':len(tail)})
            record.update(success=True,sha256=proof['sha256'],profile='complete-personalization')
            record['finished']=time.time();base.write(output/'result.json',record)
            return 0
        fat=output/'keys.fat';owner=output/'public.key';fat.write_bytes(candidate.blank);owner.write_text(key)
        subprocess.run(['mcopy','-o','-i',str(fat),str(owner),'::OWNER.PUB'],check=True,timeout=10)
        if subprocess.check_output(['mtype','-i',str(fat),'::OWNER.PUB'],timeout=10)!=key.encode():
            raise ValueError('Benchmark partition key differs')
        slot=fat.read_bytes();fat.unlink();owner.unlink()
        record['full']=[];record['reuse']=[]
        for number in range(2):
            base.write(output/'progress.json',{'phase':'full-compression','sample':number+1})
            record['full'].append(complete(source/'base.img',slot,candidate.meta))
            base.write(output/'partial.json',record)
        if max(r['seconds'] for r in record['full'])>1.2*min(r['seconds'] for r in record['full']):
            record['full'].append(complete(source/'base.img',slot,candidate.meta))
        for number in range(2):
            started=time.perf_counter();cpu=time.process_time();tail,size,sha=candidate.tail(slot)
            record['reuse'].append({'seconds':time.perf_counter()-started,'cpu_seconds':time.process_time()-cpu,'bytes':size,'sha256':sha})
        part=output/'image.tail';part.write_bytes(tail)
        with fast.Reader([source/'fast/prefix.zip',part]) as reader,zipfile.ZipFile(reader) as archive:
            item=archive.getinfo(fast.NAME.decode())
            if item.CRC!=record['full'][0]['crc32'] or item.file_size!=proof['bytes']:
                raise ValueError('Reuse differs from full reference image')
        if len({r['crc32'] for r in record['full']})!=1:raise ValueError('Comparison input changed')
        # Independent standard ZIP tool: no special extractor is required.
        tool=shutil.which('unzip')
        if not tool:raise RuntimeError('Independent unzip verifier required')
        archive=output/'image.zip'
        with archive.open('xb') as sink,fast.Reader([source/'fast/prefix.zip',part]) as reader:
            while data:=reader.read(1024**2):sink.write(data)
        with (output/'unzip.log').open('xb') as log:
            subprocess.run([tool,'-t',str(archive)],check=True,stdout=log,stderr=subprocess.STDOUT,timeout=300)
        record.update(success=True,sha256=proof['sha256'],same_raw_bytes=True,standard_unzip=True,
                      temporary_archive_removed=True)
        archive.unlink();part.unlink()
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    return 0 if record['success'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for n in ('key','template','qa','failed'):p.add_argument('--'+n)
    p.add_argument('--retire',action='store_true')
    p.add_argument('--latency',action='store_true')
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.template,a.qa,a.retire,a.failed,a.latency))
    args=['--template',base.key(a.template),'--qa',base.key(a.qa)] if a.action=='submit' else []
    if a.retire:args+=['--retire']
    if a.latency:args+=['--latency']
    if a.failed:args+=['--failed',base.key(a.failed)]
    result=jobs.submit('fastprobe.py',FILES+('keys.py',),args,a.key) if a.action=='submit' else jobs.status(a.key)
    print(json.dumps(base.brief(result)))
