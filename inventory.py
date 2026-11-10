"""Exact source provenance, including code embedded into signed/static binaries."""
import os
import subprocess

import base


def paragraphs(text):
    result=[];row={};last=None
    for line in text.splitlines()+['']:
        if not line:
            if row:result.append(row)
            row={};last=None
        elif line[:1].isspace():
            if not last:raise ValueError('Control continuation without field')
            row[last]+='\n'+line[1:]
        else:
            name,sep,value=line.partition(':')
            if not sep:raise ValueError('Debian control field required')
            row[name]=value.strip();last=name
    return result


def source_set(text):
    result=set()
    for row in paragraphs(text):
        if not row.get('Version'):continue
        fields=row.get('Source',row['Package']).split()
        if len(fields)==1:source=(fields[0],row['Version'])
        elif len(fields)==2 and fields[1].startswith('(') and fields[1].endswith(')'):
            source=(fields[0],fields[1][1:-1])
        else:raise ValueError('Exact binary source provenance required')
        result.add(source)
        for field in ('Built-Using','Static-Built-Using'):
            for item in row.get(field,'').split(','):
                if not item.strip():continue
                name,sep,constraint=item.strip().partition('(')
                if not sep or not constraint.endswith(')') or not constraint.startswith('='):
                    raise ValueError('Embedded source must use an exact (= version)')
                release=constraint[1:-1].strip()
                if not release:raise ValueError('Embedded source version required')
                result.add((name.strip(),release))
    if not result:raise ValueError('Actual nonempty dpkg status required')
    return result


def collect(token,image,output):
    base.admitted(token)
    env={**os.environ,'LIBGUESTFS_BACKEND':'direct','LIBGUESTFS_MEMSIZE':'512',
         'LIBGUESTFS_BACKEND_SETTINGS':'force_kvm','LIBGUESTFS_CACHEDIR':'/var/cache/debrescuestick/guestfs'}
    subprocess.run(['guestfish','--ro','--format=raw','-a',str(image),'-i',
                    'download','/var/lib/dpkg/status',str(output)],check=True,timeout=300,env=env)
    return source_set(output.read_text())
