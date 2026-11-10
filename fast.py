"""One standard ZIP64 image, assembled from immutable and personal DEFLATE blocks.

PKWARE APPNOTE 6.3.10 sections 4.3.9/4.3.12/4.5.3; zlib FULL_FLUSH
resets the history at the two boundaries. No complete archives are concatenated.
"""
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import zlib

NAME=b'DebRescueStick-amd64.img'
SLOT=4*1024**2
OFFSET=8*1024**3
SIZE=OFFSET+8*1024**2


def header():
    extra=struct.pack('<HHQQ',1,16,0,0)
    return struct.pack('<4s5H3I2H',b'PK\x03\x04',45,8,8,0,33,0,0xffffffff,0xffffffff,len(NAME),len(extra))+NAME+extra


def footer(crc,compressed,raw):
    extra=struct.pack('<HHQQ',1,16,raw,compressed)
    descriptor=struct.pack('<4sIQQ',b'PK\x07\x08',crc,compressed,raw)
    central=struct.pack('<4s6H3I5H2I',b'PK\x01\x02',45,45,8,8,0,33,crc,0xffffffff,0xffffffff,
                        len(NAME),len(extra),0,0,0,0,0)+NAME+extra
    offset=len(header())+compressed+len(descriptor)
    end64=struct.pack('<4sQ2H2I4Q',b'PK\x06\x06',44,45,45,0,0,1,1,len(central),offset)
    locator=struct.pack('<4sIQI',b'PK\x06\x07',0,offset+len(central),1)
    end=struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,0xffff,0xffff,0xffffffff,0xffffffff,0)
    return descriptor+central+end64+locator+end


def combine(first,second,length):
    if not 0<=length<=SIZE:raise ValueError('Bounded CRC length required')
    library=ctypes.CDLL('libz.so.1')
    function=library.crc32_combine64
    function.argtypes=(ctypes.c_ulong,ctypes.c_ulong,ctypes.c_longlong)
    function.restype=ctypes.c_ulong
    return function(first,second,length)&0xffffffff


def deflate(data,final=False):
    compressor=zlib.compressobj(3,zlib.DEFLATED,-15)
    return compressor.compress(data)+compressor.flush(zlib.Z_FINISH if final else zlib.Z_FULL_FLUSH)


def pack(raw,offset,length,destination):
    """Called by the admitted remote builder; tests use only tiny synthetic files."""
    size=raw.stat().st_size
    if not 0<offset<offset+length<size or length>SLOT or size-offset-length>8*1024**2:
        raise ValueError('Bounded inner slot and suffix required')
    destination.mkdir(mode=0o700)
    compressor=zlib.compressobj(3,zlib.DEFLATED,-15);crc=0
    with raw.open('rb') as source,(destination/'prefix.zip').open('xb') as out:
        out.write(header());remaining=offset
        while remaining:
            data=source.read(min(1024**2,remaining))
            if not data:raise ValueError('Truncated system prefix')
            crc=zlib.crc32(data,crc);out.write(compressor.compress(data));remaining-=len(data)
        out.write(compressor.flush(zlib.Z_FULL_FLUSH))
        blank=source.read(length)
        if len(blank)!=length:raise ValueError('Truncated slot')
        suffix=source.read()
        if len(suffix)>8*1024**2:raise ValueError('Bounded disk suffix required')
    (destination/'blank.fat').write_bytes(blank)
    (destination/'suffix.deflate').write_bytes(deflate(suffix,final=True))
    result={'schema':'drs-zip-v1','offset':offset,'slot_bytes':length,'raw_bytes':size,
            'prefix_crc32':crc,'suffix_crc32':zlib.crc32(suffix),'suffix_raw_bytes':len(suffix)}
    for name in ('prefix.zip','blank.fat','suffix.deflate'):
        with (destination/name).open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        result[name]={'bytes':(destination/name).stat().st_size,'sha256':sha}
    (destination/'archive.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


class Template:
    def __init__(self,path):
        self.path=Path(path);self.meta=json.loads((self.path/'archive.json').read_text())
        if self.meta['schema']!='drs-zip-v1' or not 0<self.meta['slot_bytes']<=SLOT:
            raise ValueError('Known bounded image format required')
        self.sha=hashlib.sha256()
        for name in ('prefix.zip','blank.fat','suffix.deflate'):
            path=self.path/name
            if path.is_symlink():raise ValueError('Linked immutable archive refused')
            info=path.stat();expected=self.meta[name]
            maximum=4*1024**3 if name=='prefix.zip' else SLOT if name=='blank.fat' else 8*1024**2
            if not stat.S_ISREG(info.st_mode) or info.st_size!=expected['bytes'] or not 0<info.st_size<=maximum:
                raise ValueError('Archive component size changed')
            with path.open('rb') as stream:
                sha=hashlib.file_digest(stream,'sha256')
            if sha.hexdigest()!=expected['sha256']:raise ValueError('Immutable archive component changed')
            if name=='prefix.zip':self.sha=sha
        self.blank=(self.path/'blank.fat').read_bytes()
        self.suffix=(self.path/'suffix.deflate').read_bytes()

    def tail(self,slot):
        if len(slot)!=self.meta['slot_bytes']:raise ValueError('Exact personal partition size required')
        data=deflate(slot)+self.suffix
        compressed=self.meta['prefix.zip']['bytes']-len(header())+len(data)
        crc=combine(self.meta['prefix_crc32'],zlib.crc32(slot),len(slot))
        crc=combine(crc,self.meta['suffix_crc32'],self.meta['suffix_raw_bytes'])
        result=data+footer(crc,compressed,self.meta['raw_bytes'])
        sha=self.sha.copy();sha.update(result)
        return result,self.meta['prefix.zip']['bytes']+len(result),sha.hexdigest()

    def personalize(self,key,output):
        fat=output/'keys.fat';owner=output/'public.key'
        fat.write_bytes(self.blank);owner.write_text(key)
        subprocess.run(['mcopy','-o','-i',str(fat),str(owner),'::OWNER.PUB'],check=True,timeout=10,
                       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        check=subprocess.check_output(['mtype','-i',str(fat),'::OWNER.PUB'],timeout=10)
        if check!=key.encode():raise ValueError('Exact partition key readback failed')
        result=self.tail(fat.read_bytes());fat.unlink();owner.unlink()
        return result


class Reader(io.RawIOBase):
    """Seekable view across regular files; Range downloads never create a copy."""
    def __init__(self,paths):
        super().__init__();self.parts=[];self.position=0;self.size=0
        try:
            for path in paths:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                stream=os.fdopen(fd,'rb');info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):stream.close();raise ValueError('Regular archive component required')
                self.parts.append((self.size,info.st_size,stream));self.size+=info.st_size
        except BaseException:self.close();raise

    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.position
    def seek(self,offset,whence=os.SEEK_SET):
        position=offset+(self.position if whence==os.SEEK_CUR else self.size if whence==os.SEEK_END else 0)
        if whence not in (0,1,2) or position<0:raise ValueError('Invalid archive offset')
        self.position=position;return position
    def read(self,size=-1):
        if size<0:size=max(0,self.size-self.position)
        result=[];remaining=min(size,max(0,self.size-self.position))
        for start,length,stream in self.parts:
            if not remaining:break
            if start<=self.position<start+length:
                stream.seek(self.position-start);count=min(remaining,start+length-self.position)
                data=stream.read(count)
                if len(data)!=count:raise OSError('Truncated archive component')
                result.append(data);remaining-=count;self.position+=count
        return b''.join(result)
    def close(self):
        for _,_,stream in getattr(self,'parts',()):stream.close()
        super().close()
