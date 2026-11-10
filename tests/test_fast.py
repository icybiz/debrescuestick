import hashlib
import io
import json
import random
import unittest
import zipfile
import zlib
from support import workspace
import fast


class FastTests(unittest.TestCase):
    def test_crc_combination_including_boundaries(self):
        rng=random.Random(717)
        for n in [0,1,2,31,4096]:
            a=rng.randbytes(n);b=rng.randbytes(n//2)
            self.assertEqual(zlib.crc32(a+b),fast.combine(zlib.crc32(a),zlib.crc32(b),len(b)))
        with self.assertRaises(ValueError):fast.combine(0,0,-1)

    def test_standard_zip_reuses_prefix_and_preserves_exact_image(self):
        with workspace() as root:
            rng=random.Random(219);prefix=rng.randbytes(16384);suffix=rng.randbytes(4096)
            raw=root/'synthetic.bin';raw.write_bytes(prefix+b'\0'*128+suffix)
            meta=fast.pack(raw,len(prefix),128,root/'packed');template=fast.Template(root/'packed')
            common=(root/'packed/prefix.zip').read_bytes();before=hashlib.sha256(common).hexdigest()
            for slot in (b'a'*128,b'b'*128,rng.randbytes(128)):
                tail,size,sha=template.tail(slot);archive=common+tail
                self.assertEqual(len(archive),size);self.assertEqual(hashlib.sha256(archive).hexdigest(),sha)
                with zipfile.ZipFile(io.BytesIO(archive)) as check:
                    self.assertEqual(check.namelist(),[fast.NAME.decode()])
                    self.assertIsNone(check.testzip())
                    self.assertEqual(check.read(fast.NAME.decode()),prefix+slot+suffix)
                part=root/'tail';part.write_bytes(tail)
                with fast.Reader([root/'packed/prefix.zip',part]) as reader:
                    self.assertEqual(reader.read(),archive)
                    for offset in [0,len(common)-1,len(common),len(common)+1,len(archive)-1,len(archive),len(archive)+1]:
                        reader.seek(offset);self.assertEqual(reader.read(17),archive[offset:offset+17])
                    with zipfile.ZipFile(reader) as check:self.assertEqual(check.read(fast.NAME.decode()),prefix+slot+suffix)
            self.assertEqual(hashlib.sha256((root/'packed/prefix.zip').read_bytes()).hexdigest(),before)
            with self.assertRaises(ValueError):template.tail(b'wrong size')
            (root/'packed/suffix.deflate').write_bytes(b'bad')
            with self.assertRaises(ValueError):fast.Template(root/'packed')
