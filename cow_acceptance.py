"""Bounded mounted COW proof; callers must provide the actual installed mount."""
import hashlib

BASE = bytes(range(256)) * 8192
PATCH = b'meshia-cow-partial-edit'
PATCH_OFFSET = 65531
SHRINK = 786437
GROW = 1048583
PATH = 'mac-cold-cow.bin'


def expected_bytes():
    changed = bytearray(BASE)
    changed[PATCH_OFFSET:PATCH_OFFSET + len(PATCH)] = PATCH
    return bytes(changed[:SHRINK]) + bytes(GROW - SHRINK)


# Run with the installed Python, without checkout imports or injected native
# ownership. The first byte read occurs only after the cold source is edited.
PROBE = r'''
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1])
base=bytes(range(256))*8192
patch=b'meshia-cow-partial-edit'
expected=bytearray(base)
expected[65531:65531+len(patch)]=patch
with p.open('r+b',buffering=0) as f:
 assert os.fstat(f.fileno()).st_size==len(base),'Cold source size changed'
 f.seek(65531);assert f.write(patch)==len(patch)
 os.fsync(f.fileno())
 f.seek(0);assert f.read()==bytes(expected),'Partial edit changed untouched bytes'
 f.truncate(786437);os.fsync(f.fileno())
 f.truncate(1048583);os.fsync(f.fileno())
 expected=bytes(expected[:786437])+bytes(1048583-786437)
 f.seek(0);assert f.read()==expected,'Truncate and growth did not preserve zero-fill'
assert p.read_bytes()==expected,'Closed mounted file readback changed'
print(json.dumps({'size_bytes':len(expected),'content_sha256':hashlib.sha256(expected).hexdigest(),
 'partial_write':True,'truncate':True,'regrow_zero_fill':True,'fsync':True,'mounted_readback':True}))
'''


def validate(result):
    expected = expected_bytes()
    return result == {'size_bytes': len(expected),
        'content_sha256': hashlib.sha256(expected).hexdigest(),
        'partial_write': True, 'truncate': True, 'regrow_zero_fill': True,
        'fsync': True, 'mounted_readback': True}
