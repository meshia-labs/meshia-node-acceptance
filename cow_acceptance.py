"""Bounded mounted COW proof; callers must provide the actual installed mount."""
import hashlib
import json
from pathlib import Path

BASE = bytes(range(256)) * 8192
PATCH = b'meshia-cow-partial-edit'
PATCH_OFFSET = 65531
SHRINK = 786437
GROW = 1048583
PATH = 'mac-cold-cow.bin'
SPARSE_PATH = 'mac-large-cold-cow.bin'
SPARSE_SIZE = 2 * 1024**3 + 4096
# Different immutable bytes from the ordinary seed: its already-warm CAS
# object must not let the cold fixture accidentally reuse a verified cache.
SPARSE_PREFIX = BASE.translate(bytes(value ^ 0x5a for value in range(256)))
RAW_BASE = bytes(range(256)) * (9 * 4096)
RAW_DESTINATION = 'mac-raw-cow-renamed.bin'
RAW_DESCRIPTOR_HASHES = {
    'implicit': ('canonical-raw-source.json', 'fbb8b377c7ea9290f1ba26b321452ccec14c39dafb29092db37024cc5b14e363'),
    'sha256': ('canonical-raw-source-explicit.json', '638b24ac83884a4dc28c27b93f37d4a02e88abaf2000de209fc60227500becd2'),
}
PROBE_FAILURE_MARKERS = (
    'Cold source size changed', 'Partial edit changed untouched bytes',
    'Truncate and growth did not preserve zero-fill', 'Closed mounted file readback changed',
    'Raw source size changed', 'Raw partial edit changed source bytes',
    'Raw truncate growth changed zero-fill', 'Raw closed file readback changed', 'Local rename changed bytes',
    'Sparse source size changed', 'Sparse prefix window changed', 'Sparse untouched zero tail changed',
    'Sparse tail write changed', 'Sparse shrink/grow result changed', 'Sparse closed readback changed',
)


def canonical_raw_source(algorithm='implicit'):
    name, digest = RAW_DESCRIPTOR_HASHES[algorithm]
    raw = (Path(__file__).resolve().parent / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Canonical web source fixture changed')
    return json.loads(raw)['op']


def verify_rename_projection(snapshot, old, new, *, source, destination, size):
    if (not isinstance(snapshot, dict) or snapshot.get('schema') != 'meshia.fabric_v2.snapshot.v1'
            or snapshot.get('workspace') != 'workspace' or 'next_after' not in snapshot
            or any(not isinstance(reply, dict) or reply.get('schema') != 'meshia.fabric_v2.entry.v1'
                   or reply.get('workspace') != 'workspace' or 'entry' not in reply for reply in (old, new))):
        raise AssertionError('Authoritative rename response identity changed')
    entries = snapshot.get('entries')
    if (snapshot.get('next_after') is not None or not isinstance(entries, list)
            or any(not isinstance(entry, dict) or not isinstance(entry.get('path'), str) for entry in entries)
            or old['entry'] is not None or not isinstance(new['entry'], dict)):
        raise AssertionError('Authoritative rename lookup did not converge')
    listed = {entry['path']: entry for entry in entries}
    entry = new['entry']
    if (len(listed) != len(entries) or source in listed or destination not in listed or entry.get('path') != destination
            or entry.get('kind') != 'file' or entry.get('size_bytes') != size
            or listed[destination] != entry):
        raise AssertionError('Authoritative rename listing did not converge')
    return {'signed_list_old_source_absent': True, 'signed_lookup_old_source_absent': True,
            'signed_destination_present': True}


def expected_bytes():
    changed = bytearray(BASE)
    changed[PATCH_OFFSET:PATCH_OFFSET + len(PATCH)] = PATCH
    return bytes(changed[:SHRINK]) + bytes(GROW - SHRINK)


def sparse_expected_bytes():
    changed = bytearray(SPARSE_PREFIX[:SHRINK])
    changed[PATCH_OFFSET:PATCH_OFFSET + len(PATCH)] = PATCH
    return bytes(changed) + bytes(GROW - SHRINK)


CLASSIC_RECREATE_BODY = b'mounted-recreated-source'
CLASSIC_RENAME_BODY = b'mounted-second-edit'
CLASSIC_RECREATE_PROBE = r'''
import json,os,pathlib,sys
p,q=map(pathlib.Path,sys.argv[1:])
with p.open('wb',buffering=0) as f:
 assert f.write(b'mounted-second-edit')==len(b'mounted-second-edit')
 os.fsync(f.fileno())
p.rename(q)
assert not p.exists(),'Renamed source remains locally visible'
assert q.read_bytes()==b'mounted-second-edit','Renamed destination bytes changed'
with p.open('xb',buffering=0) as f:
 assert f.write(b'mounted-recreated-source')==len(b'mounted-recreated-source')
 os.fsync(f.fileno())
assert p.read_bytes()==b'mounted-recreated-source','Recreated source bytes changed'
assert q.read_bytes()==b'mounted-second-edit','Recreation changed renamed destination'
print(json.dumps({'local_rename':True,'source_recreated':True,'mounted_readback':True,'fsync':True}))
'''


def verify_recreated_source_projection(snapshot, source_lookup, destination_lookup, *, source, destination):
    expected = {source: CLASSIC_RECREATE_BODY, destination: CLASSIC_RENAME_BODY}
    if (not isinstance(snapshot, dict) or snapshot.get('schema') != 'meshia.fabric_v2.snapshot.v1'
            or snapshot.get('workspace') != 'workspace' or snapshot.get('next_after', 'missing') is not None
            or not isinstance(snapshot.get('entries'), list)):
        raise AssertionError('Recreated-source snapshot identity changed')
    entries = snapshot['entries']
    if any(not isinstance(item, dict) or not isinstance(item.get('path'), str) for item in entries):
        raise AssertionError('Recreated-source listing changed')
    listed = {item['path']: item for item in entries}
    if len(listed) != len(entries):
        raise AssertionError('Recreated-source listing contains duplicate paths')
    for path, reply in ((source, source_lookup), (destination, destination_lookup)):
        body = expected[path]
        if (not isinstance(reply, dict) or reply.get('schema') != 'meshia.fabric_v2.entry.v1'
                or reply.get('workspace') != 'workspace' or not isinstance(reply.get('entry'), dict)):
            raise AssertionError('Recreated-source lookup identity changed')
        entry = reply['entry']
        if (entry.get('path') != path or entry.get('kind') != 'file' or entry.get('size_bytes') != len(body)
                or entry.get('sha256') != hashlib.sha256(body).hexdigest() or listed.get(path) != entry):
            raise AssertionError('Recreated source or renamed destination was not durably preserved')
    return {'signed_recreated_source_present': True, 'signed_destination_present': True}


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


RAW_PROBE = r'''
import hashlib,json,os,pathlib,sys
p,destination=map(pathlib.Path,sys.argv[1:])
base=bytes(range(256))*(9*4096)
patch=b'meshia-cow-partial-edit'
expected=bytearray(base)
with p.open('r+b',buffering=0) as f:
 assert os.fstat(f.fileno()).st_size==len(base),'Raw source size changed'
 for offset in (65531,8*1024*1024-5):
  f.seek(offset);assert f.write(patch)==len(patch)
  expected[offset:offset+len(patch)]=patch
 os.fsync(f.fileno())
 for offset in (0,65520,4*1024*1024+101,8*1024*1024-16,len(base)-64):
  f.seek(offset);assert f.read(64)==bytes(expected[offset:offset+64]),'Raw partial edit changed source bytes'
 f.truncate(786437);os.fsync(f.fileno())
 f.truncate(1048583);os.fsync(f.fileno())
 expected=bytes(expected[:786437])+bytes(1048583-786437)
 f.seek(0);assert f.read()==expected,'Raw truncate growth changed zero-fill'
assert p.read_bytes()==expected,'Raw closed file readback changed'
p.rename(destination)
assert not p.exists() and destination.read_bytes()==expected,'Local rename changed bytes'
print(json.dumps({'size_bytes':len(expected),'content_sha256':hashlib.sha256(expected).hexdigest(),
 'partial_write':True,'cross_block_write':True,'truncate':True,'regrow_zero_fill':True,
 'fsync':True,'mounted_readback':True,'closed_file_reopen':True,'local_rename':True}))
'''


# Logical size exceeds the normal maximum eager budget. No whole-file read,
# hash, or >1-MiB publication occurs: only sampled windows, then shrink/grow.
SPARSE_PROBE = r'''
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]);size=2*1024**3+4096
prefix=(bytes(range(256))*8192).translate(bytes(v^0x5a for v in range(256)))
patch=b'meshia-cow-partial-edit';expected=bytearray(prefix)
with p.open('r+b',buffering=0) as f:
 assert os.fstat(f.fileno()).st_size==size,'Sparse source size changed'
 f.seek(65531);assert f.write(patch)==len(patch)
 expected[65531:65531+len(patch)]=patch
 for offset in (0,65520,786400,len(prefix)-64):
  f.seek(offset);assert f.read(64)==bytes(expected[offset:offset+64]),'Sparse prefix window changed'
 f.seek(size-512);assert f.read(128)==bytes(128),'Sparse untouched zero tail changed'
 f.seek(size-256);assert f.write(b'tail-edit')==9
 f.seek(size-260);assert f.read(17)==bytes(4)+b'tail-edit'+bytes(4),'Sparse tail write changed'
 f.truncate(786437);f.truncate(1048583);os.fsync(f.fileno())
 expected=bytes(expected[:786437])+bytes(1048583-786437)
 f.seek(0);assert f.read()==expected,'Sparse shrink/grow result changed'
assert p.read_bytes()==expected,'Sparse closed readback changed'
print(json.dumps({'size_bytes':len(expected),'content_sha256':hashlib.sha256(expected).hexdigest(),
 'logical_source_bytes':size,'partial_write':True,'sampled_untouched_prefix':True,
 'far_zero_tail':True,'tail_write':True,'truncate':True,'regrow_zero_fill':True,
 'fsync':True,'mounted_readback':True}))
'''

RAW_REOPEN_PROBE = r'''
import hashlib,json,pathlib,sys
p,old=map(pathlib.Path,sys.argv[1:])
expected=bytearray(bytes(range(256))*8192)
patch=b'meshia-cow-partial-edit';expected[65531:65531+len(patch)]=patch
expected=bytes(expected[:786437])+bytes(1048583-786437)
assert not old.exists(),'Old source returned after remount'
assert p.read_bytes()==expected,'Remounted result bytes changed'
print(json.dumps({'mounted_readback':True,'old_source_absent':True,
 'size_bytes':len(expected),'content_sha256':hashlib.sha256(expected).hexdigest()}))
'''


def validate(result):
    expected = expected_bytes()
    return result == {'size_bytes': len(expected),
        'content_sha256': hashlib.sha256(expected).hexdigest(),
        'partial_write': True, 'truncate': True, 'regrow_zero_fill': True,
        'fsync': True, 'mounted_readback': True}
