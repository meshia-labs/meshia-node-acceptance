"""One bounded native36 command; only synthetic files in its mounted workspace."""
import json,os,time
from pathlib import Path

root=Path.cwd()
assert str(root).startswith('/Users/runner/Meshia/')
assert os.getuid()==501
try:
    Path('/Users/runner/meshia-acceptance-personal.txt').read_bytes()
except PermissionError:
    denied=True
else:
    raise AssertionError('Limited personal canary was readable')

destination=root/'xcrun_db'
temporary=root/'xcrun_db-Meshia36'
old=b'meshia36 original synthetic cache\n'
new=b'meshia36 replacement synthetic cache\n'
def create(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        assert os.write(fd,data)==len(data)
        os.fsync(fd)
    finally:os.close(fd)

started=time.monotonic()
create(destination,old)
create(temporary,new)
os.replace(temporary,destination)
assert destination.read_bytes()==new
assert not temporary.exists()
closed_seconds=time.monotonic()-started

# An already-open reader retains its original complete version while a later
# open resolves the replacement; use ordinary descriptors without runtime APIs.
reader=os.open(destination,os.O_RDONLY)
try:
    assert os.read(reader,len(new)+1)==new
    os.lseek(reader,0,os.SEEK_SET)
    create(temporary,old)
    os.replace(temporary,destination)
    assert os.read(reader,len(new)+1)==new
    assert destination.read_bytes()==old
finally:os.close(reader)
print(json.dumps({'limited_existing_canary_denied':denied,
 'closed_destination_replace':True,'pinned_open_reader_old_bytes':True,
 'new_path_new_bytes':True,'uid':os.getuid(),'closed_replace_seconds':round(closed_seconds,3)}))
