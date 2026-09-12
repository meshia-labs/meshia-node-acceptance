"""Real default-directory TemporaryFile lifecycle inside the command workspace."""
import errno
import json
import os
from pathlib import Path
import tempfile

workspace=Path.cwd().resolve()
# The normal native command declares its workspace through cwd and supplies
# TMPDIR. Do not override tempfile.tempdir or pass a dir argument to the API.
declared=os.environ.get('TMPDIR')
assert declared, 'TMPDIR_REQUIRED'
assert Path(declared).resolve().is_relative_to(workspace), 'TMPDIR_OUTSIDE_WORKSPACE'
temporary_root=Path(tempfile.gettempdir()).resolve()
assert temporary_root.is_relative_to(workspace), 'DEFAULT_TEMP_OUTSIDE_WORKSPACE'
before=set(temporary_root.iterdir())
body=b'meshia anonymous tempfile\x00payload\n'
with tempfile.TemporaryFile() as stream:
    descriptor=stream.fileno()
    assert stream.write(body)==len(body)
    stream.flush()
    os.fsync(descriptor)
    assert os.fstat(descriptor).st_size==len(body)
    assert stream.seek(0)==0
    assert stream.read()==body
    assert stream.seek(7)==7
    assert stream.write(b'PRIVATE')==7
    stream.flush()
    expected=body[:7]+b'PRIVATE'+body[14:]
    assert stream.seek(0)==0 and stream.read()==expected
    assert stream.truncate(11)==11
    stream.flush()
    assert os.fstat(descriptor).st_size==11
    assert stream.seek(0)==0 and stream.read()==expected[:11]
    assert stream.truncate(4096)==4096
    stream.flush()
    os.fsync(descriptor)
    assert os.fstat(descriptor).st_size==4096
    assert stream.seek(11)==11 and stream.read()==b'\0'*(4096-11)
assert stream.closed
try:
    os.fstat(descriptor)
except OSError as error:
    assert error.errno==errno.EBADF
else:
    raise AssertionError('TEMPFILE_DESCRIPTOR_NOT_CLOSED')
assert set(temporary_root.iterdir())==before, 'TEMPFILE_NAMESPACE_LEFTOVER'
print(json.dumps({'default_tmpdir_within_workspace':True,'temporary_file':True,
  'write_read_seek':True,'truncate_shrink':True,'truncate_extend_zero_fill':True,
  'fstat':True,'fsync':True,'closed':True,'descriptor_closed':True,
  'no_namespace_leftover':True,'uid':os.getuid() if hasattr(os,'getuid') else None}))
