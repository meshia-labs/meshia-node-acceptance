"""Bounded workload for the native paths changed after the Mac29 matrix."""

FD_SOURCE = bytes(range(256)) * 1024
FD_PATCHES = ((0, b'FD30'), (4093, b'cross-page-write'), (262137, b'ENDSEED'))
FD_PATH = 'mac-open-description.bin'
# Existing hosted permission-adoption allowance, covering the unchanged
# thirty-second native heartbeat cadence plus bounded request scheduling.
ACCESS_ADOPTION_SECONDS = 40
FD_FAILURE_MARKERS = (
    'Open description seed changed', 'Retained reader missed in-place write',
    'Writer missed in-place write', 'Reopened reader missed in-place write',
    'Retained reader missed truncate', 'Retained reader missed zero regrowth',
    'Closed description bytes changed',
)


def fd_expected():
    value = bytearray(FD_SOURCE)
    for offset, body in FD_PATCHES:
        value[offset:offset + len(body)] = body
    return bytes(value[:17]) + bytes(16)


def exercise_access_transition(plane, mode, *, configured_access, native_app, wait, progress):
    """A new signed reservation must survive the next ordinary access report."""
    previous = configured_access()
    state = {'mode': mode, 'previous_mode': previous if previous in ('full', 'limited', 'files') else 'unknown',
             'deterministic_fixture_ordering': True, 'production_concurrency_tested': False}
    def check(assertion, condition):
        progress(**state, phase=assertion, assertion=assertion, condition_passed=bool(condition))
        if not condition:
            raise AssertionError(assertion)
    check('ACCESS_TRANSITION_PRIOR_MODE', previous in ('full', 'limited') and previous != mode)
    plane.begin_access_transition(mode)
    try:
        # The existing config is the prior mode. Do not require an extra
        # heartbeat before reserving: its normal interval is thirty seconds.
        def after_reserve():
            check('ACCESS_TRANSITION_RESERVATION_ORDER', configured_access() == previous)
            plane.release_access_heartbeat()
            progress(**state, phase='await_access_adoption', adoption_timeout_seconds=ACCESS_ADOPTION_SECONDS,
                     reservation_before_heartbeat=True)
            try:
                wait('delayed access heartbeat applied', lambda: configured_access() == mode, ACCESS_ADOPTION_SECONDS)
            except AssertionError as error:
                if str(error) == 'Timed out: delayed access heartbeat applied':
                    check('ACCESS_TRANSITION_ADOPTION_TIMEOUT', False)
                raise
            check('ACCESS_TRANSITION_ADOPTED_MODE', configured_access() == mode)
        native_app(mode, after_reserve=after_reserve)
        return {**state, 'reservation_before_heartbeat': True, 'access_applied_before_register': True,
                'signed_app_lane': True, 'owned_process_stopped': True}
    finally:
        plane.release_access_heartbeat()


FD_PROBE = r'''
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); expected=bytearray(bytes(range(256))*1024)
reader=os.open(p,os.O_RDONLY); writer=None
try:
 assert os.pread(reader,len(expected),0)==expected,'Open description seed changed'
 writer=os.open(p,os.O_RDWR)
 for offset,body in ((0,b'FD30'),(4093,b'cross-page-write'),(262137,b'ENDSEED')):
  assert os.pwrite(writer,body,offset)==len(body)
  expected[offset:offset+len(body)]=body
 os.fsync(writer)
 assert os.pread(reader,len(expected),0)==expected,'Retained reader missed in-place write'
 assert os.pread(writer,len(expected),0)==expected,'Writer missed in-place write'
 assert p.read_bytes()==expected,'Reopened reader missed in-place write'
 os.ftruncate(writer,17);os.fsync(writer)
 assert os.pread(reader,100,0)==expected[:17],'Retained reader missed truncate'
 os.ftruncate(writer,33);os.fsync(writer)
 expected=bytes(expected[:17])+bytes(16)
 assert os.pread(reader,100,0)==expected,'Retained reader missed zero regrowth'
 assert os.pread(writer,100,0)==expected,'Writer missed in-place write'
finally:
 if writer is not None: os.close(writer)
 os.close(reader)
assert p.read_bytes()==expected,'Closed description bytes changed'
print(json.dumps({'retained_reader':True,'writer_readback':True,'reopened_readback':True,
 'reader_cached_before_write':True,'cross_page_write':True,'truncate':True,'regrow_zero_fill':True,
 'fsync':True,'size_bytes':len(expected),'content_sha256':hashlib.sha256(expected).hexdigest()}))
'''
