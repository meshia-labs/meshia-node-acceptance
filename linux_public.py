"""Exact published Linux41 wheel acceptance with no source overlays."""
import errno
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
import ctypes
import threading
import struct
from unittest.mock import patch

import linux_fuse_acceptance as public

class PublicLinux(public.LinuxFuse):
    def test_inflight_retained_stat_after_successful_replacement(self):
        from meshia_node.linux_fuse import LinuxInodeOperations
        original_getattr = LinuxInodeOperations.getattr
        original_process = LinuxInodeOperations.process
        original_open = LinuxInodeOperations.open
        computed, release, renamed = threading.Event(), threading.Event(), threading.Event()
        armed = threading.Event()
        observed = []
        failures = []
        retained = {}
        def capture_process(owner, body, callback):
            owner.context.diagnostic_nodeid = struct.unpack_from('=Q', body, 16)[0]
            try:
                return original_process(owner, body, callback)
            finally:
                del owner.context.diagnostic_nodeid
        def capture_open(owner, path, flags):
            handle = original_open(owner, path, flags)
            if path in owner._failed_retirements:
                import fuse
                library = fuse._libfuse
                pointer = library.fuse_get_context().contents.fuse
                channel = library.fuse_session_next_chan(library.fuse_get_session(pointer), None)
                retained.update(nodeid=owner.context.diagnostic_nodeid, channel=channel, library=library)
            return handle
        def delayed_getattr(owner, path, fh=None):
            attrs = original_getattr(owner, path, fh)
            if armed.is_set() and path in owner._failed_retirements and attrs['st_nlink'] == 2:
                armed.clear()
                observed.append({'hidden_old_nlink': attrs['st_nlink']})
                computed.set()
                if not release.wait(5):
                    raise RuntimeError('bounded old stat barrier timed out')
            return attrs
        with patch.object(LinuxInodeOperations, 'getattr', delayed_getattr), \
                patch.object(LinuxInodeOperations, 'process', capture_process), \
                patch.object(LinuxInodeOperations, 'open', capture_open):
            with public.mounted(b'original destination bytes', materialize=True) as (root, plane, coordinator, database, workspace, settled):
                dest, source = root / 'data.bin', root / 'source.tmp'
                writer = os.open(dest, os.O_RDWR)
                reader = None
                stat_thread = rename_thread = None
                try:
                    os.pwrite(writer, b'EDIT', 0)
                    source.write_bytes(b'replacement')
                    with self.assertRaises(OSError) as error:
                        os.replace(source, dest)
                    self.assertEqual(error.exception.errno, errno.EBUSY)
                    self.assertEqual(dest.read_bytes(), b'EDITinal destination bytes')
                    self.assertEqual(os.fstat(writer).st_nlink, 1)
                    reader = os.open(dest, os.O_RDONLY)
                    os.close(writer)
                    writer = None
                    settled(lambda: not database.list_operations())
                    self.assertEqual(os.fstat(reader).st_nlink, 1)
                    self.assertTrue(retained, 'reader did not open the failed hidden inode')
                    notify = retained['library'].fuse_lowlevel_notify_inval_inode
                    notify.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int64, ctypes.c_int64]
                    notify.restype = ctypes.c_int
                    self.assertEqual(notify(retained['channel'], retained['nodeid'], -1, 0), 0)
                    libc = ctypes.CDLL(None, use_errno=True)
                    libc.statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
                    libc.statx.restype = ctypes.c_int
                    def stat_worker():
                        buffer = ctypes.create_string_buffer(256)
                        # AT_EMPTY_PATH | AT_STATX_FORCE_SYNC requests fresh inode attrs.
                        result = libc.statx(reader, b'', 0x1000 | 0x2000, 0x7ff, buffer)
                        if result != 0:
                            failures.append(('statx', ctypes.get_errno()))
                    def rename_worker():
                        try:
                            os.replace(source, dest)
                            renamed.set()
                        except BaseException as error:
                            failures.append(('rename', type(error).__name__))
                    armed.set()
                    stat_thread = threading.Thread(target=stat_worker)
                    stat_thread.start()
                    self.assertTrue(computed.wait(3), 'forced stat did not reach old hidden GETATTR')
                    rename_thread = threading.Thread(target=rename_worker)
                    rename_thread.start()
                    self.assertTrue(renamed.wait(3), 'libfuse serialized rename behind hidden GETATTR')
                    release.set()
                    stat_thread.join(3)
                    self.assertFalse(stat_thread.is_alive())
                    self.assertFalse(failures)
                    self.assertEqual(dest.read_bytes(), b'replacement')
                    self.assertEqual(os.fstat(reader).st_nlink, 0)
                    self.assertEqual(os.pread(reader, 100, 0), b'EDITinal destination bytes')
                finally:
                    release.set()
                    for worker in (stat_thread, rename_thread):
                        if worker is not None:
                            worker.join(5)
                    if writer is not None:
                        os.close(writer)
                    if reader is not None:
                        os.close(reader)

    def test_failed_replacement_retains_original_public_name(self):
        for continuation in ('rename_unlink', 'successful_retry'):
            with self.subTest(continuation=continuation):
                self.failed_replacement_continuation(continuation)

    def failed_replacement_continuation(self, continuation):
        original = b'original destination bytes'
        with public.mounted(original, materialize=True) as (root, plane, coordinator, database, workspace, settled):
            destination = root / 'data.bin'
            writer = os.open(destination, os.O_RDWR)
            reader = None
            try:
                os.pwrite(writer, b'EDIT', 0)
                expected = b'EDIT' + original[4:]
                source = root / 'source.tmp'
                source.write_bytes(b'replacement')
                with self.assertRaises(OSError) as error:
                    os.replace(source, destination)
                self.assertEqual(error.exception.errno, errno.EBUSY)
                self.assertEqual(destination.read_bytes(), expected)
                self.assertEqual(os.fstat(writer).st_size, len(expected))
                self.assertEqual(os.fstat(writer).st_nlink, 1)
                self.assertEqual(os.pread(writer, 100, 0), expected)
                self.assertEqual(source.read_bytes(), b'replacement')
                if continuation == 'rename_unlink':
                    moved = root / 'moved.bin'
                    os.rename(destination, moved)
                    self.assertEqual(moved.read_bytes(), expected)
                    self.assertFalse(destination.exists())
                    self.assertEqual(os.fstat(writer).st_nlink, 1)
                    moved.unlink()
                    self.assertFalse(moved.exists())
                    self.assertEqual(os.fstat(writer).st_nlink, 0)
                    self.assertEqual(os.pread(writer, 100, 0), expected)
                else:
                    reader = os.open(destination, os.O_RDONLY)
                    os.close(writer)
                    writer = None
                    settled(lambda: not database.list_operations())
                    os.replace(source, destination)
                    self.assertEqual(destination.read_bytes(), b'replacement')
                    self.assertEqual(os.fstat(reader).st_nlink, 0)
                    self.assertEqual(os.pread(reader, 100, 0), expected)
                self.assertFalse(any(path.name.startswith('.fuse_hidden') for path in root.iterdir()))
            finally:
                if reader is not None:
                    os.close(reader)
                if writer is not None:
                    os.close(writer)


def main():
    directory = Path(sys.argv[1])
    public.require_binding()
    assert sys.platform == 'linux' and os.getuid() != 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and Path('/dev/fuse').is_char_device()
    receipt = public.verify_installed(directory)
    receipt.update(source_candidate=False, public_artifact_acceptance=False, callback_interleaving_diagnostic=True,
                   uid=os.getuid(), kernel=os.uname().release,
                   authority='signed_loopback_fixture', actual_linux_fuse=True, production_enrollment=False)
    receipt['libfuse_version'] = subprocess.check_output(['fusermount', '--version'], text=True).strip()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicLinux))
    receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   skipped=len(result.skipped), passed=result.wasSuccessful() and result.testsRun == 10 and not result.skipped)
    (directory / 'linux-fuse-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
