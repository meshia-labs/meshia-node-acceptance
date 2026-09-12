"""Exact published Linux41 wheel acceptance with no source overlays."""
import errno
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from collections import deque

import linux_fuse_acceptance as public

class PublicLinux(public.LinuxFuse):
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
    from meshia_node.linux_fuse import LinuxInodeOperations
    events = deque(maxlen=100)
    original_getattr = LinuxInodeOperations.getattr
    original_rename = LinuxInodeOperations.rename
    def diagnostic_getattr(owner, path, fh=None):
        result = original_getattr(owner, path, fh)
        if path in owner._aliases:
            events.append({'event': 'hidden_getattr', 'failed': path in owner._failed_retirements,
                           'nlink': result['st_nlink'], 'size': result['st_size']})
        return result
    def diagnostic_rename(owner, old, new):
        event = {'event': 'rename', 'old_hidden': '.fuse_hidden' in old,
                 'new_hidden': '.fuse_hidden' in new, 'failed_before': len(owner._failed_retirements)}
        try:
            result = original_rename(owner, old, new)
            event['success'] = True
            return result
        except BaseException:
            event['success'] = False
            raise
        finally:
            event['failed_after'] = len(owner._failed_retirements)
            event['alias_count'] = len(owner._aliases)
            events.append(event)
    LinuxInodeOperations.getattr = diagnostic_getattr
    LinuxInodeOperations.rename = diagnostic_rename
    receipt.update(source_candidate=False, public_artifact_acceptance=True,
                   uid=os.getuid(), kernel=os.uname().release,
                   authority='signed_loopback_fixture', actual_linux_fuse=True, production_enrollment=False)
    receipt['libfuse_version'] = subprocess.check_output(['fusermount', '--version'], text=True).strip()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicLinux))
    receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   skipped=len(result.skipped), passed=result.wasSuccessful() and result.testsRun == 9 and not result.skipped)
    receipt.update(public_artifact_acceptance=False, callback_diagnostic=True, events=list(events))
    (directory / 'linux-fuse-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
