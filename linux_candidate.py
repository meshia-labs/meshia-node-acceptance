"""Source-candidate qualification, explicitly not public-artifact acceptance."""
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest

import linux_fuse_acceptance as public

SOURCE = '06adc2e1b17fc92b2652d6b39e1d61ee89bc81b7'
OVERLAYS = {
    'fabric_mount.py': 'e0f641c50a9b683bef83eb6740b8099ab675f47cc0dc79766848b932aa9e5f70',
    'linux_fuse.py': '2905d79b4e5d45e0ec81b5de801effa67ed19fbf186cad752d462c0b17cb2e7e',
}


class CandidateLinux(public.LinuxFuse):
    def test_failed_replacement_retains_original_public_name(self):
        original = b'original destination bytes'
        with public.mounted(original, materialize=True) as (root, *_):
            destination = root / 'data.bin'
            writer = os.open(destination, os.O_RDWR)
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
                self.assertEqual(os.pread(writer, 100, 0), expected)
                self.assertEqual(source.read_bytes(), b'replacement')
                self.assertFalse(any(path.name.startswith('.fuse_hidden') for path in root.iterdir()))
            finally:
                os.close(writer)


def main():
    directory = Path(sys.argv[1])
    public.require_binding()
    assert sys.platform == 'linux' and os.getuid() != 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and Path('/dev/fuse').is_char_device()
    receipt = public.verify_installed(directory)
    import meshia_node
    package = Path(meshia_node.__file__).parent
    for name, digest in OVERLAYS.items():
        body = (Path(__file__).parent / 'candidate' / 'meshia_node' / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == digest
        (package / name).write_bytes(body)
        assert hashlib.sha256((package / name).read_bytes()).hexdigest() == digest
    receipt.update(source_candidate=True, public_artifact_acceptance=False, candidate_source=SOURCE,
                   candidate_module_sha256=OVERLAYS, uid=os.getuid(), kernel=os.uname().release,
                   authority='signed_loopback_fixture', actual_linux_fuse=True, production_enrollment=False)
    receipt['libfuse_version'] = subprocess.check_output(['fusermount', '--version'], text=True).strip()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CandidateLinux))
    receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   skipped=len(result.skipped), passed=result.wasSuccessful() and result.testsRun == 9 and not result.skipped)
    (directory / 'linux-candidate-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
