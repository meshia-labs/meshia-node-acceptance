"""Exact public wheel, ordinary Linux FUSE, signed disposable loopback authority.

This does not enroll production compute or claim a new Linux execution-policy
qualification. It exercises only kernel file descriptions and atomic saves.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
from pathlib import Path
import sys
import threading
import time
import unittest
import zipfile

from production_install import VERSION, SOURCE, HASHES, fetch_exact


def require_binding():
    names = ('release.json', f'meshia_node-{VERSION}-py3-none-any.whl')
    if VERSION != '1.3.41' or not re.fullmatch(r'[0-9a-f]{40}', SOURCE):
        raise ValueError('Linux41 release source is not bound')
    if any(not re.fullmatch(r'[0-9a-f]{64}', HASHES.get(name, '')) for name in names):
        raise ValueError('Linux41 release artifacts are not bound')


def verify_installed(directory):
    import meshia_node
    wheel = directory / f'meshia_node-{VERSION}-py3-none-any.whl'
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == HASHES[wheel.name]
    assert importlib.metadata.version('meshia-node') == VERSION
    package = Path(meshia_node.__file__).parent
    with zipfile.ZipFile(wheel) as archive:
        modules = [name for name in archive.namelist()
                   if name.startswith('meshia_node/') and name.endswith('.py')]
        assert len(modules) >= 80
        installed_modules = {str(path.relative_to(package.parent)) for path in package.rglob('*.py')}
        assert installed_modules == set(modules), 'Installed Python module inventory differs from the wheel'
        module_sha256 = {}
        for name in modules:
            assert (package.parent / name).read_bytes() == archive.read(name), name
            module_sha256[name] = hashlib.sha256(archive.read(name)).hexdigest()
    return {'version': VERSION, 'source_commit': SOURCE,
            'wheel_sha256': HASHES[wheel.name], 'matched_python_modules': len(modules),
            'module_sha256': module_sha256}


@contextmanager
def mounted(seed=None, *, materialize=False):
    from meshia_node.fabric_mount import FabricMountBackend, FabricFuseMount, mount_registration_state
    from test_fixture_cow import joined
    with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
        if seed is not None:
            state = plane.seed_cold_file('data.bin', seed)
            drive(lambda: database.get_remote_manifest_head().generation >= state['entry_seq'])
            if materialize:
                assert coordinator.materialize('data.bin')
        backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=.05)
        backend._remote_quota.update_catalog(catalog_generation=1, quota_bytes=64*1024**2, used_bytes=0)
        mount = FabricFuseMount(backend, workspace.root.parent / 'mount',
                               state_path=workspace.root.parent / 'owned-mount.json')
        stop = threading.Event()
        failures = []
        def poll():
            try:
                while not stop.is_set():
                    drive(lambda: True)
                    stop.wait(.02)
            except BaseException as error:
                failures.append(type(error).__name__)
        worker = threading.Thread(target=poll, daemon=True)
        try:
            assert mount.start(), 'Actual Linux FUSE did not mount'
            worker.start()
            def settled(predicate):
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    assert not failures, failures
                    if predicate():
                        return
                    time.sleep(.02)
                raise AssertionError('Bounded signed publication did not settle')
            yield mount.mount_point / 'Research', plane, coordinator, database, workspace, settled
        finally:
            try:
                assert mount.close(), 'Owned FUSE mount did not close'
                assert mount_registration_state(mount.mount_point) is False
            finally:
                stop.set()
                if worker.ident is not None:
                    worker.join(5)
                    assert not worker.is_alive()
                backend.close()
                coordinator.close()
                workspace.close()


class LinuxFuse(unittest.TestCase):
    def coherence(self, cached_before_write):
        # Same two real-kernel cases as product test_fabric_mount_handle_coherence:
        # a materialized 256 KiB inode, optionally pre-read into kernel cache.
        original = bytes(range(256)) * 1024
        with mounted(original, materialize=True) as (root, *_):
            path = root / 'data.bin'
            writer, reader = os.open(path, os.O_RDWR), os.open(path, os.O_RDONLY)
            try:
                expected = bytearray(original)
                if cached_before_write:
                    self.assertEqual(os.pread(reader, len(original), 0), original)
                for offset, value in ((0, b'O29'), (4093, b'cross-page-write'), (262137, b'ENDSEED')):
                    self.assertEqual(os.pwrite(writer, value, offset), len(value))
                    expected[offset:offset+len(value)] = value
                os.fsync(writer)
                self.assertEqual(os.pread(reader, len(original), 0), expected)
                self.assertEqual(os.pread(writer, len(original), 0), expected)
                self.assertEqual(path.read_bytes(), expected)
                os.ftruncate(writer, 17)
                os.ftruncate(writer, 33)
                os.fsync(writer)
                self.assertEqual(os.pread(reader, 100, 0), expected[:17] + bytes(16))
                self.assertEqual(os.pread(writer, 100, 0), expected[:17] + bytes(16))
            finally:
                os.close(reader)
                os.close(writer)

    def test_existing_descriptions_without_kernel_preread(self):
        self.coherence(False)

    def test_existing_descriptions_with_kernel_preread(self):
        self.coherence(True)

    def replacement(self, publish_source, *, cold_source=False):
        original = b'meshia original cache\n'
        replacement = b'meshia replacement cache with a deliberately different length\n'
        with mounted() as (root, plane, coordinator, database, workspace, settled):
            dest, temp = root / 'xcrun_db', root / 'xcrun_db-Meshia36'
            def create(path, data):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    self.assertEqual(os.write(descriptor, data), len(data))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            create(dest, original)
            settled(lambda: plane.fabric_files.get(dest.name) == original and not database.list_operations())
            retained = None
            try:
                for index, value in enumerate((replacement, original, b'meshia third cache\n')):
                    if cold_source:
                        seeded = plane.seed_cold_file(temp.name, value)
                        settled(lambda: database.get_remote_manifest_head().generation >= seeded['entry_seq'])
                        self.assertIsNone(workspace.stat_fingerprint(temp.name))
                        # Exercise precisely the clean materialized target
                        # plus remote-only source branch changed in 1.3.39.
                        from meshia_node.fabric_mount import _fingerprint_text
                        coordinator.materialize(dest.name)
                        with coordinator._coordinator_lock:
                            cached = database.get_materialized(dest.name)
                            durable = coordinator._remote_entry_for_write(dest.name)
                            fingerprint = workspace.stat_fingerprint(dest.name)
                            self.assertIsNotNone(fingerprint)
                            self.assertEqual(cached.state, 'clean')
                            self.assertEqual(cached.clean_digest, durable.digest)
                            self.assertEqual(cached.stat_fingerprint, _fingerprint_text(fingerprint))
                    else:
                        create(temp, value)
                    if publish_source and not cold_source:
                        settled(lambda: plane.fabric_files.get(temp.name) == value and not database.list_operations())
                    os.replace(temp, dest)
                    self.assertEqual(dest.read_bytes(), value)
                    self.assertFalse(temp.exists())
                    if retained is not None:
                        self.assertEqual(os.pread(retained, 100, 0), replacement)
                    settled(lambda: plane.fabric_files.get(dest.name) == value
                            and temp.name not in plane.v2_entries and not database.list_operations())
                    if index == 0:
                        retained = os.open(dest, os.O_RDONLY)
                        self.assertEqual(os.pread(retained, 100, 0), replacement)
                self.assertFalse(database.list_conflicts())
            finally:
                if retained is not None:
                    os.close(retained)

    def test_reusable_temp_after_source_publication(self):
        self.replacement(True)

    def test_reusable_temp_immediately_after_close(self):
        self.replacement(False)

    def test_reusable_cold_source_over_materialized_destination(self):
        self.replacement(False, cold_source=True)

    def removed_reader(self, replace):
        original = b'meshia retained original inode\n'
        replacement = b'new namespace bytes with a different size\n'
        with mounted(original, materialize=True) as (root, plane, coordinator, database, workspace, settled):
            path = root / 'data.bin'
            reader = os.open(path, os.O_RDONLY)
            try:
                self.assertEqual(os.pread(reader, 100, 0), original)
                if replace:
                    source = root / 'replacement.tmp'
                    source.write_bytes(replacement)
                    os.replace(source, path)
                    self.assertEqual(path.read_bytes(), replacement)
                    self.assertFalse(source.exists())
                else:
                    path.unlink()
                    self.assertFalse(path.exists())
                stat = os.fstat(reader)
                self.assertEqual(stat.st_size, len(original))
                self.assertEqual(stat.st_nlink, 0)
                self.assertEqual(os.pread(reader, 100, 0), original)
                os.fsync(reader)
                settled(lambda: not database.list_operations() and (
                    plane.fabric_files.get('data.bin') == replacement if replace
                    else 'data.bin' not in plane.v2_entries))
                self.assertEqual(os.fstat(reader).st_size, len(original))
                self.assertEqual(os.pread(reader, 100, 0), original)
            finally:
                os.close(reader)

    def test_replaced_read_description_survives_nullpath(self):
        self.removed_reader(True)

    def test_unlinked_read_description_survives_nullpath(self):
        self.removed_reader(False)

    def test_stdlib_default_temporary_file_lifecycle(self):
        # Same unmodified stdlib probe as Mac40, executed on this real mount.
        probe = Path(__file__).with_name('tempfile_probe.py').read_text()
        with mounted() as (root, plane, coordinator, database, workspace, settled):
            temporary_root = root / 'tmp'
            temporary_root.mkdir()
            result = subprocess.run([sys.executable, '-I', '-c', probe], cwd=root,
                env={**os.environ, 'TMPDIR': str(temporary_root)},
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertTrue(all(value is True for key, value in receipt.items() if key != 'uid'))
            self.assertEqual(receipt['uid'], os.getuid())
            self.assertEqual(list(temporary_root.iterdir()), [])
            settled(lambda: not database.list_operations())
            self.assertFalse(any(path.startswith('tmp/') for path in plane.v2_entries))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['fetch', 'run'])
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    require_binding()
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.action == 'fetch':
        manifest = json.loads(fetch_exact('release.json', args.directory).read_text())
        assert (manifest['version'], manifest['source_commit']) == (VERSION, SOURCE)
        fetch_exact(f'meshia_node-{VERSION}-py3-none-any.whl', args.directory)
        return 0
    assert sys.platform == 'linux' and os.geteuid() != 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and Path('/dev/fuse').is_char_device()
    receipt = verify_installed(args.directory)
    receipt.update(uid=os.getuid(), kernel=os.uname().release, authority='signed_loopback_fixture',
                   actual_linux_fuse=True, production_enrollment=False)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LinuxFuse))
    receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   skipped=len(result.skipped), passed=result.wasSuccessful() and result.testsRun == 8 and not result.skipped)
    (args.directory / 'linux-fuse-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
