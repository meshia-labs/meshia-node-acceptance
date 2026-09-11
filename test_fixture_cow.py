"""Real signed transport/journal/backend tests; no OS mount or policy claim."""
from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from fixture_plane import AcceptancePlane
from fixture_control_plane import NATIVE_WORKSPACE_PROFILE, Rejected
import cow_acceptance


@contextmanager
def joined(*, default_cache_policy=False, disk_usage=None):
    from meshia_node.client import SignedClient
    from meshia_node.config import ConfigStore, Paths
    from meshia_node.enroll import enroll
    from meshia_node.identity import DeviceIdentity
    from meshia_node.fabric import SignedFabricTransport, FabricAuthority
    from meshia_node.fabric_cache import FabricRangeCache
    from meshia_node.fabric_db import FabricDatabase
    from meshia_node.fabric_sync import FabricSyncCoordinator
    from meshia_node.fabric_watch import FabricWatch
    from meshia_node.workspace import WorkspaceBoundary
    plane = AcceptancePlane(); plane.select_access_mode('full'); plane.start()
    try:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve(); paths = Paths(root / 'node')
            config = enroll(paths=paths, api_url=plane.origin, pairing_code=plane.mint_pairing_code(),
                            access='files', workspace=root / 'enrolled')
            client = SignedClient(ConfigStore(paths), DeviceIdentity.load_or_create(paths.identity_dir))
            attached = client.post_json(f'/api/connected-hosts/{config.host_id}/attach', {
                'session_id': config.session_id, 'mount_name': 'workspace',
                'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
            host = plane.hosts[config.host_id]
            common = {'attachment_id': attached['attachment']['id'], 'workspace': 'workspace'}
            transport = SignedFabricTransport(client, host.id, allow_insecure_loopback=True)
            workspace_root = root / 'workspace'; workspace_root.mkdir()
            database = FabricDatabase(root / 'sync.sqlite3')
            workspace = WorkspaceBoundary(workspace_root)
            now = [100.0]
            clock = lambda: now[0]
            coordinator = FabricSyncCoordinator(transport, database,
                FabricRangeCache(root / 'cache', max_bytes=32*1024**2, chunk_bytes=4096),
                FabricWatch(workspace_root, debounce_seconds=0, force_fallback=True, clock=clock), workspace,
                FabricAuthority(host.id, host.session_id, host.generation, common['attachment_id']),
                root / 'staging', clock=clock, min_staging_free_bytes=0,
                staging_admission_path=root / 'admission.sqlite3', max_staging_bytes=128*1024**2,
                **({} if default_cache_policy else {'max_auto_materializations': 0}),
                **({} if disk_usage is None else {'disk_usage': disk_usage}))
            def drive(predicate):
                for _ in range(800):
                    coordinator.poll_once(); now[0] += .2
                    if predicate():
                        return
                    time.sleep(.002)
                pending = database.get_latest_nonterminal_operation(cow_acceptance.PATH)
                raise AssertionError('Signed COW fixture did not converge: ' + repr({
                    'errors': plane.safe_errors, 'sync_error_present': coordinator.last_error is not None,
                    'pending': None if pending is None else {key: getattr(pending, key, None)
                        for key in ('state', 'failure_count')},
                    'cow': plane.cow_counters}))
            try:
                drive(lambda: coordinator.ready_for_commands)
                yield plane, host, common, transport, coordinator, database, workspace, drive
            finally:
                coordinator.close(); database.close()
    finally:
        plane.stop()


class CowFixture(unittest.TestCase):
    def test_default_policy_prefetches_small_seed_but_sparse_source_stays_cold(self):
        from collections import namedtuple
        from meshia_node.fabric_mount import FabricMountBackend
        from meshia_node.fabric_contract_generated import FileTree
        capacity = namedtuple('Usage', 'total used free')(256*1024**3,128*1024**3,128*1024**3)
        with joined(default_cache_policy=True, disk_usage=lambda _path: capacity) as (
                plane, host, common, transport, coordinator, database, workspace, drive):
            self.assertEqual(coordinator.max_auto_materialized_bytes, 2*1024**3)
            small = plane.seed_cold_file(cow_acceptance.PATH, cow_acceptance.BASE)
            drive(lambda: plane.cow_source_read_bytes[small['content_sha256']] > 0)
            seed = plane.seed_cold_file(cow_acceptance.SPARSE_PATH, cow_acceptance.SPARSE_PREFIX,
                                       logical_size=cow_acceptance.SPARSE_SIZE)
            entry = plane.v2_entries[cow_acceptance.SPARSE_PATH]
            # Exact released production parser validates the sparse shape.
            tree = FileTree.from_descriptor(entry['blocks'], load_node=None, read_object=None, put_object=None)
            self.assertEqual((tree.size, tree.digest), (seed['size_bytes'], seed['digest']))
            drive(lambda: database.get_remote_manifest_head().generation >= seed['entry_seq'])
            self.assertEqual(plane.cow_source_read_bytes[seed['content_sha256']], 0)
            self.assertIsNone(workspace.stat_fingerprint(cow_acceptance.SPARSE_PATH))
            self.assertNotIn(cow_acceptance.SPARSE_PATH, plane.fabric_files)
            self.assertEqual(plane._tree_bytes(entry['blocks'], seed['size_bytes'], seed['digest'], validate_only=True), b'')
            with self.assertRaises(Rejected):
                plane._tree_bytes(entry['blocks'], seed['size_bytes'], seed['digest'])
            with self.assertRaises(Rejected):
                plane._tree_bytes(entry['blocks'], seed['size_bytes'], '0'*64, validate_only=True)
            with self.assertRaises(Rejected):
                plane._tree_bytes(entry['blocks'], seed['size_bytes'], seed['digest'], data_proofs=set(), validate_only=True)
            backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
            path = '/Research/' + cow_acceptance.SPARSE_PATH
            opened = None
            try:
                opened = backend.open(path, os.O_RDWR)
                self.assertIsNotNone(backend._handles[opened].tree_journal)
                self.assertEqual(plane.cow_source_read_bytes[seed['content_sha256']], 0)
                backend.write(opened, cow_acceptance.PATCH_OFFSET, cow_acceptance.PATCH)
                changed = bytearray(cow_acceptance.SPARSE_PREFIX)
                changed[cow_acceptance.PATCH_OFFSET:cow_acceptance.PATCH_OFFSET+len(cow_acceptance.PATCH)] = cow_acceptance.PATCH
                for offset in (0,65520,786400,len(changed)-64):
                    self.assertEqual(backend.read(opened,offset,64), bytes(changed[offset:offset+64]))
                self.assertEqual(backend.read(opened,seed['size_bytes']-512,128), bytes(128))
                backend.write(opened,seed['size_bytes']-256,b'tail-edit')
                self.assertEqual(backend.read(opened,seed['size_bytes']-260,17),bytes(4)+b'tail-edit'+bytes(4))
                self.assertLess(plane.cow_source_read_bytes[seed['content_sha256']], 32768)
                backend.truncate(path,cow_acceptance.SHRINK,handle=opened)
                backend.truncate(path,cow_acceptance.GROW,handle=opened); backend.fsync(opened)
                self.assertEqual(backend.read(opened,0,cow_acceptance.GROW), cow_acceptance.sparse_expected_bytes())
                backend.release(opened); opened=None; backend.flush_writes()
                drive(lambda: plane.fabric_files.get(cow_acceptance.SPARSE_PATH)==cow_acceptance.sparse_expected_bytes())
                self.assertGreater(plane.cow_source_read_bytes[seed['content_sha256']], 0)
                self.assertLessEqual(plane.cow_source_read_bytes[seed['content_sha256']], 4*1024**2)
                self.assertEqual(plane.v2_entries[cow_acceptance.SPARSE_PATH]['size_bytes'], cow_acceptance.GROW)
            finally:
                if opened is not None: backend.release(opened)
                backend.close()

    def test_signed_raw_cas_ticket_upload_preserves_current_storage_contract(self):
        with joined() as (plane, host, common, transport, *_):
            data = b'public canonical raw CAS upload fixture'
            digest = hashlib.sha256(data).hexdigest()
            response = transport.blocks({**common, 'operation': 'write_batch',
                'mutation_id': str(uuid.uuid4()), 'storage_kind': 'object_cas_v1',
                'blocks': [{'sha256': digest, 'size_bytes': len(data)}]})
            ticket = response['tickets'][0]
            self.assertEqual(ticket['storage_kind'], 'object_cas_v1')
            transport.upload_block(ticket, data)
            self.assertEqual(plane.fabric_cas[digest], data)

    def test_classic_dirty_rename_requires_separate_source_delete(self):
        from meshia_node.fabric_mount import FabricMountBackend
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
            catalog = transport.client.post_json(f'/api/connected-hosts/{host.id}/workspaces/catalog', {})
            storage = next(item['storage'] for item in catalog['workspaces'] if item['session_id'] == host.session_id)
            backend._remote_quota.update_catalog(catalog_generation=catalog['snapshot_generation'],
                quota_bytes=storage['quota_bytes'], used_bytes=storage['used_bytes'])
            path, destination = '/Research/classic.txt', '/Research/classic-renamed.txt'
            handle = None
            try:
                handle = backend.open(path, os.O_CREAT | os.O_WRONLY)
                backend.write(handle, 0, b'mounted'); backend.fsync(handle)
                backend.release(handle); handle = None
                backend.flush_writes()
                drive(lambda: plane.fabric_files.get('classic.txt') == b'mounted')
                handle = backend.open(path, os.O_WRONLY | os.O_TRUNC)
                self.assertIsNone(backend._handles[handle].tree_journal)
                backend.write(handle, 0, b'mounted-edited'); backend.fsync(handle)
                backend.release(handle); handle = None
                backend.rename(path, destination); backend.flush_writes()
                drive(lambda: plane.fabric_files.get('classic-renamed.txt') == b'mounted-edited'
                      and 'classic.txt' not in plane.v2_entries)
                facts = cow_acceptance.verify_rename_projection(
                    transport.snapshot_v2({**common, 'limit': 256}),
                    transport.lookup_v2({**common, 'path': 'classic.txt'}),
                    transport.lookup_v2({**common, 'path': 'classic-renamed.txt'}),
                    source='classic.txt', destination='classic-renamed.txt', size=14)
                self.assertTrue(facts['signed_list_old_source_absent'])
                operations = [entry['op'] for entry in plane.v2_journal]
                self.assertEqual(operations, ['put', 'put', 'delete'])
            finally:
                if handle is not None: backend.release(handle)
                backend.close()

    def test_canonical_raw_retained_journal_reloads_after_signed_path_delete(self):
        from meshia_node.fabric_native_journal import NativeJournalPool
        from meshia_node.fabric_file_version import FabricFileVersionPool
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            source = cow_acceptance.canonical_raw_source()
            seed = plane.seed_canonical_raw_file(source, cow_acceptance.RAW_BASE)
            drive(lambda: database.get_remote_manifest_head().generation >= seed['entry_seq'])
            pool = coordinator._native_journals
            job = pool.create(source['path'], expected_digest=source['digest'], expected_size=source['size_bytes'])
            owner = job.mutate(lambda: job.journal.retain(owner='mount:' + uuid.uuid4().hex))
            offset = 8*1024**2+7
            job.mutate(lambda: job.journal.write(offset, b'updated'))
            hold = plane.v2_file_holds[(host.session_id, host.id, job.token)]
            self.assertEqual(hold['entry']['sha256'], source['digest'])
            response = transport.commit_v2({**common, 'mutation_id': str(uuid.uuid4()),
                'ops': [{'op': 'delete', 'path': source['path'], 'prev_digest': source['digest']}]})
            self.assertEqual(response['applied'], 1)
            self.assertIsNone(transport.lookup_v2({**common, 'path': source['path']})['entry'])
            # Reload actual durable journal and hold state; this local test
            # does not claim a process crash or an operating-system mount.
            coordinator._native_journals.close(); coordinator._file_versions.close()
            coordinator._file_versions = FabricFileVersionPool(request=coordinator._file_version_request,
                check_context=coordinator._check_file_version_context, stream=coordinator._stream_file_version,
                read_source=coordinator._read_file_version_source, clock=coordinator._clock)
            coordinator._native_journals = pool = NativeJournalPool(coordinator)
            restored = pool.get(job.token)
            self.assertEqual(restored.source.entry.digest, source['digest'])
            self.assertEqual(restored.journal.read(offset, 7), b'updated')
            self.assertEqual(restored.journal.read(offset+4096, 37), cow_acceptance.RAW_BASE[offset+4096:offset+4133])
            restored.release(owner)
            self.assertTrue(pool.retire(job.token))
            self.assertTrue(plane.v2_file_holds[(host.session_id, host.id, job.token)]['released'])

    def test_canonical_raw_source_cold_cross_block_edit_publish_and_rename(self):
        from meshia_node.fabric_mount import FabricMountBackend
        for algorithm in ('implicit', 'sha256'):
            with self.subTest(algorithm=algorithm), joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
                source = cow_acceptance.canonical_raw_source(algorithm)
                seed = plane.seed_canonical_raw_file(source, cow_acceptance.RAW_BASE)
                self.assertEqual(seed['blocks'], source['blocks'])
                drive(lambda: database.get_remote_manifest_head().generation >= seed['entry_seq'])
                backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
                path = '/Research/' + source['path']
                destination = '/Research/' + cow_acceptance.RAW_DESTINATION
                handle = None
                try:
                    before = plane.fabric_counters['direct_get_bytes']
                    handle = backend.open(path, os.O_RDWR)
                    self.assertIsNotNone(backend._handles[handle].tree_journal)
                    self.assertEqual(plane.fabric_counters['direct_get_bytes'], before)
                    expected = bytearray(cow_acceptance.RAW_BASE)
                    for offset in (cow_acceptance.PATCH_OFFSET, 8*1024**2-5):
                        self.assertEqual(backend.write(handle, offset, cow_acceptance.PATCH), len(cow_acceptance.PATCH))
                        expected[offset:offset+len(cow_acceptance.PATCH)] = cow_acceptance.PATCH
                        self.assertEqual(backend.read(handle, offset-8, 64), bytes(expected[offset-8:offset+56]))
                    self.assertLess(plane.fabric_counters['direct_get_bytes'] - before, 32768)
                    backend.fsync(handle)
                    backend.truncate(path, cow_acceptance.SHRINK, handle=handle)
                    backend.truncate(path, cow_acceptance.GROW, handle=handle); backend.fsync(handle)
                    self.assertEqual(backend.read(handle, 0, cow_acceptance.GROW), cow_acceptance.expected_bytes())
                    backend.release(handle); handle = None
                    backend.rename(path, destination)
                    backend.flush_writes()
                    drive(lambda: plane.fabric_files.get(cow_acceptance.RAW_DESTINATION) == cow_acceptance.expected_bytes()
                          and source['path'] not in plane.v2_entries)
                    listed = transport.snapshot_v2({**common, 'limit': 256})
                    self.assertNotIn(source['path'], {entry['path'] for entry in listed['entries']})
                    self.assertIsNone(transport.lookup_v2({**common, 'path': source['path']})['entry'])
                    self.assertIsNotNone(transport.lookup_v2({**common, 'path': cow_acceptance.RAW_DESTINATION})['entry'])
                finally:
                    if handle is not None: backend.release(handle)
                    backend.close()

    def test_real_released_backend_cold_edit_fsync_truncate_and_durable_tree(self):
        from meshia_node.fabric_mount import FabricMountBackend
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            self.assertEqual(database.get_remote_manifest_head().generation, 0)
            seed = plane.seed_cold_file(cow_acceptance.PATH, cow_acceptance.BASE)
            drive(lambda: database.get_remote_manifest_head().generation >= seed['entry_seq'])
            self.assertFalse((workspace.root / cow_acceptance.PATH).exists())
            before = plane.fabric_counters['direct_get_bytes']
            backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
            path = '/Research/' + cow_acceptance.PATH
            handle = None
            try:
                handle = backend.open(path, os.O_RDWR)
                self.assertIsNotNone(backend._handles[handle].tree_journal)
                self.assertEqual(plane.fabric_counters['direct_get_bytes'], before)
                self.assertEqual(backend.write(handle, cow_acceptance.PATCH_OFFSET, cow_acceptance.PATCH),
                                 len(cow_acceptance.PATCH))
                self.assertLessEqual(plane.fabric_counters['direct_get_bytes'] - before, 8192)
                backend.fsync(handle)
                changed = bytearray(cow_acceptance.BASE)
                changed[cow_acceptance.PATCH_OFFSET:cow_acceptance.PATCH_OFFSET+len(cow_acceptance.PATCH)] = cow_acceptance.PATCH
                self.assertEqual(backend.read(handle, 0, len(changed)), bytes(changed))
                backend.truncate(path, cow_acceptance.SHRINK, handle=handle); backend.fsync(handle)
                backend.truncate(path, cow_acceptance.GROW, handle=handle); backend.fsync(handle)
                self.assertEqual(backend.read(handle, 0, cow_acceptance.GROW), cow_acceptance.expected_bytes())
                backend.release(handle); handle = None
                backend.flush_writes()
                drive(lambda: plane.fabric_files.get(cow_acceptance.PATH) == cow_acceptance.expected_bytes())
                self.assertEqual(plane.v2_entries[cow_acceptance.PATH]['blocks']['file_digest_algorithm'], 'sha256_tree_v1')
                self.assertGreater(plane.cow_counters['held_reads'], 0)
                self.assertGreater(plane.cow_counters['tree_node_proofs'], 0)
                self.assertGreater(plane.cow_counters['tree_commits'], 0)
            finally:
                if handle is not None: backend.release(handle)
                backend.close()

    def test_hold_immutable_identity_release_and_unreferenced_range_refusal(self):
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            seed = plane.seed_cold_file('held.bin', b'0123456789' * 1000)
            acquire = {**common, 'operation': 'file_hold', 'action': 'acquire', 'hold_id': str(uuid.uuid4()),
                       'path': 'held.bin', 'file_digest': seed['digest'], 'size_bytes': seed['size_bytes'],
                       'mode': 'read', 'ttl_seconds': 900}
            held = transport.blocks(acquire)
            self.assertEqual(held['digest'], seed['digest'])
            request = {**common, 'operation': 'read_batch_v2', 'hold_id': held['hold_id'],
                       'path': seed['path'], 'file_digest': seed['digest'], 'tree_path': [],
                       'blocks': [{'sha256': seed['content_sha256'], 'size_bytes': seed['size_bytes']}]}
            ticket = transport.block_reads(request)['tickets'][0]
            self.assertEqual(transport.download_block_range(ticket, 7, 19), (b'0123456789'*1000)[7:26])
            plane.v2_entries.pop('held.bin')
            self.assertEqual(transport.block_reads(request)['tickets'][0]['sha256'], seed['content_sha256'])
            with self.assertRaises(Rejected):
                plane.fabric_blocks(host, {**request, 'file_digest': 'f'*64})
            with self.assertRaises(Rejected):
                plane.fabric_blocks(host, {**request, 'blocks': [{'sha256': 'f'*64, 'size_bytes': 1}]})
            with self.assertRaises(Rejected):
                plane.fabric_blocks(host, {**acquire, 'size_bytes': seed['size_bytes']+1})
            transport.blocks({**common, 'operation': 'file_hold', 'action': 'release', 'hold_id': held['hold_id']})
            with self.assertRaises(Rejected): plane.fabric_blocks(host, request)
            with self.assertRaises(Rejected): plane.fabric_blocks(host, acquire)

    def test_tree_seed_rejects_bad_digest_missing_object_and_malformed_range(self):
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            seed = plane.seed_cold_file('seed.bin', b'public-fixture' * 1000)
            entry = copy.deepcopy(plane.v2_entries['seed.bin'])
            with self.assertRaises(Rejected):
                plane._tree_bytes(entry['blocks'], entry['size_bytes'], '0'*64)
            with self.assertRaises(Rejected):
                plane._tree_bytes(entry['blocks'], entry['size_bytes'], entry['sha256'], data_proofs=set())
            ticket = transport.block_reads({**common, 'operation': 'read_batch_v2', 'path': 'seed.bin',
                'blocks': [{'sha256': seed['content_sha256'], 'size_bytes': seed['size_bytes']}]})['tickets'][0]
            token = ticket['url'].rsplit('/', 1)[-1]
            for bad in ('bytes=-1', 'bytes=0-999999', 'bytes=4-2', 'private-value'):
                with self.assertRaises(Rejected): plane.fabric_direct_range(token, bad)
            plane.fabric_cas[seed['content_sha256']] = b'corrupt'
            with self.assertRaises(Rejected): plane.fabric_direct_range(token, 'bytes=0-2')


if __name__ == '__main__':
    unittest.main()
