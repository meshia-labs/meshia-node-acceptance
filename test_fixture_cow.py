"""Real signed transport/journal/backend tests; no OS mount or policy claim."""
from contextlib import contextmanager
import copy
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
def joined():
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
                root / 'staging', clock=clock, max_auto_materializations=0, min_staging_free_bytes=0,
                staging_admission_path=root / 'admission.sqlite3', max_staging_bytes=128*1024**2)
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
