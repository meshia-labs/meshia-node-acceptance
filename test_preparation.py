"""Portable kit adaptation checks: no product import, install, service or mount."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import acceptance
import cow_acceptance
import report
import native_delta_acceptance as delta


class Preparation(unittest.TestCase):
    def test_open_descriptions_workload_and_public_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owned-file'
            path.write_bytes(delta.FD_SOURCE)
            result = json.loads(subprocess.check_output([sys.executable, '-I', '-c',
                delta.FD_PROBE, str(path)], timeout=10))
            self.assertEqual(path.read_bytes(), delta.fd_expected())
            self.assertTrue(result['retained_reader'])
            self.assertTrue(result['reader_cached_before_write'])
            self.assertEqual(report.public(result), result)
        for marker in delta.FD_FAILURE_MARKERS:
            safe = acceptance.subprocess_diagnostics(['python3'], 1, b'',
                ('AssertionError: ' + marker + ' private-sentinel').encode())
            self.assertEqual(safe['known_errors'], [marker])
            self.assertNotIn('private-sentinel', json.dumps(report.public({'diagnostics': safe})))

    def test_access_transition_fixture_preserves_complete_heartbeats(self):
        # Exact distribution and real signed endpoints. No blocked HTTP response,
        # native process, mount, primary state or product monkeypatch.
        acceptance.verify_release()
        sys.path.insert(0, str(acceptance.ROOT / 'release/meshia_node-1.3.30-py3-none-any.whl'))
        from fixture_plane import AccessTransitionPlane
        from fixture_control_plane import NATIVE_WORKSPACE_PROFILE
        from meshia_node.client import SignedClient
        from meshia_node.config import ConfigStore, Paths
        from meshia_node.enroll import enroll
        from meshia_node.identity import DeviceIdentity
        plane = AccessTransitionPlane(); plane.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                paths = Paths(Path(directory) / 'node')
                config = enroll(paths=paths, api_url=plane.origin, pairing_code=plane.mint_pairing_code(),
                                access='files', workspace=Path(directory) / 'workspace')
                client = SignedClient(ConfigStore(paths), DeviceIdentity.load_or_create(paths.identity_dir))
                base = f'/api/connected-hosts/{config.host_id}'
                attached = client.post_json(base + '/attach', {'session_id': config.session_id,
                    'mount_name': 'workspace', 'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
                heartbeat = {'attachment_id': attached['attachment']['id']}
                claim_body = {'workspace_commands': True, 'native_execution': True,
                              'app_commands': True, 'app_protocol': 'http-stream-v1', 'active_apps': []}
                for prior, current in (('full', 'limited'), ('limited', 'full')):
                    self.assertEqual(client.post_json(base + '/heartbeat', heartbeat)['access_mode'], prior)
                    plane.begin_access_transition(current)
                    self.assertEqual(client.post_json(base + '/heartbeat', heartbeat)['access_mode'], prior)
                    self.assertTrue(plane.heartbeat_observed.is_set())
                    command_id = plane.enqueue('app_control', {'operation': 'reserve_lab_app_port',
                        'arguments': {'app_id': 'transition-' + current}})
                    claim = client.post_json(base + '/commands/claim', claim_body)['commands'][0]
                    self.assertEqual(claim['id'], command_id)
                    self.assertEqual(claim['execution_scope'], 'workspace' if current == 'limited' else 'host')
                    self.assertEqual(claim['payload']['access_revision'], plane.app_access_revision)
                    plane.release_access_heartbeat()
                    self.assertEqual(client.post_json(base + '/heartbeat', heartbeat)['access_mode'], current)
        finally:
            plane.stop()

    def test_sparse_workload_is_bounded_on_a_disposable_sparse_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture'
            with path.open('wb') as output:
                output.write(cow_acceptance.SPARSE_PREFIX)
                output.truncate(cow_acceptance.SPARSE_SIZE)
            self.assertLess(path.stat().st_blocks*512,8*1024**2)
            result=json.loads(subprocess.check_output([sys.executable,'-I','-c',
                cow_acceptance.SPARSE_PROBE,str(path)],timeout=10))
            self.assertEqual(path.read_bytes(),cow_acceptance.sparse_expected_bytes())
            self.assertTrue(result['far_zero_tail'])
            self.assertTrue(result['sampled_untouched_prefix'])
            self.assertEqual(result['logical_source_bytes'],cow_acceptance.SPARSE_SIZE)
            self.assertEqual(report.public(result),result)
        observation={'source_size_bytes':cow_acceptance.SPARSE_SIZE,'physical_source_bytes':len(cow_acceptance.SPARSE_PREFIX),
                     'source_read_bytes_before':0,'source_read_bytes':8192,'raw_stderr':'private-sentinel','token':'private-sentinel'}
        projected=report.public({'phase':'mounted_sparse_cow_cold_precondition','cow_observation':observation,
                                 'message':'private-sentinel'})
        self.assertEqual(projected['cow_observation']['source_read_bytes'],8192)
        self.assertNotIn('private-sentinel',json.dumps(projected))
        for marker in cow_acceptance.PROBE_FAILURE_MARKERS:
            result=acceptance.subprocess_diagnostics(['python3'],1,b'',
                ('AssertionError: '+marker+' private-sentinel').encode())
            self.assertEqual(result['known_errors'],[marker])
            self.assertEqual(result['exception_types'],['AssertionError'])
            self.assertNotIn('private-sentinel',json.dumps(report.public({'diagnostics':result})))

    def test_unbound_release_fails_before_artifact_access(self):
        lock = json.loads((acceptance.ROOT / 'release-lock.json').read_text())
        self.assertEqual(lock['version'], '1.3.30')
        if lock['source_commit'] is None:
            self.assertIsNone(lock['package_commit'])
            self.assertTrue(all(value is None for value in lock['artifacts'].values()))
            self.assertIsNone(acceptance.LOCK_SHA256)
            with self.assertRaisesRegex(AssertionError, 'not bound'):
                acceptance.verify_release(Path('/does-not-exist'))
        else:
            acceptance.verify_release()

    def test_recreation_workload_on_plain_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = (Path(directory) / name for name in ('source', 'destination'))
            source.write_bytes(b'original')
            result = json.loads(subprocess.check_output([sys.executable, '-I', '-c',
                cow_acceptance.CLASSIC_RECREATE_PROBE, str(source), str(destination)], timeout=10))
            self.assertEqual(result, {'local_rename': True, 'source_recreated': True,
                                     'mounted_readback': True, 'fsync': True})
            self.assertEqual(source.read_bytes(), cow_acceptance.CLASSIC_RECREATE_BODY)
            self.assertEqual(destination.read_bytes(), cow_acceptance.CLASSIC_RENAME_BODY)
            self.assertEqual(report.public(result), result)

    def test_signed_recreation_projection_requires_both_exact_identities(self):
        bodies = {'source': cow_acceptance.CLASSIC_RECREATE_BODY, 'destination': cow_acceptance.CLASSIC_RENAME_BODY}
        entries = {name: {'path': name, 'kind': 'file', 'size_bytes': len(body),
                         'sha256': hashlib.sha256(body).hexdigest()} for name, body in bodies.items()}
        snapshot = {'schema': 'meshia.fabric_v2.snapshot.v1', 'workspace': 'workspace',
                    'next_after': None, 'entries': list(entries.values())}
        lookup = lambda name: {'schema': 'meshia.fabric_v2.entry.v1', 'workspace': 'workspace', 'entry': entries[name]}
        check = lambda s, a, b: cow_acceptance.verify_recreated_source_projection(
            s, a, b, source='source', destination='destination')
        self.assertEqual(check(snapshot, lookup('source'), lookup('destination')),
                         {'signed_recreated_source_present': True, 'signed_destination_present': True})
        for damage in ('source_absent', 'stale_digest', 'duplicate_path', 'wrong_workspace', 'partial_list'):
            with self.subTest(damage=damage):
                s, a, b = copy.deepcopy((snapshot, lookup('source'), lookup('destination')))
                if damage == 'source_absent': a['entry'] = None
                if damage == 'stale_digest': a['entry']['sha256'] = '0' * 64
                if damage == 'duplicate_path': s['entries'].append(s['entries'][0])
                if damage == 'wrong_workspace': b['workspace'] = 'other'
                if damage == 'partial_list': s['next_after'] = 'source'
                with self.assertRaises(AssertionError): check(s, a, b)


if __name__ == '__main__':
    unittest.main()
