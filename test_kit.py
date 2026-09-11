"""No install or mount: exact bytes, ownership fences and real signed loopback."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest.mock import patch

import acceptance
import report

# Import the verified distribution, never private checkout source.
acceptance.verify_release()
sys.path.insert(0, str(acceptance.ROOT / 'release' / 'meshia_node-1.3.18-py3-none-any.whl'))

class ReleaseBoundary(unittest.TestCase):
    def test_disabled_or_changed_gatekeeper_policy_cannot_pass_assessment(self):
        for output in ((b'assessments disabled\n',),
                       (b'assessments enabled\n', b'', b'assessments disabled\n')):
            with self.subTest(output=output), patch.object(acceptance, 'run', side_effect=output) as command:
                with self.assertRaisesRegex(AssertionError, 'assessments must be enabled'):
                    acceptance.assess_gatekeeper(Path('/fixture.app'))
                self.assertEqual(command.call_count, len(output))
        with patch.object(acceptance, 'run', side_effect=(b'assessments enabled\n', b'', b'assessments enabled\n')):
            acceptance.assess_gatekeeper(Path('/fixture.app'))
        with patch.object(acceptance, 'run', side_effect=(b'assessments enabled\n', AssertionError('rejected'))):
            with self.assertRaisesRegex(AssertionError, 'rejected'):
                acceptance.assess_gatekeeper(Path('/fixture.app'))

    def test_exact_distributed_bytes_and_signed_plist(self):
        lock, manifest = acceptance.verify_release()
        self.assertEqual(manifest['version'], '1.3.18')
        self.assertEqual(lock['source_commit'], 'PENDING_FINAL_SOURCE_COMMIT')
        self.assertEqual(lock['package_commit'], 'PENDING_FINAL_PACKAGE_COMMIT')

    def test_tampered_artifact_lock_extra_file_and_symlink_fail(self):
        for mode in ('bytes', 'lock', 'extra', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                shutil.copytree(acceptance.ROOT / 'release', root / 'release')
                shutil.copy2(acceptance.ROOT / 'release-lock.json', root / 'release-lock.json')
                app = root / 'release' / 'MeshiaNode-1.3.18.app.zip'
                if mode == 'bytes':
                    app.write_bytes(app.read_bytes() + b'changed')
                elif mode == 'lock':
                    (root / 'release-lock.json').write_text('{}')
                elif mode == 'extra':
                    (root / 'release' / '.credential').write_text('fixture-only')
                else:
                    target = root / 'app'; app.replace(target); app.symlink_to(target)
                with self.assertRaises(AssertionError):
                    acceptance.verify_release(root)

    def test_fetch_refuses_primary_account_before_staging(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}):
            target = Path(name) / 'artifacts'
            with self.assertRaises(AssertionError):
                acceptance.fetch(target)
            self.assertFalse(target.exists())

    def test_fetch_binds_actual_bundle_without_private_checkout(self):
        with tempfile.TemporaryDirectory() as name, patch.object(acceptance, 'fresh_account'):
            target = Path(name) / 'artifacts'
            acceptance.fetch(target)
            context = acceptance.read_json(target / 'context.json')
            self.assertEqual(context['source'], 'PENDING_FINAL_SOURCE_COMMIT')
            for file, digest in context['artifacts'].items():
                self.assertEqual(hashlib.sha256((target / file).read_bytes()).hexdigest(), digest)

    def test_missing_or_wrong_cleanup_marker_never_calls_service(self):
        with tempfile.TemporaryDirectory() as name, patch.object(acceptance, 'run') as command:
            root = Path(name)
            self.assertEqual(acceptance.cleanup(root), {'required': False, 'passed': True})
            acceptance.write_json(root / 'owned.json', {'run_id': 'wrong'})
            with patch.object(acceptance, 'account', return_value=root), self.assertRaises(AssertionError):
                acceptance.cleanup(root)
            command.assert_not_called()

    def test_remaining_owned_mount_is_failure_not_recursively_deleted(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GITHUB_RUN_ID': '42'}):
            root = Path(name)
            acceptance.write_json(root / 'owned.json', {'run_id': '42', 'uid': os.getuid(),
                'home': str(root), 'fresh_installation_claimed': True})
            with patch.object(acceptance, 'account', return_value=root), \
                 patch.object(acceptance, 'mounts', return_value=[{'path': str(root / 'Meshia'), 'type': 'nfs'}]), \
                 patch.object(acceptance.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
                self.assertFalse(acceptance.cleanup(root)['passed'])

    def test_receipt_projection_discards_credentials_and_command_output(self):
        document = {'passed': True, 'token': 'private-sentinel', 'config': {'secret': 'hidden'},
                    'steps': [{'name': 'test', 'output_base64': 'private-sentinel'}],
                    'artifacts': {'meshia_node-1.3.18-py3-none-any.whl': 'a' * 64, 'credential': 'private-sentinel'},
                    'failure': {'phase': 'fixture', 'message': 'private-sentinel'}}
        rendered = json.dumps(report.public(document))
        self.assertNotIn('private-sentinel', rendered)
        self.assertNotIn('hidden', rendered)
        self.assertIn('fixture', rendered)
        self.assertIn('a' * 64, rendered)

    def test_local_artifact_server_has_no_listing_or_path_alias(self):
        with tempfile.TemporaryDirectory() as name, patch.object(acceptance, 'account'):
            root = Path(name); (root / 'fixture.whl').write_bytes(b'verified')
            context = {'artifacts': {'fixture.whl': hashlib.sha256(b'verified').hexdigest()}}
            with acceptance.artifact_origin(context, root) as origin:
                with urllib.request.urlopen(origin + '/fixture.whl') as response:
                    self.assertEqual(response.read(), b'verified')
                for path in ('/', '/../fixture.whl', '/fixture.whl?token=x', '/%66ixture.whl'):
                    with self.assertRaises(urllib.error.HTTPError) as rejected:
                        urllib.request.urlopen(origin + path)
                    rejected.exception.close()

    def test_failed_subprocess_cannot_export_captured_output(self):
        with self.assertRaises(AssertionError) as failure:
            acceptance.run([sys.executable, '-c', 'print("private-sentinel");raise SystemExit(7)'])
        self.assertNotIn('private-sentinel', str(failure.exception))
        self.assertNotIn('private-sentinel', json.dumps(failure.exception.diagnostics))

    def test_installer_diagnostics_only_include_hash_pinned_literal_reasons(self):
        reason = 'pairing enrollment failed'
        result = acceptance.subprocess_diagnostics(['bash'], 7,
            b'private-sentinel https://private.invalid/?token=private-sentinel',
            ('meshia-node install failed: ' + reason + '\nImportError: private-sentinel').encode())
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual(result['known_errors'], [reason])
        self.assertEqual(result['exception_types'], ['ImportError'])
        self.assertNotIn('private-sentinel', json.dumps(report.public({'diagnostics': result})))

    def test_installer_readiness_diagnostics_are_typed_and_private(self):
        value = acceptance.readiness_projection({'api_url': 'private-sentinel',
            'native_mount_enabled': True, 'mount': {'mounted': True, 'state': 'mounted',
                'mount_point': 'private-sentinel'},
            'service': {'native_host_owned': True, 'manager_active': True,
                'runtime': {'workspace_execution': {'ready': False, 'policy_supported': True,
                    'reason': 'workspace_access_denied', 'host_id': 'private-sentinel'}}}})
        self.assertEqual(value['workspace_execution']['reason'], 'workspace_access_denied')
        self.assertTrue(value['mount']['mounted'])
        self.assertNotIn('private-sentinel', json.dumps(report.public({'installer_readiness': value})))
        self.assertEqual(acceptance.readiness_projection({'mount': {'state': 'private-sentinel'},
            'service': {'runtime': {'workspace_execution': {'reason': 'private-sentinel'}}}})
            ['workspace_execution']['reason'], 'unknown')

    def test_fuse_diagnostics_only_execute_pinned_read_only_predicates(self):
        with patch.object(acceptance.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 1)) as execute:
            value = acceptance.fuse_prerequisite_projection()
        self.assertEqual(len(value), 25)
        self.assertFalse(any(check['passed'] for check in value))
        for call in execute.call_args_list:
            argv = call.args[0]
            self.assertIn(argv[4], {'fuse_t_path_is_safe', 'fuse_t_signed_by_pinned_team',
                                  'fuse_t_candidate_is_compatible', 'fuse_t_receipt_is_pinned'})
            self.assertNotIn('sudo', argv[2])
            self.assertEqual(call.kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(call.kwargs['stderr'], subprocess.DEVNULL)

    def test_fixed_installer_log_is_kept_without_adjacent_private_text(self):
        reason = 'Meshia is connected, but its background service has not verified access to the mounted workspace.'
        value = acceptance.subprocess_diagnostics(['bash'], 1, b'',
            ('private-sentinel ' + reason + '\nprivate-sentinel').encode())
        self.assertIn(reason, value['known_errors'])
        self.assertNotIn('private-sentinel', json.dumps(value))

    def test_installer_diagnostics_keep_last_observed_failure_in_execution_order(self):
        reason = 'Meshia is connected, but its background service has not verified access to the mounted workspace.'
        phases = ['Preparing the kext-less Meshia filesystem runtime',
            'Installing the kext-less filesystem runtime (one-time administrator approval)',
            'Meshia itself remains a script-installed user service',
            'skipping the native Meshia.app as requested', 'state directory ready (0700, no sudo used)',
            'Preparing the managed Python toolchain', 'Resolving the meshia-node release',
            'Installing and verifying the Meshia background service', reason]
        value = acceptance.subprocess_diagnostics(['bash'], 1, b'', '\n'.join(phases).encode())
        self.assertEqual(len(value['known_errors']), 8)
        self.assertEqual(value['known_errors'][-1], reason)

class FixtureAuthority(unittest.TestCase):
    def test_real_release_client_enrollment_signature_and_revocation(self):
        from fixture_plane import AcceptancePlane
        from meshia_node.client import SignedClient
        from meshia_node.config import ConfigStore, Paths
        from meshia_node.enroll import enroll
        from meshia_node.identity import DeviceIdentity
        from meshia_node.errors import Disconnected
        from fixture_control_plane import NATIVE_WORKSPACE_PROFILE
        plane = AcceptancePlane(); plane.select_access_mode('full'); plane.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                paths = Paths(Path(name) / 'node')
                config = enroll(paths=paths, api_url=plane.origin, pairing_code=plane.mint_pairing_code(),
                                access='files', workspace=Path(name) / 'workspace')
                client = SignedClient(ConfigStore(paths), DeviceIdentity.load_or_create(paths.identity_dir))
                # The fixture uses actual enrollment proof and signed request
                # verification; no native executor or primary installation runs.
                attached = client.post_json(f'/api/connected-hosts/{config.host_id}/attach', {
                    'session_id': config.session_id, 'mount_name': 'workspace',
                    'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
                body = {'attachment_id': attached['attachment']['id']}
                client.post_json(f'/api/connected-hosts/{config.host_id}/heartbeat', body)
                host = plane.hosts[config.host_id]
                self.assertGreater(len(host.consumed), 0)
                from meshia_node.fabric import SignedFabricTransport
                transport = SignedFabricTransport(client, config.host_id, allow_insecure_loopback=True)
                common = {'attachment_id': attached['attachment']['id'], 'workspace': 'workspace'}
                empty = transport.snapshot_v2({**common, 'after': None, 'limit': 256})
                self.assertEqual(empty, {'schema': 'meshia.fabric_v2.snapshot.v1', 'workspace': 'workspace',
                                        'last_seq': 0, 'entries': [], 'next_after': None})
                from meshia_node.fabric import FabricAuthority
                from meshia_node.fabric_cache import FabricRangeCache
                from meshia_node.fabric_db import FabricDatabase
                from meshia_node.fabric_sync import FabricSyncCoordinator
                from meshia_node.fabric_watch import FabricWatch
                from meshia_node.workspace import WorkspaceBoundary
                root = Path(name) / 'real-sync'; root.mkdir()
                workspace = WorkspaceBoundary(root)
                database = FabricDatabase(Path(name) / 'sync.sqlite3')
                clock = [100.0]
                tick = lambda: clock[0]
                watch = FabricWatch(root, debounce_seconds=0, force_fallback=True, clock=tick)
                coordinator = FabricSyncCoordinator(transport, database,
                    FabricRangeCache(Path(name) / 'cache', max_bytes=32*1024*1024, chunk_bytes=4096),
                    watch, workspace,
                    FabricAuthority(host.id, host.session_id, host.generation, common['attachment_id']),
                    Path(name) / 'staging', clock=tick, max_auto_materializations=0)
                try:
                    def drive(predicate):
                        for _ in range(600):
                            coordinator.poll_once(); clock[0] += 0.2
                            if predicate():
                                return
                            time.sleep(0.002)
                        self.fail('real released-wheel signed sync did not converge: ' + json.dumps(plane.safe_errors))
                    drive(lambda: coordinator.ready_for_commands)
                    head = database.get_remote_manifest_head()
                    self.assertEqual((head.generation, head.digest), (0, None))
                    self.assertEqual(database.list_remote_entries(), ())
                    self.assertEqual(plane.fabric_counters['manifest_requests'], 0)
                    (root / 'first.txt').write_bytes(b'first real signed sync')
                    self.assertTrue(watch.record_put('first.txt'))
                    drive(lambda: plane.fabric_files.get('first.txt') == b'first real signed sync')
                    self.assertGreater(plane.v2_calls['commit'], 0)
                    self.assertFalse(plane.fabric_manifest_available)
                    self.assertEqual(plane.fabric_counters['manifest_requests'], 0)
                    lookup = transport.lookup_v2({**common, 'path': 'first.txt'})['entry']
                    self.assertEqual(lookup['sha256'], hashlib.sha256(b'first real signed sync').hexdigest())
                    blocks = [{'sha256': b['sha256'], 'size_bytes': b['size_bytes']} for b in lookup['blocks']['blocks']]
                    tickets = client.post_json(f'/api/connected-hosts/{host.id}/fabric/blocks',
                        {**common, 'operation': 'read_batch_v2', 'path': 'first.txt', 'blocks': blocks})['tickets']
                    with urllib.request.urlopen(tickets[0]['url']) as response:
                        self.assertEqual(response.read(), b'first real signed sync')
                    from meshia_node.errors import RemoteError
                    with self.assertRaises(RemoteError):
                        transport.snapshot_v2({**common, 'attachment_id': str(uuid.uuid4()), 'after': None, 'limit': 256})
                    with self.assertRaises(RemoteError):
                        transport.manifest({**common, 'offset': 0, 'limit': 256})
                finally:
                    coordinator.close(); database.close(); workspace.close()
                plane.revoke(host)
                with self.assertRaises(Disconnected):
                    client.post_json(f'/api/connected-hosts/{config.host_id}/heartbeat', body)
                with self.assertRaises(Disconnected):
                    transport.snapshot_v2({**common, 'after': None, 'limit': 256})
        finally:
            plane.stop()

    def test_v2_commit_integrity_replay_and_authority_fences(self):
        from fixture_plane import AcceptancePlane
        from fixture_control_plane import Host, NATIVE_WORKSPACE_PROFILE, Rejected
        plane = AcceptancePlane()
        host = Host(id=str(uuid.uuid4()), public_key_pem='', generation=1, status='connected', session_id=str(uuid.uuid4()))
        plane.hosts[host.id] = host
        _, attached = plane.attach(host, {'session_id': host.session_id, 'mount_name': 'workspace', 'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
        common = {'attachment_id': attached['attachment']['id'], 'workspace': 'workspace'}
        content = b'bound bytes'; sha = hashlib.sha256(content).hexdigest()
        block = {'index': 0, 'offset_bytes': 0, 'size_bytes': len(content), 'sha256': sha}
        op = {'op': 'put', 'path': 'file.txt', 'kind': 'file', 'digest': sha, 'size_bytes': len(content),
              'blocks': {'version': 1, 'algorithm': 'sha256', 'block_size_bytes': len(content), 'block_count': 1,
                         'total_bytes': len(content), 'storage': {'kind': 'connected_host_object_cas_v1'}, 'blocks': [block]}}
        body = {**common, 'mutation_id': str(uuid.uuid4()), 'ops': [op],
                'inline_blocks': [{'sha256': sha, 'size_bytes': len(content), 'bytes_b64': base64.b64encode(content).decode()}]}
        import copy
        bad = []
        candidate = copy.deepcopy(body); candidate['inline_blocks'][0]['bytes_b64'] = base64.b64encode(b'bad').decode(); bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['attachment_id'] = str(uuid.uuid4()); bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['request_digest'] = '0'*64; bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['ops'][0]['path'] = '../outside'; bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['verification_mutation_ids'] = ['not-a-uuid']; bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['unknown'] = True; bad.append(candidate)
        for candidate in bad:
            with self.assertRaises(Rejected):
                plane.fabric_v2_commit(host, candidate)
            self.assertEqual(plane.fabric_files, {})
        result = plane.fabric_v2_commit(host, body)
        self.assertEqual(result[1]['applied'], 1)
        self.assertEqual(plane.fabric_v2_commit(host, body), result)
        self.assertEqual(len(plane.v2_journal), 1)
        changed = copy.deepcopy(body); changed['ops'][0]['path'] = 'changed.txt'
        with self.assertRaises(Rejected):
            plane.fabric_v2_commit(host, changed)
        plane.revoke(host)
        with self.assertRaises(Rejected):
            plane.fabric_v2_commit(host, body)

    def test_owner_downgrade_and_exact_command_supervision(self):
        from fixture_plane import AcceptancePlane
        from fixture_control_plane import Host, NATIVE_FULL_PROFILE, NATIVE_WORKSPACE_PROFILE
        plane = AcceptancePlane(); plane.select_access_mode('full')
        host = Host(id=str(uuid.uuid4()), public_key_pem='', generation=1,
                    status='connected', session_id=str(uuid.uuid4()))
        plane.hosts[host.id] = host
        _, attached = plane.attach(host, {'session_id': host.session_id, 'mount_name': 'workspace',
                                         'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
        self.assertEqual(attached['attachment']['permissions'], NATIVE_FULL_PROFILE)
        command = plane.enqueue('exec', {'argv': ['true']})
        _, claimed = plane.claim(host)
        self.assertEqual(claimed['command']['execution_scope'], 'host')
        active = {'id': command, 'claim_token': claimed['command']['claim_token']}
        self.assertTrue(plane.supervise(host, active)[1]['supervision']['continue'])
        plane.cancelled.add(command)
        self.assertFalse(plane.supervise(host, active)[1]['supervision']['continue'])
        plane.select_access_mode('limited')
        self.assertEqual(attached['attachment']['permissions'], NATIVE_WORKSPACE_PROFILE)
        plane.revoke(host)
        self.assertEqual(host.status, 'revoked')
        self.assertEqual(host.generation, 2)

if __name__ == '__main__':
    unittest.main()
