"""No install or mount: exact bytes, ownership fences and real signed loopback."""
import base64
import hashlib
import json
import os
import socket
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
import app_acceptance
import report

# Import the verified distribution, never private checkout source.
acceptance.verify_release()
sys.path.insert(0, str(acceptance.ROOT / 'release' / 'meshia_node-1.3.25-py3-none-any.whl'))

class ReleaseBoundary(unittest.TestCase):
    def test_ca_progress_persists_exact_candidate_before_admission_failure(self):
        snapshots = []
        def enqueue(*args, **kwargs):
            name = snapshots[-1][-1]['name']
            self.assertEqual(snapshots[-1][-1]['status'], 'running')
            if name == 'homebrew_arm64':
                raise AssertionError('fixture startup failed')
            return name
        with patch.object(Path, 'is_file', return_value=True), self.assertRaisesRegex(AssertionError, 'fixture startup'):
            acceptance.limited_public_ca_stores(enqueue, lambda _: {'ca_certificates': 123},
                Path('/fixture/managed'), on_progress=snapshots.append)
        self.assertEqual(snapshots[0], [{'name': 'managed', 'present': True, 'status': 'running'}])
        self.assertEqual(snapshots[-1][0]['status'], 'succeeded')
        self.assertEqual(snapshots[-1][-1],
                         {'name': 'homebrew_arm64', 'present': True, 'status': 'running'})
        self.assertEqual(report.public({'public_ca_stores': snapshots[-1]})['public_ca_stores'], snapshots[-1])

    def test_native_completion_diagnostics_only_keep_fixed_public_reasons_and_types(self):
        reason = 'macOS did not isolate command ownership'
        output = ('Native command startup failed: ' + reason + ' private-sentinel\n'
                  'Meshia Node verification failed or timed out: private-sentinel\n'
                  'macOS native workspace boundary could not start: private-sentinel\n'
                  'PermissionError: [Errno 13] private-sentinel\n').encode()
        completion = {'result': {'output_base64': base64.b64encode(output).decode(),
            'message': 'private-sentinel', 'error_code': 'LOCAL_ACCESS_REFUSED', 'timed_out': False,
            'truncated': False, 'started_at': '2026-09-11T02:30:00Z', 'finished_at': '2026-09-11T02:30:10.123Z'}}
        value = acceptance.native_completion_diagnostics(completion)
        self.assertEqual(value['known_errors'], [reason])
        self.assertEqual(value['exception_types'], ['PermissionError'])
        self.assertTrue(value['native_startup_failed'])
        self.assertTrue(value['native_host_verification_failed'])
        self.assertTrue(value['workspace_boundary_start_failed'])
        self.assertFalse(value['truncated'])
        self.assertEqual(value['elapsed_seconds'], 10.123)
        self.assertEqual(value['errno'], 13)
        self.assertFalse(value['timed_out'])
        self.assertEqual(value['error_code'], 'LOCAL_ACCESS_REFUSED')
        self.assertNotIn('private-sentinel', json.dumps(report.public({'diagnostics': value})))
        for encoded in ('not base64', 'x' * 24001, None):
            with self.subTest(encoded_type=type(encoded).__name__):
                value = acceptance.native_completion_diagnostics({'result': {
                    'output_base64': encoded, 'timed_out': 'private-sentinel', 'error_code': 'private-sentinel'}})
                self.assertFalse(value['output_valid'])
                self.assertEqual(value['output_bytes'], 0)
                self.assertNotIn('timed_out', value)
                self.assertNotIn('error_code', value)
        value = acceptance.native_completion_diagnostics({'result': {
            'output_base64': '', 'timed_out': True,
            'message': 'The command exceeded its timeout and its process session was stopped.'}})
        self.assertTrue(value['timed_out'])
        self.assertEqual(len(value['known_errors']), 1)

    def test_failed_completion_retains_only_exact_bounded_ca_probe_result(self):
        for payload, expected in (({'ca_certificates': 123}, True),
                                  ({'ca_certificates': 0}, False),
                                  ({'ca_certificates': True}, False),
                                  ({'ca_certificates': 123, 'private': 'private-sentinel'}, False)):
            with self.subTest(expected=expected):
                output = (json.dumps(payload) + '\nNative command startup failed: private-sentinel\n').encode()
                value = acceptance.native_completion_diagnostics({'result': {
                    'exit_code': 70, 'output_base64': base64.b64encode(output).decode()}})
                self.assertEqual(value['ca_probe_completed'], expected)
                self.assertEqual(value.get('ca_certificates'), 123 if expected else None)
                self.assertNotIn('private-sentinel', json.dumps(report.public({'diagnostics': value})))

    def test_public_ca_probe_loads_real_default_store_and_rejects_empty_store(self):
        result = subprocess.run([sys.executable, '-I', '-c', acceptance.PUBLIC_CA_PROBE],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertGreater(json.loads(result.stdout)['ca_certificates'], 0)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'empty.pem').write_text('')
            environment = dict(os.environ, SSL_CERT_FILE=str(root / 'empty.pem'), SSL_CERT_DIR=str(root))
            result = subprocess.run([sys.executable, '-I', '-c', acceptance.PUBLIC_CA_PROBE],
                                    env=environment, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Default public CA store is empty', result.stderr)

    def test_public_ca_checks_use_signed_queue_for_managed_and_only_installed_homebrew(self):
        from unittest.mock import Mock
        managed = Path('/fixture/runtime/bin/python3')
        enqueue = Mock(side_effect=['managed-command', 'homebrew-command'])
        complete = Mock(return_value={'ca_certificates': 123, 'credential': 'private-sentinel'})
        with patch.object(Path, 'is_file', side_effect=[True, False]):
            stores = acceptance.limited_public_ca_stores(enqueue, complete, managed)
        self.assertEqual([c.kwargs['executable'] for c in enqueue.call_args_list],
                         [managed, Path('/opt/homebrew/bin/python3.14')])
        self.assertEqual([c.args[0] for c in complete.call_args_list],
                         ['managed-command', 'homebrew-command'])
        self.assertTrue(all(c.args == (acceptance.PUBLIC_CA_PROBE,) and c.kwargs['timeout'] == 10
                            for c in enqueue.call_args_list))
        self.assertEqual(stores[-1], {'name': 'homebrew_intel', 'present': False})
        self.assertNotIn('private-sentinel', json.dumps(report.public({'stores': stores})))
        self.assertEqual(report.public({'stores': stores})['stores'][0]['ca_certificates'], 123)
        for invalid in (0, True, '123', None, 100001):
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                acceptance.limited_public_ca_stores(Mock(), lambda _: {'ca_certificates': invalid}, managed)

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
        self.assertEqual(manifest['version'], '1.3.25')
        self.assertEqual(lock['source_commit'], '7d2415f5e1e0f6b37c91f067d6aebac365d92ae5')
        self.assertEqual(lock['package_commit'], '1960a1624e549ef62f43f7b26a031b6150d306a1')

    def test_tampered_artifact_lock_extra_file_and_symlink_fail(self):
        for mode in ('bytes', 'lock', 'extra', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                shutil.copytree(acceptance.ROOT / 'release', root / 'release')
                shutil.copy2(acceptance.ROOT / 'release-lock.json', root / 'release-lock.json')
                app = root / 'release' / 'MeshiaNode-1.3.25.app.zip'
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
            self.assertEqual(context['source'], '7d2415f5e1e0f6b37c91f067d6aebac365d92ae5')
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
                    'artifacts': {'meshia_node-1.3.25-py3-none-any.whl': 'a' * 64, 'credential': 'private-sentinel'},
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

    def test_failed_probe_phase_matches_exact_distribution_allowlist(self):
        from meshia_node.native_command import WORKSPACE_READ_PHASES
        for ready, phase in ([(False, phase) for phase in WORKSPACE_READ_PHASES]
                             + [(False, 'private-sentinel'), (False, []), (False, None), (True, 'complete')]):
            with self.subTest(ready=ready, phase=phase):
                result = acceptance.readiness_projection({'service': {'runtime': {'workspace_execution': {
                    'ready': ready, 'reason': 'ready' if ready else 'workspace_access_timeout',
                    'probe_phase': phase, 'output': 'private-sentinel'}}}})
                public = report.public({'installer_readiness': result})
                self.assertNotIn('private-sentinel', json.dumps(public))
                evidence = public['installer_readiness']['workspace_execution']
                if ready is False and isinstance(phase, str) and phase in WORKSPACE_READ_PHASES:
                    self.assertEqual(evidence['probe_phase'], phase)
                else:
                    self.assertNotIn('probe_phase', evidence)

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
    def test_signed_app_lane_preserves_native_fence_and_separate_command_claim(self):
        from fixture_plane import AcceptancePlane
        from fixture_control_plane import NATIVE_WORKSPACE_PROFILE
        from meshia_node.client import SignedClient
        from meshia_node.config import ConfigStore, Paths
        from meshia_node.enroll import enroll
        from meshia_node.identity import DeviceIdentity
        from meshia_node.native_apps import AppFence
        plane = AcceptancePlane(); plane.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                paths = Paths(Path(name) / 'node')
                config = enroll(paths=paths, api_url=plane.origin, pairing_code=plane.mint_pairing_code(),
                                access='files', workspace=Path(name) / 'workspace')
                client = SignedClient(ConfigStore(paths), DeviceIdentity.load_or_create(paths.identity_dir))
                base = f'/api/connected-hosts/{config.host_id}'
                client.post_json(base + '/attach', {'session_id': config.session_id,
                    'mount_name': 'workspace', 'permissions': dict(NATIVE_WORKSPACE_PROFILE)})
                app_id = plane.enqueue('app_control', {'operation': 'register_lab_app',
                    'arguments': {'app_id': 'fixture-app'}})
                exec_id = plane.enqueue('exec', {'argv': ['true']})
                self.assertEqual(client.post_json(base + '/commands/claim', {})['command']['id'], exec_id)
                body = {'workspace_commands': True, 'native_execution': True, 'app_commands': True,
                        'app_protocol': 'http-stream-v1', 'active_apps': []}
                claimed = client.post_json(base + '/commands/claim', body)['commands'][0]
                self.assertEqual(claimed['id'], app_id)
                fence = AppFence.from_command(claimed, config)
                self.assertEqual(fence.access_mode, 'full')
                active = fence.active('fixture-app', str(uuid.uuid4()))
                body['active_apps'] = [active]
                result = client.post_json(base + '/commands/claim', body)
                self.assertTrue(result['app_supervision'][0]['continue'])
                for field, value in (('instance_id', str(uuid.uuid4())), ('session_id', str(uuid.uuid4())),
                                     ('attachment_id', str(uuid.uuid4())), ('access_revision', 9)):
                    with self.subTest(field=field):
                        changed = {**body, 'active_apps': [{**active, field: value}]}
                        self.assertFalse(client.post_json(base + '/commands/claim', changed)['app_supervision'][0]['continue'])
                completion = {'command_id': app_id, 'claim_token': claimed['claim_token'],
                              'status': 'succeeded', 'result': {}, 'error_code': None}
                result = client.post_json(base + '/commands/complete-app-batch', {'completions': [completion]})
                self.assertEqual(result['completions'][0]['status'], 'acknowledged')
                self.assertIn(app_id, plane.completions)
                plane.app_grants['fixture-app']['deadline'] = plane.now() - 1
                self.assertFalse(client.post_json(base + '/commands/claim', body)['app_supervision'][0]['continue'])
                plane.select_access_mode('limited')
                self.assertFalse(client.post_json(base + '/commands/claim', body)['app_supervision'][0]['continue'])
                plane.enqueue('app_control', {'operation': 'reserve_lab_app_port', 'arguments': {'app_id': 'limited-app'}})
                limited = client.post_json(base + '/commands/claim', {**body, 'active_apps': []})['commands'][0]
                self.assertEqual(AppFence.from_command(limited, config).access_mode, 'limited')
                self.assertEqual(limited['execution_scope'], 'workspace')
        finally:
            plane.stop()

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
                    # NativeApps reserves its port by creating this nested
                    # registry. Exercise the released directory publisher,
                    # whose caller digest differs from ordinary file cohorts.
                    for directory in ('.gpu-hub-internal', '.gpu-hub-internal/lab-apps'):
                        (root / directory).mkdir()
                        coordinator.stage_local_directory(directory)
                        self.assertTrue(coordinator._publish_one_directory_put())
                        self.assertTrue(coordinator.refresh_remote())
                        self.assertTrue(database.is_remote_directory(directory))
                    registry = '.gpu-hub-internal/lab-apps/connected_host-' + host.id + '.json'
                    registry_bytes = b'{"apps":{},"port_leases":{"fixture":{"port":9000}}}'
                    (root / registry).write_bytes(registry_bytes)
                    self.assertTrue(watch.record_put(registry))
                    drive(lambda: plane.fabric_files.get(registry) == registry_bytes
                          and coordinator.ready_for_commands)
                    self.assertEqual(plane.safe_errors, [])
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
        body = {**common, 'mutation_id': str(uuid.uuid4()), 'request_digest': '0'*64, 'ops': [op],
                'inline_blocks': [{'sha256': sha, 'size_bytes': len(content), 'bytes_b64': base64.b64encode(content).decode()}]}
        import copy
        bad = []
        candidate = copy.deepcopy(body); candidate['inline_blocks'][0]['bytes_b64'] = base64.b64encode(b'bad').decode(); bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['attachment_id'] = str(uuid.uuid4()); bad.append(candidate)
        candidate = copy.deepcopy(body); candidate['request_digest'] = 'not-a-digest'; bad.append(candidate)
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
        changed = copy.deepcopy(body); changed['request_digest'] = '1'*64
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

class AppFixture(unittest.TestCase):
    def test_real_fixture_startup_failures_have_safe_distinct_exit_stages(self):
        # Ordinary temporary subprocesses prove diagnostic stages only, not
        # installed native ownership or Workspace-only isolation.
        for phase in ('child_setup', 'dependency_import', 'personal_boundary', 'mounted_write', 'listener_setup'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name, socket.socket() as listener:
                root = Path(name)
                private = root / 'private-sentinel'
                private.write_text('full')
                listener.bind(('127.0.0.1', 0)); listener.listen()
                argv = [sys.executable, '-I'] + (['-S'] if phase == 'dependency_import' else [])
                argv += ['-c', app_acceptance.APP_SOURCE]
                if phase != 'child_setup':
                    argv += ['limited' if phase == 'personal_boundary' else 'full', str(private)]
                if phase == 'mounted_write':
                    (root / 'mac-app-full.txt').mkdir()
                result = subprocess.run(argv, cwd=root,
                    env={**os.environ, 'PORT': str(listener.getsockname()[1])}, capture_output=True, timeout=10)
                self.assertEqual(app_acceptance.APP_EXIT_PHASES.get(result.returncode), phase)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'')

    def test_app_startup_diagnostics_accept_only_exact_service_literals(self):
        def completion(message, code='APP_START_FAILED'):
            return {'error_code': code, 'result': {'message': message,
                'started_at': '2026-09-11T12:00:00Z', 'finished_at': '2026-09-11T12:00:03.125Z'}}
        for exit_code in (70, 80, 81, 82, 83, 84, 85, -9):
            with self.subTest(exit_code=exit_code):
                message = f'App exited before opening its owned port. (exit code {exit_code})'
                safe = app_acceptance.app_completion_diagnostics(completion(message))
                self.assertEqual(safe['exit_code'], exit_code)
                self.assertEqual(safe.get('phase'), app_acceptance.APP_EXIT_PHASES.get(exit_code))
                self.assertEqual(safe['elapsed_seconds'], 3.125)
                self.assertEqual(report.public({'diagnostics': safe})['diagnostics'], safe)
        safe = app_acceptance.app_completion_diagnostics(completion(
            'App exited before opening its owned port. (LOCAL_ACCESS_REFUSED)'))
        self.assertEqual(safe, {'reason': 'LOCAL_ACCESS_REFUSED', 'elapsed_seconds': 3.125})
        for message in ('private-sentinel', 'App exited before opening its owned port. (private-sentinel)',
                        'App exited before opening its owned port. (exit code 83) private-sentinel',
                        'App exited before opening its owned port. (exit code 4294967296)',
                        'App exited before opening its owned port. (exit code -2147483649)',
                        None, [], 'x' * 201):
            with self.subTest(message_type=type(message).__name__):
                safe = app_acceptance.app_completion_diagnostics(completion(message))
                self.assertEqual(safe, {'elapsed_seconds': 3.125})
                self.assertNotIn('private-sentinel', json.dumps(report.public({'diagnostics': safe})))
        safe = app_acceptance.app_completion_diagnostics(completion(
            'App exited before opening its owned port. (exit code 83)', 'APP_OPERATION_FAILED'))
        self.assertEqual(safe, {'elapsed_seconds': 3.125})

    def test_fixture_server_same_port_http_sse_and_websocket_without_native_claim(self):
        # This proves fixture bytes and the already-installed websockets API,
        # not native ownership or Limited isolation. Hosted acceptance must
        # launch the same code through the installed daemon's signed queue.
        from websockets.sync.client import connect
        with tempfile.TemporaryDirectory() as name, socket.socket() as reservation:
            root = Path(name); workspace = root / 'workspace'; workspace.mkdir()
            personal = root / 'personal'; personal.write_text('full')
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
            reservation.close()
            process = subprocess.Popen([sys.executable, '-I', '-u', '-c', app_acceptance.APP_SOURCE,
                'full', str(personal)], cwd=workspace, env={**os.environ, 'PORT': str(port)},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                def ready():
                    self.assertIsNone(process.poll(), 'Fixture server exited')
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/http', timeout=1) as response:
                            return json.load(response)
                    except OSError:
                        return None
                data = acceptance.wait('fixture HTTP', ready, 5)
                self.assertEqual(data['pid'], process.pid)
                self.assertEqual(data['uid'], os.getuid())
                self.assertTrue(all(data[key] == 'allowed' for key in ('read', 'write', 'stat')))
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/sse', timeout=2) as response:
                    self.assertEqual(response.headers['Content-Type'], 'text/event-stream')
                    self.assertEqual(response.read(), app_acceptance.SSE_BODY)
                import http.client
                for method, path, headers, status, length in (
                    ('HEAD', '/sse', {}, 200, len(app_acceptance.SSE_BODY)),
                    ('HEAD', '/sse', {'Range': 'bytes=16-47'}, 206, 32),
                    ('GET', '/not-modified', {}, 304, len(app_acceptance.SSE_BODY)),
                ):
                    with self.subTest(method=method, status=status):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                        try:
                            connection.request(method, path, headers=headers)
                            response = connection.getresponse()
                            self.assertEqual(response.status, status)
                            self.assertEqual(response.getheader('Content-Length'), str(length))
                            self.assertEqual(response.read(), b'')
                            if status == 206:
                                self.assertEqual(response.getheader('Content-Range'),
                                                 'bytes 16-47/' + str(len(app_acceptance.SSE_BODY)))
                        finally:
                            connection.close()
                request = urllib.request.Request(f'http://127.0.0.1:{port}/sse', headers={'Range': 'bytes=16-47'})
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 206)
                    self.assertEqual(response.read(), app_acceptance.SSE_BODY[16:48])
                with connect(f'ws://127.0.0.1:{port}/ws', open_timeout=2, close_timeout=1) as connection:
                    connection.send(app_acceptance.WS_BODY)
                    self.assertEqual(connection.recv(timeout=2), app_acceptance.WS_BODY)
                self.assertEqual((workspace / 'mac-app-full.txt').read_text(), 'app-compute-full')
                self.assertEqual(personal.read_text(), 'full')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)

    def test_driver_uses_typed_lane_closes_streams_and_never_promotes_failed_cleanup(self):
        for fail in (None, 'register', 'http', 'head', 'range_head', 'not_modified', 'websocket', 'cleanup'):
            with self.subTest(fail=fail), socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                calls, states, reads = [], [], {}
                def submit(kind, payload):
                    operation = payload['operation']; calls.append((kind, dict(payload)))
                    if operation == 'reserve_lab_app_port':
                        return {'lease': {'port': reservation.getsockname()[1]}}
                    if operation == 'register_lab_app':
                        if fail == 'register': raise AssertionError('fixture register')
                        self.assertEqual(payload['arguments']['launch_argv'][1:4], ['-I', '-u', '-c'])
                        self.assertEqual(payload['arguments']['cwd'], '.')
                        return {'app': {'instance_id': str(uuid.uuid4()), 'status': 'ready',
                                        'port': reservation.getsockname()[1]}}
                    if operation == 'unregister_lab_app':
                        return {'cleanup': {'owned_process_stopped': fail != 'cleanup'}}
                    if operation == 'open':
                        if fail == 'http': raise AssertionError('fixture HTTP')
                        if payload['method'] == 'HEAD' or payload['path'] == '/not-modified':
                            ranged = bool(payload['headers'].get('range'))
                            stage = 'not_modified' if payload['path'] == '/not-modified' else 'range_head' if ranged else 'head'
                            response = {'status': 304 if stage == 'not_modified' else 206 if ranged else 200,
                                'headers': {'content-length': str(32 if ranged else len(app_acceptance.SSE_BODY))},
                                'eof': True, 'body_base64': '', 'next_offset': 0}
                            if ranged:
                                response['headers']['content-range'] = 'bytes 16-47/' + str(len(app_acceptance.SSE_BODY))
                            if fail == stage:
                                if stage == 'head': del response['headers']['content-length']
                                elif stage == 'range_head': response['headers']['content-range'] = 'bytes 16-48/999'
                                else: response['body_base64'] = 'eA=='
                            return response
                        body = (json.dumps({'uid': os.getuid(), 'pid': 123, 'read': 'denied',
                                            'write': 'denied', 'stat': 'denied'}).encode()
                                if payload['path'] == '/http' else app_acceptance.SSE_BODY)
                        reads[payload['stream_id']] = body[262144:]
                        return {'status': 200, 'headers': {'content-type': 'text/event-stream'},
                                'body_base64': base64.b64encode(body[:262144]).decode(),
                                'eof': len(body) <= 262144, 'next_sequence': 1}
                    if operation == 'read':
                        return {'offset': 262144, 'body_base64': base64.b64encode(reads[payload['stream_id']]).decode(),
                                'eof': True, 'next_sequence': 2}
                    if operation == 'ws_open' and fail == 'websocket':
                        raise AssertionError('fixture WS')
                    if operation == 'ws_read':
                        return {'message_type': 'binary', 'body_base64': base64.b64encode(app_acceptance.WS_BODY).decode(),
                                'next_sequence': 1, 'end_of_message': True}
                    return {}
                def run():
                    return app_acceptance.exercise_app(submit, Path('/fixture/python'), Path('/fixture/personal'),
                        'limited', remember=lambda pid: pid, gone=lambda identity: True,
                        uid=os.getuid(), progress=lambda **state: states.append(state))
                if fail is None:
                    result = run()
                    self.assertTrue(result['http'] and result['sse_body'] and result['websocket_binary'])
                    self.assertTrue(all(result[key] for key in ('head', 'range_head', 'not_modified')))
                    self.assertTrue(all(report.public(result)[key] for key in ('head', 'range_head', 'not_modified')))
                    self.assertFalse(result['sse_progressive_timing_tested'])
                    self.assertEqual(result['outside_access'], 'denied')
                else:
                    with self.assertRaises(AssertionError): run()
                self.assertEqual(calls[-1][1]['operation'], 'unregister_lab_app')
                self.assertEqual(sum(p['operation'] == 'unregister_lab_app' for _, p in calls), 1)
                self.assertTrue(all(kind in ('app_control', 'app_http') for kind, _ in calls))
                self.assertEqual(states[-1]['owned_process_stopped'], fail != 'cleanup')
                if fail == 'http': self.assertTrue(any(p['operation'] == 'close' for _, p in calls))
                if fail == 'websocket': self.assertTrue(any(p['operation'] == 'ws_close' for _, p in calls))
                if fail in ('register', 'http', 'head', 'range_head', 'not_modified', 'websocket'):
                    self.assertTrue(any(state['phase'] == fail and state['status'] == 'failed' for state in states))

    def test_app_failure_receipt_accepts_only_public_fixed_error_code(self):
        allowed = {'APP_START_TIMEOUT', 'APP_HTTP_UNAVAILABLE'}
        for value in ('APP_START_TIMEOUT', 'private-sentinel', None, {'token': 'private-sentinel'}):
            code = app_acceptance.app_error_code(value, allowed)
            public = report.public({'native_app_failure': {'mode': 'full', 'phase': 'http',
                'status': 'failed', 'error_code': code, 'output': 'private-sentinel', 'claim_token': 'private-sentinel'}})
            self.assertNotIn('private-sentinel', json.dumps(public))
            self.assertEqual(code, value if value == 'APP_START_TIMEOUT' else 'unclassified')

if __name__ == '__main__':
    unittest.main()
