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
import unittest
import urllib.error
import urllib.request
import uuid
from unittest.mock import patch

import acceptance
import report

# Import the verified distribution, never private checkout source.
acceptance.verify_release()
sys.path.insert(0, str(acceptance.ROOT / 'release' / 'meshia_node-1.3.17-py3-none-any.whl'))

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
        self.assertEqual(manifest['version'], '1.3.17')
        self.assertEqual(lock['source_commit'], '119499e1824ffc02d187ef8589cbe51f6c72e9ee')
        self.assertEqual(lock['package_commit'], '9155ff76167e18757d667cbee987fb955444881e')

    def test_tampered_artifact_lock_extra_file_and_symlink_fail(self):
        for mode in ('bytes', 'lock', 'extra', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                shutil.copytree(acceptance.ROOT / 'release', root / 'release')
                shutil.copy2(acceptance.ROOT / 'release-lock.json', root / 'release-lock.json')
                app = root / 'release' / 'MeshiaNode-1.3.17.app.zip'
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
            self.assertEqual(context['source'], '119499e1824ffc02d187ef8589cbe51f6c72e9ee')
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
                    'artifacts': {'meshia_node-1.3.17-py3-none-any.whl': 'a' * 64, 'credential': 'private-sentinel'},
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
                plane.revoke(host)
                with self.assertRaises(Disconnected):
                    client.post_json(f'/api/connected-hosts/{config.host_id}/heartbeat', body)
        finally:
            plane.stop()

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
