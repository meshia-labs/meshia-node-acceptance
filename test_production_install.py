import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
import production_install as p
import report

class ProductionInstall(unittest.TestCase):
    def test_pre_marker_cleanup_is_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(p.cleanup(Path(directory)), {'required': False, 'passed': True})

    def test_canary_is_real_owned_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = p.personal_canary(home, '123456')
            path = home / result['canary_relative_path']
            self.assertEqual(path.read_text(), result['canary_expected_content'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): p.personal_canary(home, '789')
            self.assertEqual(path.read_text(), result['canary_expected_content'])

    def test_missing_status_is_not_closure(self):
        self.assertFalse(p.local_closed({}, []))
        self.assertFalse(p.local_closed({'service': {'manager_active': False}}, [{}]))
        self.assertTrue(p.local_closed({'service': {'manager_active': False}}, []))

    def test_local_success_always_requires_owner_and_cleanup(self):
        receipt = {'local_install_and_closure_passed': True}
        self.assertEqual(p.finish_receipt(receipt, {'passed': True}), 0)
        self.assertTrue(receipt['requires_owner_receipt'])
        self.assertNotIn('passed', receipt)
        self.assertEqual(p.finish_receipt(receipt, {'passed': False}), 1)
        self.assertFalse(receipt['local_install_and_closure_passed'])

    def test_identity_excludes_authority(self):
        host = '11111111-1111-4111-8111-111111111111'
        self.assertEqual(p.identity({'host_id': host, 'token': 'secret', 'key': 'private'}), {'host_id': host})
        with self.assertRaises(ValueError):
            p.identity({'host_id': 'secret'})

    def test_wrong_delivery_bytes_never_written(self):
        class Response:
            url = p.ORIGIN + '/meshia-node/install-1.3.35.sh'
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return b'wrong'
        with tempfile.TemporaryDirectory() as path, patch.object(p.urllib.request, 'urlopen', return_value=Response()):
            with self.assertRaises(ValueError): p.fetch_exact('install-1.3.35.sh', Path(path))
            self.assertEqual(list(Path(path).iterdir()), [])

    def test_primary_refused_before_network(self):
        with tempfile.TemporaryDirectory() as path, patch.object(p, 'fresh_account', side_effect=AssertionError('not hosted')), patch.object(p, 'fetch_exact') as fetch:
            with self.assertRaises(AssertionError): p.execute(Path(path))
            fetch.assert_not_called()

    def test_report_drops_tokens_and_raw_output(self):
        self.assertEqual(report.public({'PAIR_GRANT': 'secret', 'stdout': 'secret', 'host_id': '11111111-1111-4111-8111-111111111111'}), {'host_id': '11111111-1111-4111-8111-111111111111'})
