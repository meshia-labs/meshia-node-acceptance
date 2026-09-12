import unittest
from unittest.mock import patch
import tempfile
import json,os,time,zipfile
from pathlib import Path
import production_install as p
import report

class ProductionInstall(unittest.TestCase):
    def test_pre_marker_cleanup_is_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(p.cleanup(Path(directory)), {'required': False, 'passed': True})

    def test_malformed_receipt_cannot_skip_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'receipt.json').write_text('{unfinished')
            with patch.object(p,'cleanup',return_value={'passed':True}) as cleanup:
                self.assertEqual(p.finish_with_cleanup(root),1)
                cleanup.assert_called_once_with(root)

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
            url = p.ORIGIN + '/meshia-node/install-1.3.36.sh'
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return b'wrong'
        with tempfile.TemporaryDirectory() as path, patch.object(p,'HASHES',{'install-1.3.36.sh':'0'*64}), patch.object(p.urllib.request, 'urlopen', return_value=Response()):
            with self.assertRaises(ValueError): p.fetch_exact('install-1.3.36.sh', Path(path))
            self.assertEqual(list(Path(path).iterdir()), [])

    def test_primary_refused_before_network(self):
        with tempfile.TemporaryDirectory() as path, patch.object(p, 'fresh_account', side_effect=AssertionError('not hosted')), patch.object(p, 'fetch_exact') as fetch:
            with self.assertRaises(AssertionError): p.execute(Path(path))
            fetch.assert_not_called()

    def test_report_drops_tokens_and_raw_output(self):
        self.assertEqual(report.public({'PAIR_GRANT': 'secret', 'stdout': 'secret', 'host_id': '11111111-1111-4111-8111-111111111111'}), {'host_id': '11111111-1111-4111-8111-111111111111'})

    def test_install_returns_verified_checkpoint_before_wait_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory)/'home';home.mkdir();out=Path(directory)/'out';out.mkdir()
            binary=home/'.meshia/runtime/native/Meshia Node.app/Contents/MacOS/MeshiaNode'
            binary.parent.mkdir(parents=True);binary.write_bytes(b'synthetic-native')
            (home/'.meshia/config.json').write_text(json.dumps({'api_url':p.ORIGIN,'host_id':'11111111-1111-4111-8111-111111111111'}))
            def fetch(name,dest):
                path=dest/name
                if name=='release.json':path.write_text(json.dumps({'source_commit':'synthetic-source','version':'test'}))
                elif name.endswith('.zip'):
                    with zipfile.ZipFile(path,'w') as z:z.writestr('Meshia Node.app/Contents/MacOS/MeshiaNode',b'synthetic-native')
                else:path.touch()
                return path
            def run(argv,**kwargs):
                self.assertNotIn('status',argv)
                return b'85' if '-I' in argv else b''
            with patch.object(p,'fresh_account',return_value=home),patch.object(p,'VERSION','test'),patch.object(p,'SOURCE','synthetic-source'),patch.object(p,'HASHES',{str(i):str(i) for i in range(4)}),patch.object(p,'fetch_exact',side_effect=fetch),patch.object(p,'run',side_effect=run),patch.object(p,'assess_gatekeeper'),patch.object(p,'mounts',return_value=[{'synthetic':True}]),patch.object(p,'cleanup') as cleanup,patch.dict(os.environ,{'PAIR_GRANT':'synthetic','GITHUB_RUN_ID':'123','MESHIA_CACHE_DIAGNOSTICS':'false'}):
                self.assertEqual(p.execute(out),0);cleanup.assert_not_called()
            receipt=json.loads((out/'receipt.json').read_text())
            checkpoint=json.loads((out/'installed-checkpoint.json').read_text())
            self.assertEqual(checkpoint['steps'],receipt['steps'])
            self.assertNotIn('PAIR_GRANT',(out/'installed-checkpoint.json').read_text())
            self.assertTrue(receipt['installation_ready'])
            self.assertFalse(receipt['local_install_and_closure_passed'])
            stage=receipt['steps'][-1]
            self.assertEqual(stage['installed_modules'],85)
            for key in ('codesign_verified','notarization_ticket_valid','gatekeeper_accepted','native_executable_matched'):
                self.assertTrue(stage[key])

    def test_wait_failure_always_cleans_owned_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            receipt={'installation_ready':True,'package_version':'test','source_commit':'source',
                'local_install_and_closure_passed':False,'steps':[{'name':'installed_waiting_owner','run_id':'123','uid':os.getuid(),'host_id':'11111111-1111-4111-8111-111111111111'}],'owner_wait_deadline_epoch':time.time()-1}
            (root/'receipt.json').write_text(json.dumps(receipt));(root/'owned.json').write_text('{}')
            with patch.object(p,'account',return_value=root),patch.object(p,'validate_owned'),patch.object(p,'VERSION','test'),patch.object(p,'SOURCE','source'),patch.object(p,'cleanup',return_value={'passed':True}) as cleanup,patch.dict(os.environ,{'GITHUB_RUN_ID':'123'}):
                self.assertEqual(p.wait_for_owner(root),1);cleanup.assert_not_called()
                self.assertEqual(p.finish_with_cleanup(root,json.loads((root/'receipt.json').read_text())),1)
                cleanup.assert_called_once_with(root)
            self.assertFalse(json.loads((root/'receipt.json').read_text())['local_install_and_closure_passed'])

    def test_wait_success_closes_and_cleans_without_pairing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            receipt={'installation_ready':True,'package_version':'test','source_commit':'source',
                'local_install_and_closure_passed':False,'steps':[{'name':'installed_waiting_owner','run_id':'123','uid':os.getuid(),'host_id':'11111111-1111-4111-8111-111111111111'}],'owner_wait_deadline_epoch':time.time()+30}
            (root/'receipt.json').write_text(json.dumps(receipt));(root/'owned.json').write_text('{}')
            with patch.object(p,'account',return_value=root),patch.object(p,'validate_owned'),patch.object(p,'VERSION','test'),patch.object(p,'SOURCE','source'),patch.object(p,'cleanup',return_value={'passed':True}) as cleanup,patch.object(p,'mounts',return_value=[]),patch.object(p,'run',return_value=b'{"service":{"manager_active":false}}'),patch.dict(os.environ,{'GITHUB_RUN_ID':'123','MESHIA_CACHE_DIAGNOSTICS':'false'}):
                self.assertEqual(p.wait_for_owner(root),0);cleanup.assert_not_called()
                self.assertEqual(p.finish_with_cleanup(root,json.loads((root/'receipt.json').read_text())),0)
                cleanup.assert_called_once_with(root)
            saved=json.loads((root/'receipt.json').read_text())
            self.assertTrue(saved['local_install_and_closure_passed'])
            self.assertTrue(saved['requires_owner_receipt'])
            self.assertEqual(saved['steps'][-1]['name'],'service_and_mount_stopped')
