import json,sqlite3,tempfile,unittest
from pathlib import Path
from cache_diagnostics import public_event,journal,cache_name,target_database
class Diagnostics(unittest.TestCase):
    def test_multiple_workspaces_selects_only_exact_target(self):
        target='11111111-1111-4111-8111-111111111111';other='22222222-2222-4222-8222-222222222222'
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve()
            for workspace in [target,other]:
                path=home/'.meshia/accounts/account-a/workspaces'/workspace/'fabric.db'
                path.parent.mkdir(parents=True);path.touch()
            self.assertEqual(target_database(home,target).parent.name,target)
            second=home/'.meshia/accounts/account-b/workspaces'/target/'fabric.db'
            second.parent.mkdir(parents=True);second.touch()
            with self.assertRaises(ValueError):target_database(home,target)
    def test_rejects_workspace_path_injection(self):
        with self.assertRaises(ValueError):target_database(Path('/tmp'),'../../anything')
    def test_event_has_no_error_text_or_authority(self):
        e=public_event({'event':'fabric_mount_operation_failed','operation':'rename','error_code':'EBUSY',
            'error':'secret/path/token','claim_token':'secret','at':'2026-09-12'})
        self.assertNotIn('secret',json.dumps(e));self.assertEqual(e['errno'],16)
    def test_only_exact_cache_names(self):
        self.assertIsNone(cache_name('../xcrun_db'))
        self.assertIsNone(cache_name('xcrun_db-personal/file'))
        self.assertEqual(cache_name('xcrun_db-a12'),'xcrun_db-a12')
    def test_readonly_journal_excludes_payload_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'fabric.db'
            with sqlite3.connect(p) as c:
                c.execute('CREATE TABLE pending_operations(kind,path,destination_path,state,attempt_count,updated_at_ns,claim_token)')
                c.execute("INSERT INTO pending_operations VALUES('rename','xcrun_db-a','xcrun_db','queued',0,1,'secret')")
                c.execute("INSERT INTO pending_operations VALUES('put','personal',NULL,'queued',0,2,'secret')")
            result=journal(p);self.assertEqual(len(result),1);self.assertNotIn('secret',json.dumps(result))
