import json,sqlite3,tempfile,unittest
from pathlib import Path
from cache_diagnostics import public_event,journal,cache_name,target_database,error_enum
from report import public
class Diagnostics(unittest.TestCase):
    def test_busy_reason_and_flags_are_strict_and_survive_projection(self):
        value={'event':'fabric_mount_rename_busy','reason':'destination_publishing',
          'source_cached':False,'destination_open_reader':True,'destination_session':'private',
          'destination_open_writer':1,'path':'private','error':'private','token':'private'}
        result=public_event(value)
        self.assertEqual(result,{'operation':'rename','error_code':'EBUSY','errno':16,
          'reason':'destination_publishing','source_cached':False,'destination_open_reader':True})
        self.assertEqual(public(result),result)
        self.assertIsNone(public_event({**value,'reason':'private'}))
    def test_native_logger_text_booleans_are_decoded_exactly(self):
        result=public_event({'event':'fabric_mount_rename_busy','reason':'source_changed',
          'source_cached':'True','destination_cached':'False','source_session':'true',
          'destination_open_writer':'False private','destination_open_reader':0})
        self.assertIs(result['source_cached'],True)
        self.assertIs(result['destination_cached'],False)
        self.assertNotIn('source_session',result)
        self.assertNotIn('destination_open_writer',result)
        self.assertNotIn('destination_open_reader',result)
    def test_singleton_requires_exact_private_authenticated_binding(self):
        target='11111111-1111-4111-8111-111111111111';other='22222222-2222-4222-8222-222222222222'
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve();(home/'.meshia').mkdir()
            database=home/'.meshia/fabric.db';database.touch()
            registry=home/'.meshia/workspace-state-locations.json'
            registry.write_text(json.dumps({'schema':'meshia.workspace-state-locations.v1','legacy':{
                'account_id':other,'session_id':target,'workspace_id':other,'workspace_root':str(home/'Meshia')}}))
            registry.chmod(0o600)
            self.assertEqual(target_database(home,target),database)
            with self.assertRaises(ValueError):target_database(home,other)
            registry.chmod(0o644)
            with self.assertRaises(ValueError):target_database(home,target)
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
                c.execute('CREATE TABLE pending_operations(scope_id,mutation_id,journal_seq,kind,path,destination_path,state,attempt_count,predecessor_mutation_id,base_generation,base_digest,expected_source_digest,expected_destination_digest,staged_digest,staged_size,request_digest,commit_unknown,last_error,updated_at_ns,claim_token)')
                c.execute('CREATE TABLE operation_dependencies(scope_id,mutation_id,predecessor_mutation_id)')
                target='11111111-1111-4111-8111-111111111111';dep='22222222-2222-4222-8222-222222222222';other='33333333-3333-4333-8333-333333333333'
                row=(1,target,2,'rename','xcrun_db-a','xcrun_db','conflict',1,dep,3,'a'*64,'b'*64,'c'*64,'d'*64,22,'e'*64,0,'409 FABRIC_DESTINATION_EXISTS secret/token',1,'secret')
                c.execute('INSERT INTO pending_operations VALUES('+','.join('?'*20)+')',row)
                c.execute('INSERT INTO pending_operations VALUES('+','.join('?'*20)+')',tuple(other if i==1 else 'personal' if i==4 else v for i,v in enumerate(row)))
                c.executemany('INSERT INTO operation_dependencies VALUES(?,?,?)',[(1,target,dep),(2,target,other),(1,other,other)])
                c.execute('ALTER TABLE pending_operations ADD COLUMN rename_source_json TEXT')
                c.execute('UPDATE pending_operations SET rename_source_json=? WHERE mutation_id=?',('{"private_block_map":"secret"}',target))
            c.close()
            result=journal(p);self.assertEqual(len(result),1);self.assertNotIn('secret',json.dumps(result))
            self.assertEqual(result[0]['dependency_ids'],[dep]);self.assertEqual(result[0]['last_error_code'],'FABRIC_DESTINATION_EXISTS')
            self.assertEqual(result[0]['expected_destination_digest'],'c'*64)
            self.assertIs(result[0]['rename_source_frozen'],True)
            rendered=public({'cache_diagnostics':{'samples':[{'journal':result}]}})
            self.assertEqual(rendered['cache_diagnostics']['samples'][0]['journal'][0]['dependency_ids'],[dep])
    def test_error_redaction_never_exports_message(self):
        self.assertIsNone(error_enum('token=secret /Users/personal'))
        self.assertIsNone(error_enum('EACCES secret'))
        self.assertEqual(error_enum('EBUSY'),'EBUSY')
        self.assertEqual(error_enum('HTTP409 FABRIC_DESTINATION_EXISTS /private/secret'),'FABRIC_DESTINATION_EXISTS')
    def test_unbound_release_cannot_fetch(self):
        import production_install as install
        from unittest.mock import patch
        with patch.object(install,'HASHES',{}),patch.object(install.urllib.request,'urlopen') as fetch:
            with self.assertRaises(ValueError):install.fetch_exact('release.json',Path('/tmp'))
            fetch.assert_not_called()
