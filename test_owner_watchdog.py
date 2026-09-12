import unittest,tempfile,json
from pathlib import Path
import owner_watchdog as w

class Watchdog(unittest.TestCase):
    def setUp(self):
        self.b={'workspace_id':'11111111-1111-4111-8111-111111111111','version':'1.3.41',
          'protected_primary_host':w.PRIMARY,'root_authorized':True,'delete_storage':True,'created_at':0,'deadline':100}
        self.state={};self.calls=[];self.cleanup={'session_id':self.b['workspace_id']}
    def call(self,name,args):
        self.calls.append(name)
        if name.endswith('_stop'):raise TimeoutError('ambiguous')
        return {'cleanup':self.cleanup}
    def test_ambiguous_stop_never_repeated(self):
        with self.assertRaises(TimeoutError):w.advance(self.b,self.state,self.call,lambda s:None,101)
        w.advance(self.b,self.state,self.call,lambda s:None,102)
        self.assertEqual(self.calls.count('meshia_workspace_stop'),1)
    def test_existing_original_stop_is_read_only(self):
        self.cleanup['stop_operation_id']='original'
        w.advance(self.b,self.state,self.call,lambda s:None,101)
        self.assertEqual(self.calls,['meshia_workspace_status'])
        self.assertEqual(self.state['stop_operation_id'],'original')
    def test_all_counters_and_billing_required(self):
        c={k:0 for k in w.COUNTS};c.update(stop_operation_state='completed',billing_state='finalized',storage_terminal_state='deleted',cleanup_pending=False)
        self.assertTrue(w.complete(c));del c[w.COUNTS[0]];self.assertFalse(w.complete(c))
    def test_protected_workspace_denied(self):
        self.b['workspace_id']=next(iter(w.PROTECTED))
        with self.assertRaises(AssertionError):w.validate(self.b)
    def test_before_deadline_reads_only(self):
        w.advance(self.b,self.state,self.call,lambda s:None,50)
        self.assertEqual(self.calls,['meshia_workspace_status'])
    def test_early_signal_requires_exact_workspace_and_regular_file(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'signal';self.assertFalse(w.early_signal(p,self.b['workspace_id']))
            p.write_text(json.dumps({'workspace_id':self.b['workspace_id']}))
            self.assertTrue(w.early_signal(p,self.b['workspace_id']))
            self.assertFalse(w.early_signal(p,'other'))
            s=Path(d)/'link';s.symlink_to(p)
            with self.assertRaises(AssertionError):w.early_signal(s,self.b['workspace_id'])
