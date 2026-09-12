import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path

PROBE=Path(__file__).with_name('tempfile_probe.py').read_text()
class TemporaryFileProbe(unittest.TestCase):
    def test_real_stdio_default_temp_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);tmp=root/'tmp';tmp.mkdir()
            result=subprocess.run([sys.executable,'-I','-c',PROBE],cwd=root,
              env={**os.environ,'TMPDIR':str(tmp)},capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=json.loads(result.stdout)
            self.assertTrue(all(v is True for k,v in receipt.items() if k!='uid'))
            self.assertEqual(list(tmp.iterdir()),[])
    def test_outside_temp_is_rejected_before_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);workspace=root/'workspace';workspace.mkdir();outside=root/'outside';outside.mkdir()
            result=subprocess.run([sys.executable,'-I','-c',PROBE],cwd=workspace,
              env={**os.environ,'TMPDIR':str(outside)},capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('TMPDIR_OUTSIDE_WORKSPACE',result.stderr)
            self.assertEqual(list(outside.iterdir()),[])
