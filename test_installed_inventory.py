"""Execute the actual isolated-child verification source on disposable wheels."""
import ast,os,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path

class InstalledInventory(unittest.TestCase):
    def test_exact_manifest_derived_count_and_corruption_refusal(self):
        tree=ast.parse(Path(__file__).with_name('production_install.py').read_text())
        scripts=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and
          isinstance(n.value,str) and n.value.startswith('import meshia_node,pathlib,sys,zipfile')]
        self.assertEqual(len(scripts),1)
        for damage in ('none','missing','extra','changed'):
            with self.subTest(damage=damage),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);package=root/'meshia_node';package.mkdir()
                entries={'meshia_node/__init__.py':b''}
                entries.update({f'meshia_node/module_{i}.py':b'# exact fixture\n' for i in range(85)})
                wheel=root/'fixture.whl'
                with zipfile.ZipFile(wheel,'w') as archive:
                    for name,body in entries.items():
                        archive.writestr(name,body);(root/name).write_bytes(body)
                if damage=='missing':(package/'module_0.py').unlink()
                if damage=='extra':(package/'unexpected.py').write_text('# unexpected')
                if damage=='changed':(package/'module_0.py').write_text('# changed')
                result=subprocess.run([sys.executable,'-c',scripts[0],str(wheel)],cwd=root,
                  env={**os.environ,'PYTHONPATH':str(root)},capture_output=True,text=True,timeout=10)
                if damage=='none':self.assertEqual((result.returncode,result.stdout.strip()),(0,'86'))
                else:self.assertNotEqual(result.returncode,0)
