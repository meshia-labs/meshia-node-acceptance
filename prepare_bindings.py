"""Read-only exact candidate binding check; never fetch, edit, enroll or dispatch."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path

def prepare(candidate,wheel):
    value=json.loads(candidate.read_text())
    assert value['version']=='1.3.41' and value['source_dirty'] is False
    assert re.fullmatch('[a-f0-9]{40}',value['source_commit'])
    assert value['package']=='meshia_node-1.3.41-py3-none-any.whl'
    assert value['macos_node_app']=='MeshiaNode-1.3.41.app.zip'
    assert value['install']['posix']=='install-1.3.41.sh'
    hashes={'release.json':value.get('release_json_sha256',hashlib.sha256(candidate.read_bytes()).hexdigest()),value['package']:value['sha256'],
      value['macos_node_app']:value['macos_node_app_sha256'],value['install']['posix']:value['install']['posix_sha256']}
    assert all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in hashes.values())
    assert wheel.name==value['package'] and hashlib.sha256(wheel.read_bytes()).hexdigest()==value['sha256']
    with zipfile.ZipFile(wheel) as z:
        modules=[n for n in z.namelist() if n.startswith('meshia_node/') and n.endswith('.py')]
        assert len(modules)==len(set(modules)) and 'meshia_node/__init__.py' in modules
        assert 'meshia_node/linux_fuse.py' in modules
        assert all('..' not in Path(n).parts for n in modules)
    return {'version':value['version'],'source':value['source_commit'],'mac_hashes':hashes,
      'windows_wheel_sha256':value['sha256'],'wheel_manifest_module_count':len(modules),
      'public_delivery_verified':False,'dispatch_authorized':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('candidate',type=Path);p.add_argument('--wheel',type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.candidate,a.wheel),indent=2))
