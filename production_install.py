"""Bounded real-account install proof. Pair grant is environment-only; no OAuth copy."""
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import time
import urllib.request
import uuid
import zipfile

from acceptance import account, validate_owned, read_json, fresh_account, cleanup, run, write_json, mounts, assess_gatekeeper

ORIGIN = 'https://meshia.io'
VERSION = '1.3.38'
SOURCE = '1084de4e5011b04dd4f5fffd26b3f87692686da0'
HASHES = {
    'release.json':'a4c1ba50fc22b1357a66a9d4849d140b13f8a847dd4c5a4ea961cf0189111d53',
    'install-1.3.38.sh':'4709dab517723a001572a8de5dcaf897f74c2f7c957dd6070ba157b128f847b7',
    'meshia_node-1.3.38-py3-none-any.whl':'6a570e0cd2b5f034861a051f7db454ee3249fe6e71a4cc51112389f1da6e7fe6',
    'MeshiaNode-1.3.38.app.zip':'1045b136f3072611cfae9f9b1ebd641554982efa9a62740965cf4052e3afaa63',
}

def fetch_exact(name, directory):
    if name not in HASHES:raise ValueError('Release artifact is not pinned')
    with urllib.request.urlopen(ORIGIN + '/meshia-node/' + name, timeout=30) as response:
        if not response.url.startswith(ORIGIN + '/meshia-node/'):
            raise ValueError('Unexpected delivery origin')
        body = response.read(256 * 1024 * 1024 + 1)
    if hashlib.sha256(body).hexdigest() != HASHES[name]:
        raise ValueError('Artifact mismatch')
    path = directory / name
    path.write_bytes(body)
    return path

def identity(config):
    # Deliberately never project the surrounding configuration or key fields.
    return {'host_id': str(uuid.UUID(config['host_id']))}

def personal_canary(home, run_id):
    if not re.fullmatch(r'[0-9]{1,24}', run_id):
        raise ValueError('Invalid run identity')
    name = 'meshia-acceptance-personal.txt'
    content = 'meshia-mac35-personal-' + run_id + '\n'
    # Exclusive creation also refuses existing symlinks; never replace user data.
    fd = os.open(home / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    return {'canary_relative_path': name, 'canary_expected_content': content}

def local_closed(status, mount_records):
    return status.get('service', {}).get('manager_active') is False and not mount_records

def finish_receipt(receipt, cleanup_result):
    receipt['cleanup'] = cleanup_result
    receipt['local_install_and_closure_passed'] = bool(
        receipt.get('local_install_and_closure_passed') and cleanup_result.get('passed'))
    receipt['requires_owner_receipt'] = True
    return 0 if receipt['local_install_and_closure_passed'] else 1

def execute(directory):
    directory.mkdir(parents=True, exist_ok=True)
    home = fresh_account()  # Refuses the primary Mac and every non-hosted account.
    if not VERSION or not SOURCE or len(HASHES)!=4:raise ValueError('Release is not bound')
    normal_grant = os.environ.pop('PAIR_GRANT', '')
    cache_grant = os.environ.pop('CACHE_PAIR_GRANT', '')
    grant = cache_grant if os.environ.get('MESHIA_CACHE_DIAGNOSTICS') == 'true' else normal_grant
    normal_grant = cache_grant = ''
    if not grant:
        raise ValueError('Missing one-use pairing grant')
    installation_ready = False
    receipt = {'local_install_and_closure_passed': False, 'requires_owner_receipt': True,
               'source_commit': SOURCE, 'package_version': VERSION,
               'scope': 'hosted_macos_production_install', 'production_account_tested': False,
               'customer_privacy_prompt_ux_tested': False, 'steps': [],
               'owner_wait_deadline_epoch': time.time()+660}
    def record(stage, **facts):
        event = {'name': stage, **facts}
        receipt['steps'].append(event)
        write_json(directory / 'receipt.json', receipt)
        print(json.dumps(event), flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
                output.write('\n```json\n' + json.dumps(event) + '\n```\n')
    try:
        manifest = json.loads(fetch_exact('release.json', directory).read_text())
        if manifest.get('source_commit') != SOURCE or manifest.get('version') != VERSION:
            raise ValueError('Release identity mismatch')
        installer = fetch_exact(f'install-{VERSION}.sh', directory)
        wheel = fetch_exact(f'meshia_node-{VERSION}-py3-none-any.whl', directory)
        archive = fetch_exact(f'MeshiaNode-{VERSION}.app.zip', directory)
        write_json(directory / 'owned.json', {'run_id': os.environ['GITHUB_RUN_ID'],
                   'uid': os.getuid(), 'home': str(home), 'fresh_installation_claimed': True})
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith(('MESHIA_', 'UV_', 'PYTHON'))
                       and k not in ('API_URL', 'PACKAGE_URL', 'PACKAGE_SHA256', 'CONNECT_MODE',
                                     'PAIR_CODE', 'PAIR_GRANT', 'NATIVE_APP_ZIP_URL', 'NATIVE_APP_ZIP_SHA')}
        environment['PAIR_GRANT'] = grant
        grant = ''
        try:
            run(['bash', installer, '--', '--access', 'limited'], timeout=360, environment=environment)
        finally:
            environment.pop('PAIR_GRANT', None)
        cli = home / '.meshia/runtime/bin/meshia-node'
        python = home / '.meshia/runtime/bin/python3'
        app = home / '.meshia/runtime/native/Meshia Node.app'
        run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
        run(['/usr/bin/xcrun', 'stapler', 'validate', app])
        assess_gatekeeper(app)
        with zipfile.ZipFile(archive) as bundle:
            candidates = [name for name in bundle.namelist()
                          if name.endswith('.app/Contents/MacOS/MeshiaNode')]
            if len(candidates) != 1 or bundle.read(candidates[0]) != (app / 'Contents/MacOS/MeshiaNode').read_bytes():
                raise ValueError('Installed native executable differs from pinned release')
        count = int(run([python, '-I', '-c',
            "import meshia_node,pathlib,sys,zipfile\n"
            "root=pathlib.Path(meshia_node.__file__).parent.parent\n"
            "with zipfile.ZipFile(sys.argv[1]) as z:\n"
            " names=[n for n in z.namelist() if n.startswith('meshia_node/') and n.endswith('.py')]\n"
            " assert len(names)==85 and all((root/n).read_bytes()==z.read(n) for n in names)\n"
            " print(len(names))", wheel]))
        config = json.loads((home / '.meshia/config.json').read_text())
        if config.get('api_url') != ORIGIN:
            raise ValueError('Wrong account origin')
        host = identity(config)
        if not mounts(home / 'Meshia'):
            raise ValueError('No native mount')
        receipt['production_account_tested'] = True
        canary = personal_canary(home, os.environ['GITHUB_RUN_ID'])
        receipt['installation_ready'] = True
        record('installed_waiting_owner', **host, installed_modules=count,
               uid=os.getuid(), run_id=os.environ['GITHUB_RUN_ID'],
               codesign_verified=True, notarization_ticket_valid=True,
               gatekeeper_accepted=True, native_executable_matched=True, **canary)
        from report import public
        write_json(directory/'installed-checkpoint.json',public(receipt))
        installation_ready = True
    except Exception as error:
        receipt['failure'] = {'error_type': type(error).__name__}
    finally:
        grant = ''
        # A successful install step ends now, publishing its verified checkpoint
        # before owner commands. Job-level always cleanup protects the gap.
        if not installation_ready:
            write_json(directory/'receipt.json',receipt)
    return 0 if installation_ready else 1

def finish_with_cleanup(directory,receipt=None):
    if receipt is None:
        try:
            receipt=read_json(directory/'receipt.json') if (directory/'receipt.json').exists() else {}
        except Exception as error:
            receipt={'failure':{'error_type':type(error).__name__}}
    try:
        result = cleanup(directory)
    except Exception as error:
        result = {'passed': False, 'error_type': type(error).__name__}
    code = finish_receipt(receipt, result)
    write_json(directory / 'receipt.json', receipt)
    return code

def wait_for_owner(directory):
    home=account()
    validate_owned(read_json(directory/'owned.json'),home)
    receipt=read_json(directory/'receipt.json');observer=None
    try:
        if not receipt.get('installation_ready') or receipt.get('package_version')!=VERSION or receipt.get('source_commit')!=SOURCE:
            raise ValueError('Verified installation checkpoint is absent')
        stage=next(s for s in receipt['steps'] if s['name']=='installed_waiting_owner')
        if stage['run_id']!=os.environ['GITHUB_RUN_ID'] or stage['uid']!=os.getuid():raise ValueError('Wrong checkpoint owner')
        deadline=receipt['owner_wait_deadline_epoch']
        if not time.time()<deadline<=time.time()+660:raise ValueError('Owner wait deadline invalid or expired')
        if os.environ.get('MESHIA_CACHE_DIAGNOSTICS')=='true':
            from cache_diagnostics import Observer
            observer=Observer(home,os.environ.get('MESHIA_DIAGNOSTIC_WORKSPACE_ID',''))
        cli=home/'.meshia/runtime/bin/meshia-node'
        while time.time()<deadline:
            if observer is not None:observer.sample()
            status=json.loads(run([cli,'--json','status'],timeout=15))
            if local_closed(status,mounts(home/'Meshia')):
                event={'name':'service_and_mount_stopped','host_id':stage['host_id']}
                receipt['steps'].append(event);print(json.dumps(event),flush=True)
                receipt['local_install_and_closure_passed']=True
                break
            time.sleep(5)
        if not receipt['local_install_and_closure_passed']:raise TimeoutError('Owner acceptance window ended')
    except Exception as error:
        receipt['failure']={'error_type':type(error).__name__}
    finally:
        if observer is not None:
            observer.sample();receipt['cache_diagnostics']=observer.result()
        write_json(directory/'receipt.json',receipt)
    return 0 if receipt['local_install_and_closure_passed'] else 1

if __name__ == '__main__':
    action=sys.argv[1];directory = Path(sys.argv[2])
    try:
        if action not in ('install','wait','cleanup'):raise ValueError('Unknown profile action')
        if action=='install':code=execute(directory)
        elif action=='wait':code=wait_for_owner(directory)
        else:code=finish_with_cleanup(directory)
    except Exception as error:
        # Includes pre-marker refusal; cleanup's absent marker is a no-op.
        write_json(directory / 'receipt.json', {
            'local_install_and_closure_passed': False, 'requires_owner_receipt': True,
            'failure': {'error_type': type(error).__name__}})
        code = 1
    raise SystemExit(code)
