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

from acceptance import fresh_account, cleanup, run, write_json, mounts, assess_gatekeeper

ORIGIN = 'https://meshia.io'
VERSION = '1.3.35'
SOURCE = 'de2e46b051946f4e8897767589bd656bf21ed783'
HASHES = {
    'MeshiaNode-1.3.35.app.zip': '3021f9bb5a543c45e8beedd0e0d473c2e4e8ff5c0ba2bba09410d4155eb0d69a',
    'release.json': 'e7f80910aeceb9c58d6df4cf0a5560641d02fcf3d9f14565fc60cd49bf144490',
    'install-1.3.35.sh': '4709dab517723a001572a8de5dcaf897f74c2f7c957dd6070ba157b128f847b7',
    'meshia_node-1.3.35-py3-none-any.whl': '549d7ac7e07158922a6cc589fe679add2a8449a0059b5610152afe0b43e411f5',
}

def fetch_exact(name, directory):
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
    grant = os.environ.pop('PAIR_GRANT', '')
    if not grant:
        raise ValueError('Missing one-use pairing grant')
    started = time.monotonic()
    cache_observer = None
    receipt = {'local_install_and_closure_passed': False, 'requires_owner_receipt': True,
               'source_commit': SOURCE, 'package_version': VERSION,
               'scope': 'hosted_macos_production_install', 'production_account_tested': False,
               'customer_privacy_prompt_ux_tested': False, 'steps': []}
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
        installer = fetch_exact('install-1.3.35.sh', directory)
        wheel = fetch_exact('meshia_node-1.3.35-py3-none-any.whl', directory)
        archive = fetch_exact('MeshiaNode-1.3.35.app.zip', directory)
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
        if os.environ.get('MESHIA_CACHE_DIAGNOSTICS') == 'true':
            from cache_diagnostics import Observer
            cache_observer = Observer(home, os.environ.get('MESHIA_DIAGNOSTIC_WORKSPACE_ID', ''))
            cache_observer.sample()
        record('installed_waiting_owner', **host, installed_modules=count,
               uid=os.getuid(), run_id=os.environ['GITHUB_RUN_ID'], **canary)
        # Root performs exact-host normal MCP checks and revocation. This job never
        # broadens permissions or declares those remote checks passed itself.
        while time.monotonic() - started < 660:
            if cache_observer is not None:cache_observer.sample()
            status = json.loads(run([cli, '--json', 'status'], timeout=15))
            if local_closed(status, mounts(home / 'Meshia')):
                record('service_and_mount_stopped', **host)
                receipt['local_install_and_closure_passed'] = True
                break
            time.sleep(5)
        if not receipt['local_install_and_closure_passed']:
            raise TimeoutError('Owner acceptance window ended')
    except Exception as error:
        receipt['failure'] = {'error_type': type(error).__name__}
    finally:
        grant = ''
        if cache_observer is not None:
            cache_observer.sample()
            receipt['cache_diagnostics'] = cache_observer.result()
        try:
            result = cleanup(directory)
        except Exception as error:
            result = {'passed': False, 'error_type': type(error).__name__}
        exit_code = finish_receipt(receipt, result)
        write_json(directory / 'receipt.json', receipt)
    return exit_code

if __name__ == '__main__':
    directory = Path(sys.argv[1])
    try:
        code = execute(directory)
    except Exception as error:
        # Includes pre-marker refusal; cleanup's absent marker is a no-op.
        write_json(directory / 'receipt.json', {
            'local_install_and_closure_passed': False, 'requires_owner_receipt': True,
            'failure': {'error_type': type(error).__name__}})
        code = 1
    raise SystemExit(code)
