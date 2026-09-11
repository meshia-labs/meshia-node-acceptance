"""Emit only bounded public proof fields, never config, keys or raw output."""
import json
import os
from pathlib import Path
import re
import sys

SAFE_KEYS = set('passed source_commit artifacts run_id scope production_account_tested customer_privacy_prompt_ux_tested artifact_transport deployed_https_delivery_tested native_apps_tested development_host_override loopback_control_transport steps name uid os architecture gui_domain image sip gatekeeper installed_modules empty_head native_host_owned native_host_pid runner_pid mounts path type ordinary_uid outside_read_write read write stat create cpus runtime workspace_read_write networking pid stale_pid_safe_identity completion_status cancellation_seconds command_timeout_seconds cancellation_before_natural_exit last_runtime live runtime_ready runtime_readiness_reason command_safe command_safety_reason sync_converged sync_convergence_reason fabric_head_generation package_version last_command status error_code exit_code failure phase error_type cleanup required service_registered service_definition_exists mounts_remaining owned_processes_gone errors action'.split())
SAFE_KEYS.update(('codesign_verified', 'notarization_ticket_valid', 'gatekeeper_accepted'))
ARTIFACT_NAMES = {'meshia_node-1.3.17-py3-none-any.whl', 'MeshiaNode-1.3.17.app.zip', 'install-1.3.17.sh'}

def public(value, *, depth=0):
    if depth > 6:
        return None
    if isinstance(value, dict):
        return {k: ({name: digest for name, digest in v.items()
                     if name in ARTIFACT_NAMES and isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest)}
                    if k == 'artifacts' and isinstance(v, dict) else public(v, depth=depth+1))
                for k, v in value.items() if k in SAFE_KEYS}
    if isinstance(value, list):
        return [public(v, depth=depth+1) for v in value[:30]]
    if isinstance(value, str):
        return value[:240]
    return value if value is None or isinstance(value, (bool, int, float)) else None

def main(directory):
    result = {}
    for name in ('receipt.json', 'cleanup.json'):
        path = Path(directory) / name
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
            result[name] = public(json.loads(path.read_text()))
    rendered = json.dumps(result, indent=2)
    if len(rendered.encode()) > 65536:
        raise ValueError('Public receipt exceeded bound')
    print(rendered)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write('### Exact 1.3.17 acceptance\n\n```json\n' + rendered + '\n```\n')

if __name__ == '__main__':
    main(sys.argv[1])
