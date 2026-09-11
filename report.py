"""Emit only bounded public proof fields, never config, keys or raw output."""
import json
import os
from pathlib import Path
import re
import sys

SAFE_KEYS = set('passed source_commit artifacts run_id scope production_account_tested customer_privacy_prompt_ux_tested artifact_transport deployed_https_delivery_tested native_apps_tested development_host_override loopback_control_transport steps name uid os architecture gui_domain image sip gatekeeper installed_modules empty_head native_host_owned native_host_pid runner_pid mounts path type ordinary_uid outside_read_write read write stat create cpus runtime workspace_read_write networking pid stale_pid_safe_identity completion_status cancellation_seconds command_timeout_seconds cancellation_before_natural_exit last_runtime live runtime_ready runtime_readiness_reason command_safe command_safety_reason sync_converged sync_convergence_reason fabric_head_generation package_version last_command status error_code exit_code failure phase error_type cleanup required service_registered service_definition_exists mounts_remaining owned_processes_gone errors action'.split())
SAFE_KEYS.update(('codesign_verified', 'notarization_ticket_valid', 'gatekeeper_accepted'))
SAFE_KEYS.update(('stores', 'ca_certificates'))
SAFE_KEYS.update(('public_ca_stores', 'output_valid', 'output_bytes', 'native_startup_failed',
                  'native_host_verification_failed', 'workspace_boundary_start_failed',
                  'timed_out', 'truncated', 'elapsed_seconds', 'errno', 'ca_probe_completed'))
SAFE_KEYS.update(('diagnostics', 'program', 'stdout_bytes', 'stderr_bytes', 'known_errors',
                  'exception_types', 'installer_state', 'cli_exists', 'native_app_exists',
                  'node_home_exists', 'fixture_errors', 'code', 'fixture_requests',
                  'snapshot', 'changes', 'commit', 'lookup'))
SAFE_KEYS.update(('installer_readiness', 'native_mount_enabled', 'manager_active', 'mount',
                 'mounted', 'state', 'workspace_execution', 'present', 'ready',
                 'policy_supported', 'reason', 'fuse_prerequisites'))
ARTIFACT_NAMES = {'meshia_node-1.3.21-py3-none-any.whl', 'MeshiaNode-1.3.21.app.zip', 'install-1.3.21.sh'}

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
            output.write('### Exact 1.3.21 acceptance\n\n```json\n' + rendered + '\n```\n')

if __name__ == '__main__':
    main(sys.argv[1])
