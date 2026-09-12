"""Disposable workspace stop watchdog. No enrollment, host command or revoke API.

The guest's independent deadline closes its owned service/mount and uninstalls.
The owner performs normal account revocation separately and can signal early
workspace cleanup with --cleanup-now. An ambiguous stop is never re-dispatched.
"""
import argparse,fcntl,json,os,stat,subprocess,tempfile,time,uuid
from pathlib import Path

PRIMARY='72bc84ae-63b5-4e2a-a0e7-c2a62726a6c3'
PROTECTED={'5c499700-783d-49bd-95e2-f6ce04efff78','e501608c-3b97-4739-b12a-f2a6ac6a9196'}
COUNTS='active_serverless_job_count unresolved_stop_target_count active_compute_instance_count active_runtime_endpoint_count provider_cleanup_pending_count active_compute_invocation_count nondeleted_storage_binding_count unresolved_mutation_authority_count pending_storage_delete_successor_count'.split()

def validate(binding):
    workspace=binding['workspace_id']
    assert str(uuid.UUID(workspace))==workspace and workspace not in PROTECTED
    assert binding['protected_primary_host']==PRIMARY
    assert binding['version']=='1.3.41' and binding['root_authorized'] is True
    assert binding['delete_storage'] is True
    assert type(binding['created_at']) in (int,float) and type(binding['deadline']) in (int,float)
    assert 0<binding['deadline']-binding['created_at']<=900
    return workspace

def complete(cleanup):
    return (cleanup.get('stop_operation_state')=='completed' and cleanup.get('billing_state')=='finalized'
      and cleanup.get('storage_terminal_state')=='deleted' and cleanup.get('cleanup_pending') is False
      and all(type(cleanup.get(k)) is int and cleanup[k]==0 for k in COUNTS))

def early_signal(path,workspace):
    try:info=path.lstat()
    except FileNotFoundError:return False
    assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_size<=128
    return json.loads(path.read_text())=={'workspace_id':workspace}

def advance(binding,state,call,save,now,early=False):
    workspace=validate(binding)
    result=call('meshia_workspace_status',{'workspace_id':workspace})
    cleanup=result.get('cleanup',{})
    assert cleanup.get('session_id')==workspace, 'Cleanup authority differs'
    original=cleanup.get('stop_operation_id')
    if original:
        assert not state.get('stop_operation_id') or state['stop_operation_id']==original
        state['stop_operation_id']=original
    state['cleanup']=cleanup;save(state)
    if complete(cleanup):state['completed']=True;save(state);return True
    if (early or now>=binding['deadline']) and not original and not state.get('stop_dispatched'):
        # Durable intent first: a crash or timeout cannot create a second stop.
        state['stop_dispatched']=True;save(state)
        call('meshia_workspace_stop',{'workspace_id':workspace,'confirm_stop':True,'delete_storage':True})
    return False

def main():
    p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True)
    p.add_argument('--state-dir',type=Path,required=True);p.add_argument('--cli',type=Path,required=True)
    p.add_argument('--cleanup-now',action='store_true');args=p.parse_args()
    binding=json.loads(args.binding.read_text());validate(binding)
    args.state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=args.state_dir.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700
    lock=os.open(args.state_dir/'watchdog.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    statepath=args.state_dir/'state.json'
    if statepath.exists():
        assert not statepath.is_symlink()
        state=json.loads(statepath.read_text());assert state['workspace_id']==binding['workspace_id']
    else:state={'workspace_id':binding['workspace_id']}
    def save(value):
        fd,name=tempfile.mkstemp(prefix='state-',dir=args.state_dir);temporary=Path(name)
        with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temporary,statepath)
        directory=os.open(args.state_dir,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    def call(name,arguments):
        assert name in {'meshia_workspace_status','meshia_workspace_stop'}
        result=subprocess.run([str(args.cli),'--json','call',name],input=json.dumps(arguments),
          text=True,capture_output=True,timeout=45)
        if result.returncode:raise RuntimeError('NORMAL_MCP_CALL_FAILED')
        return json.loads(result.stdout)
    while True:
        try:
            early=args.cleanup_now or early_signal(args.state_dir/'cleanup-now.json',binding['workspace_id'])
            if advance(binding,state,call,save,time.time(),early):return
        except (OSError,ValueError,subprocess.TimeoutExpired,RuntimeError):
            # No raw exception, subprocess output or credentials are exported.
            print('Waiting for authoritative cleanup readback',flush=True)
        time.sleep(5)

if __name__=='__main__':main()
