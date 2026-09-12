"""Run via normal Limited native command, cwd=the disposable mounted workspace."""
import errno,json,os,pathlib,re,subprocess,time

def main():
    root=pathlib.Path.cwd()
    # Must be the account's actual mounted workspace; never substitute APFS.
    if not str(root).startswith('/Users/runner/Meshia/'):
        raise RuntimeError('Not the disposable hosted native mount')
    expected='/Users/runner/meshia-acceptance-personal.txt'
    try:pathlib.Path(expected).read_bytes()
    except PermissionError:pass
    else:raise RuntimeError('Workspace-only boundary was not applied')
    started=time.monotonic()
    child=subprocess.run(['/usr/bin/python3','-c','print("MESHIA_XCRUN_CACHE_PROBE")'],
                         capture_output=True,timeout=30)
    error=child.stderr.decode('utf-8',errors='replace')
    # Preserve diagnostics as classified facts, not concealed stderr. Export no
    # arbitrary output, private path, token, cache byte or request envelope.
    result={'python_exit_code':child.returncode,
      'python_marker':child.stdout==b'MESHIA_XCRUN_CACHE_PROBE\n',
      'elapsed_seconds':round(time.monotonic()-started,3),
      'stderr_bytes':len(child.stderr),'fsevents_failed':'Failed to start fs event stream' in error,
      'darwin_cache_confstr_failed':'DARWIN_USER_CACHE_DIR' in error,
      'cache_rename_failed':"couldn't rename cache file" in error,
      'cache_rename_permission_denied':"couldn't rename cache file" in error and 'Permission denied' in error,
      'cache_files':[]}
    for path in root.glob('xcrun_db*'):
        if not re.fullmatch(r'xcrun_db(?:-[A-Za-z0-9]{1,40})?',path.name) or path.is_symlink():continue
        try:
            s=path.stat();result['cache_files'].append({'name':path.name,'size':s.st_size,'uid':s.st_uid,
               'mode':oct(s.st_mode&0o777),'inode':s.st_ino})
        except OSError as e:result['cache_files'].append({'name':path.name,'errno':e.errno})
    a=root/'meshia-xcrun-rename-control.tmp';b=root/'meshia-xcrun-rename-control.done'
    if a.exists() or b.exists():raise RuntimeError('Control already attempted')
    try:
        with a.open('x') as output:output.write('cache-rename-control');output.flush();os.fsync(output.fileno())
        os.rename(a,b)
        result['atomic_control_rename_passed']=b.read_text()=='cache-rename-control'
    except OSError as error:result['atomic_control_rename_errno']=error.errno
    print(json.dumps(result))
if __name__=='__main__':main()
