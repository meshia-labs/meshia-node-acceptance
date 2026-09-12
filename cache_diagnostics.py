"""Read-only, bounded diagnostics for the synthetic mounted xcrun cache."""
import errno,json,os,re,sqlite3,stat,time,uuid
from contextlib import closing
from pathlib import Path

CACHE=re.compile(r'^xcrun_db(?:-[A-Za-z0-9]{1,40})?$')
OPS={'rename','create','write','flush','fsync','release','getattr'}
BUSY_REASONS=set('destination_busy destination_publishing destination_changed destination_handoff_failed destination_dirty_cache source_changed source_writer source_unstable source_publishing publication_pending directory_pending directory_writer other_busy upload_pending destination_pending'.split())
BUSY_FLAGS=set('source_cached destination_cached source_session destination_session destination_modified destination_publishing destination_open_writer destination_open_reader'.split())
def public_event(value):
    if value.get('event')=='fabric_mount_rename_busy':
        if value.get('reason') not in BUSY_REASONS:return None
        result={'operation':'rename','error_code':'EBUSY','errno':16,'reason':value['reason']}
        if isinstance(value.get('at'),str) and re.fullmatch(r'[0-9T:.+Z-]{10,40}',value['at']):result['at']=value['at']
        result.update({key:value[key] for key in BUSY_FLAGS if type(value.get(key)) is bool})
        return result
    if value.get('event')!='fabric_mount_operation_failed' or value.get('operation') not in OPS:return None
    code=value.get('error_code')
    if not isinstance(code,str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',code):return None
    # Never copy error text, paths, request data or arbitrary log fields.
    return {'operation':value['operation'],'error_code':code,
            'errno':getattr(errno,code,None),'at':str(value.get('at',''))[:40]}
def cache_name(value):
    return value if isinstance(value,str) and CACHE.fullmatch(value) else None
def identifier(value):
    return value if isinstance(value,str) and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value) else None
def digest(value):
    return value if isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) else None
def error_enum(value):
    # Export only a machine enum, never an adjacent message, URL or path.
    found=re.search(r'\bFABRIC_[A-Z0-9_]{1,80}\b',str(value or '')[:4096])
    if found:return found.group(0)
    return value if value in ('EBUSY','ESTALE','EACCES','EIO','ENOENT') else None
def journal(database):
    if database.is_symlink():raise ValueError('Database symlink')
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=.2)) as connection:
        connection.row_factory=sqlite3.Row
        rows=connection.execute("SELECT scope_id,mutation_id,journal_seq,kind,path,destination_path,state,attempt_count,"
          "predecessor_mutation_id,base_generation,base_digest,expected_source_digest,expected_destination_digest,"
          "staged_digest,staged_size,request_digest,commit_unknown,last_error,(rename_source_json IS NOT NULL) AS rename_source_frozen FROM pending_operations "
          "WHERE path GLOB 'xcrun_db*' OR destination_path GLOB 'xcrun_db*' ORDER BY updated_at_ns DESC LIMIT 4").fetchall()
        result=[]
        for row in rows:
            if not cache_name(row['path']) or (row['destination_path'] is not None and not cache_name(row['destination_path'])):continue
            if not identifier(row['mutation_id']):continue
            item={key:(row[key] if isinstance(row[key],int) and 0<=row[key]<2**63 else None) for key in ('journal_seq','attempt_count','base_generation','staged_size','commit_unknown')}
            item['kind']=row['kind'] if row['kind'] in ('put','delete','rename') else None
            item['state']=row['state'] if row['state'] in ('queued','inflight','retry','acked','conflict','quarantined') else None
            item['rename_source_frozen']=bool(row['rename_source_frozen'])
            item.update(mutation_id=identifier(row['mutation_id']),cache_path=cache_name(row['path']),cache_destination=cache_name(row['destination_path']),
              predecessor_mutation_id=identifier(row['predecessor_mutation_id']),last_error_code=error_enum(row['last_error']))
            for key in ('base_digest','expected_source_digest','expected_destination_digest','staged_digest','request_digest'):item[key]=digest(row[key])
            dependencies=connection.execute('SELECT predecessor_mutation_id FROM operation_dependencies WHERE scope_id=? AND mutation_id=? ORDER BY predecessor_mutation_id LIMIT 4',(row['scope_id'],row['mutation_id'])).fetchall()
            item['dependency_ids']=[identifier(d[0]) for d in dependencies if identifier(d[0])]
            result.append(item)
    return result
def target_database(home,workspace_id):
    if str(uuid.UUID(workspace_id))!=workspace_id:raise ValueError('Invalid diagnostic workspace')
    databases=list((home/'.meshia/accounts').glob('*/workspaces/'+workspace_id+'/fabric.db'))
    # Fresh enrollment may retain the singleton journal. Its private registry,
    # written only after authenticated attachment, binds that state to one UUID.
    registry=home/'.meshia/workspace-state-locations.json'
    try:
        fd=os.open(registry,os.O_RDONLY|os.O_NOFOLLOW)
    except FileNotFoundError:
        pass
    else:
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077 or not 2<=info.st_size<=8192:
                raise ValueError('Invalid registry ownership')
            raw=os.read(fd,8193)
            if len(raw)!=info.st_size:raise ValueError('Registry changed')
        finally:os.close(fd)
        document=json.loads(raw);binding=document.get('legacy',{})
        if document.get('schema')!='meshia.workspace-state-locations.v1' or set(binding)!={'account_id','session_id','workspace_id','workspace_root'}:
            raise ValueError('Invalid registry schema')
        for key in ('account_id','session_id','workspace_id'):
            if str(uuid.UUID(binding[key]))!=binding[key]:raise ValueError('Invalid registry authority')
        if not Path(binding['workspace_root']).is_absolute():raise ValueError('Invalid registry root')
        if binding['session_id']==workspace_id:
            singleton=home/'.meshia/fabric.db'
            if singleton.exists():databases.append(singleton)
    if len(databases)!=1:raise ValueError('Diagnostic database absent or ambiguous')
    database=databases[0]
    if database.is_symlink() or any(p.is_symlink() for p in database.parents if p!=home.parent):
        raise ValueError('Diagnostic database symlink')
    return database
class Observer:
    def __init__(self,home,workspace_id):
        if str(uuid.UUID(workspace_id))!=workspace_id:raise ValueError('Invalid diagnostic workspace')
        self.workspace_id=workspace_id
        self.home=home;self.started=time.time();self.samples=[];self.events=[];self.seen=set()
        self.log=home/'.meshia/node.log';self.offset=self.log.stat().st_size if self.log.exists() else 0
    def sample(self):
        snapshot={'elapsed_seconds':round(time.time()-self.started,3)}
        try:
            # Never walk the native mount from this diagnostics process: macOS
            # responsibility/TCC and filesystem timing belong to the actual
            # bounded native command, not an observer that could warm its cache.
            snapshot['journal']=journal(target_database(self.home,self.workspace_id))
            if self.log.exists() and not self.log.is_symlink():
                with self.log.open('rb') as stream:
                    if stream.seek(0,2)<self.offset:self.offset=0
                    stream.seek(self.offset);data=stream.read(262144);self.offset=stream.tell()
                for raw in data.splitlines():
                    try:event=public_event(json.loads(raw))
                    except (ValueError,UnicodeError):continue
                    if event and json.dumps(event) not in self.seen:
                        self.seen.add(json.dumps(event));self.events.append(event)
        except (OSError,ValueError,sqlite3.Error) as error:
            snapshot['diagnostic_error_type']=type(error).__name__
        if self.samples and {k:v for k,v in self.samples[-1].items() if k!='elapsed_seconds'}=={k:v for k,v in snapshot.items() if k!='elapsed_seconds'}:
            self.samples[-1]['elapsed_seconds']=snapshot['elapsed_seconds']
        else:self.samples.append(snapshot)
        self.samples=self.samples[-8:]
    def result(self):
        return {'profile':'mounted_replacement','read_only':True,'samples':self.samples,
            'mount_events':self.events[:100],
            'quiet_rename_errno_may_be_unlogged':True,
            'invocation':['managed-python','-I','-c','mounted_replacement_probe.py'],
            'environment_contract':{'HOME':'mounted workspace','TMPDIR':'mounted workspace'},
            'scope':'Only synthetic xcrun_db names; no cache bytes or raw logs exported'}
