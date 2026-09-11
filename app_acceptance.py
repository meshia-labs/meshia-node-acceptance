"""Small same-port app fixture driven only through the installed signed app lane."""
import base64
from datetime import datetime
import hashlib
import json
import re
import socket
import time
import uuid

SSE_BODY = b'event: proof\ndata: meshia\n\n' * 12000
WS_BODY = b'\x00\xffnative-app-echo'
APP_EXIT_PHASES = {80: 'child_setup', 81: 'dependency_import', 82: 'personal_boundary',
                   83: 'mounted_write', 84: 'listener_setup', 85: 'server_running'}
APP_SOURCE = r'''
stage = 80
try:
 import json, logging, os, sys, threading
 from pathlib import Path
 stage = 81
 from websockets.sync.server import serve
 logging.disable(logging.CRITICAL)
 stage = 80
 mode, personal = sys.argv[1:]
 personal = Path(personal)
 checks = {}
 stage = 82
 for name, operation in (('read', lambda: personal.read_text()),
                         ('write', lambda: personal.write_text('full')),
                         ('stat', personal.stat)):
  try:
   operation(); checks[name] = 'allowed'
  except (PermissionError, FileNotFoundError): checks[name] = 'denied'
 expected = 'allowed' if mode == 'full' else 'denied'
 assert all(value == expected for value in checks.values()), 'App filesystem boundary failed'
 stage = 83
 with Path('mac-app-' + mode + '.txt').open('w') as result:
  result.write('app-compute-' + mode); result.flush(); os.fsync(result.fileno())
 checks.update(uid=os.getuid(), pid=os.getpid())
 def http(connection, request):
  if request.path == '/http': return connection.respond(200, json.dumps(checks))
  if request.path == '/sse':
   response = connection.respond(200, 'event: proof\ndata: meshia\n\n' * 12000)
   del response.headers['Content-Type']
   response.headers['Content-Type'] = 'text/event-stream'
   return response
 def echo(ws):
  for message in ws: ws.send(message)
 timer = threading.Timer(90, lambda: os._exit(0)); timer.daemon = True; timer.start()
 stage = 84
 with serve(echo, '127.0.0.1', int(os.environ['PORT']), process_request=http,
            compression=None, ping_interval=None, close_timeout=.2, max_size=1024) as server:
  stage = 85
  server.serve_forever()
except Exception:
 # Fixed fixture-only exit stages survive the installed service's safe
 # startup result without emitting workload output, paths or tracebacks.
 raise SystemExit(stage) from None
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


def app_error_code(code, allowed):
    return code if isinstance(code, str) and code in allowed else 'unclassified'


def app_completion_diagnostics(completion):
    """Retain exact installed-service literals; never return raw messages."""
    result = completion.get('result')
    if not isinstance(result, dict):
        return {}
    safe = {}
    try:
        elapsed = (datetime.fromisoformat(result['finished_at'].replace('Z', '+00:00'))
                   - datetime.fromisoformat(result['started_at'].replace('Z', '+00:00'))).total_seconds()
        if 0 <= elapsed <= 120:
            safe['elapsed_seconds'] = round(elapsed, 3)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        pass
    message = result.get('message')
    if completion.get('error_code') != 'APP_START_FAILED' or not isinstance(message, str) or len(message) > 200:
        return safe
    matched = re.fullmatch(r'App exited before opening its owned port\. \((exit code -?\d{1,10}|'
                          r'COMMAND_EXITED|STATE_ERROR|INVALID_TASK|UNSAFE_PATH|LOCAL_ACCESS_REFUSED|'
                          r'LOCAL_TIER_REFUSED|DISCONNECTED|WORKSPACE_ADOPTION_REQUIRED|'
                          r'WORKSPACE_CLAIM_INVALID|NETWORK_UNAVAILABLE|OS_ERROR|INTERNAL_ERROR)\)', message)
    if matched is None:
        return safe
    reason = matched[1]
    if reason.startswith('exit code '):
        code = int(reason[10:])
        if -(2**31) <= code < 2**32:
            safe['exit_code'] = code
            if code in APP_EXIT_PHASES:
                safe['phase'] = APP_EXIT_PHASES[code]
    else:
        safe['reason'] = reason
    return safe


def exercise_app(submit, python, personal, mode, *, remember, gone, uid, progress):
    """No direct HTTP fallback: every application byte crosses NativeApps."""
    require(mode in ('full', 'limited'), 'Invalid acceptance app mode')
    name = 'mac-acceptance-' + mode
    phase = 'reserve'
    app = None
    identity = None
    cleanup = False
    streams = []
    began = time.monotonic()
    def call(kind, **payload):
        progress(mode=mode, phase=phase, status='running')
        return submit(kind, payload)
    def control(operation, **arguments):
        return call('app_control', operation=operation, arguments={'app_id': name, **arguments})
    def request(stream, operation, **fields):
        return call('app_http', app_id=name, instance_id=app['instance_id'], port=app['port'],
                    stream_id=stream, operation=operation, **fields)
    def http(path):
        stream = str(uuid.uuid4())
        streams.append((stream, 'close'))
        result = request(stream, 'open', method='GET', path=path, query='', headers={}, body_base64='')
        require(result['status'] == 200, 'App HTTP status failed')
        if path == '/sse':
            require(result['headers'].get('content-type') == 'text/event-stream', 'App SSE content type changed')
        body = bytearray(base64.b64decode(result['body_base64'], validate=True))
        reads = 0
        while not result['eof']:
            require(reads < 8 and len(body) <= len(SSE_BODY), 'App response exceeded its acceptance bound')
            result = request(stream, 'read', sequence=result['next_sequence'], max_bytes=262144)
            require(result['offset'] == len(body), 'App HTTP offset changed')
            body.extend(base64.b64decode(result['body_base64'], validate=True))
            reads += 1
        streams.remove((stream, 'close'))
        request(stream, 'close')
        return bytes(body), reads
    try:
        lease = control('reserve_lab_app_port')['lease']
        phase = 'register'
        app = control('register_lab_app', title='Native acceptance', port=lease['port'],
                      launch_argv=[str(python), '-I', '-u', '-c', APP_SOURCE, mode, str(personal)], cwd='.')['app']
        require(app['status'] == 'ready', 'Native app did not become ready')
        phase = 'http'
        raw, _ = http('/http')
        facts = json.loads(raw)
        require(set(facts) == {'uid', 'pid', 'read', 'write', 'stat'} and facts['uid'] == uid
                and type(facts['pid']) is int and facts['pid'] > 0, 'App did not use the ordinary OS account')
        require(all(facts[key] == ('allowed' if mode == 'full' else 'denied')
                    for key in ('read', 'write', 'stat')), 'App filesystem boundary failed')
        identity = remember(facts['pid'])
        phase = 'sse_body'
        body, reads = http('/sse')
        require(body == SSE_BODY and reads >= 1, 'App multi-chunk SSE body changed')
        phase = 'websocket'
        stream = str(uuid.uuid4())
        streams.append((stream, 'ws_close'))
        request(stream, 'ws_open', path='/ws', query='', headers={}, subprotocols=[])
        request(stream, 'ws_send', sequence=0, message_type='binary',
                body_base64=base64.b64encode(WS_BODY).decode(), end_of_message=True)
        echoed = bytearray()
        sequence = 0
        for _ in range(8):
            chunk = request(stream, 'ws_read', sequence=sequence, max_bytes=262144)
            require(chunk['message_type'] == 'binary' or (chunk['message_type'] is None
                    and not chunk['body_base64'] and not chunk['end_of_message']), 'App WebSocket message type changed')
            echoed.extend(base64.b64decode(chunk['body_base64'], validate=True))
            require(len(echoed) <= len(WS_BODY), 'App WebSocket response exceeded its bound')
            sequence = chunk['next_sequence']
            if chunk['end_of_message']:
                break
        require(bytes(echoed) == WS_BODY and chunk['end_of_message'], 'App WebSocket echo changed')
        streams.remove((stream, 'ws_close'))
        request(stream, 'ws_close', close_code=1000, close_reason='done')
        return {'mode': mode, 'http': True, 'sse_body': True, 'sse_progressive_timing_tested': False,
                'response_bytes': len(body), 'response_sha256': hashlib.sha256(body).hexdigest(),
                'websocket_binary': True, 'ordinary_uid': True, 'workspace_read_write': True,
                'outside_access': 'allowed' if mode == 'full' else 'denied'}
    except Exception:
        progress(mode=mode, phase=phase, status='failed')
        raise
    finally:
        phase = 'cleanup'
        # Close each accepted stream once and always attempt canonical app
        # removal. The enclosing owned-service cleanup also runs on failure.
        try:
            for stream, operation in streams:
                try:
                    request(stream, operation, **({'close_code': 1000, 'close_reason': 'cleanup'}
                                                  if operation == 'ws_close' else {}))
                except Exception:
                    pass
        finally:
            result = control('unregister_lab_app')
            cleanup = result['cleanup']['owned_process_stopped'] is True
            if app is not None:
                with socket.socket() as connection:
                    connection.settimeout(1)
                    cleanup = cleanup and connection.connect_ex(('127.0.0.1', app['port'])) != 0
            if identity is not None:
                cleanup = cleanup and gone(identity)
            progress(mode=mode, phase=phase, status='succeeded' if cleanup else 'failed',
                     owned_process_stopped=cleanup, elapsed_seconds=round(time.monotonic()-began, 3))
            require(cleanup, 'Owned native app cleanup was not confirmed')
