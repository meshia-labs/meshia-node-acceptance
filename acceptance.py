#!/usr/bin/env python3
"""Public, fixture-only macOS acceptance for one pinned release; no private checkout."""
from __future__ import annotations

import argparse

import base64

from contextlib import contextmanager

from dataclasses import asdict

from datetime import datetime, timedelta, timezone

import hashlib

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import json

import os

from pathlib import Path

import plistlib

import pwd

import re

import signal

import subprocess

import sys

import threading

import time

import urllib.parse

import urllib.request

import uuid

import zipfile

ROOT = Path(__file__).resolve().parent
LOCK_SHA256 = "3c626a0c95bf05952f88b74466b7e7cd048a1d6e50759670650d9bcbecc38365"
LABEL = "io.meshia.node"

PUBLIC_KEYS = ("pid", "native_host_pid", "package_version", "live", "runtime_ready",
               "runtime_readiness_reason", "command_safe", "command_safety_reason",
               "sync_converged", "sync_convergence_reason", "fabric_head_generation")

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def gatekeeper_status():
    status = run(["/usr/sbin/spctl", "--status"]).decode().strip()
    require(status == "assessments enabled", "Gatekeeper assessments must be enabled; policy is never modified")
    return status


def assess_gatekeeper(app):
    gatekeeper_status()
    run(["/usr/sbin/spctl", "--assess", "--type", "execute", app])
    gatekeeper_status()


def subprocess_diagnostics(argv, returncode, stdout, stderr):
    # Match only fixed literal text in the hash-pinned installer. Never return
    # a captured line, expanded variable, URL, account detail or exception body.
    script = (ROOT / 'release/install-1.3.17.sh').read_text()
    output = (stdout + b'\n' + stderr)[-1024*1024:].decode(errors='replace')
    fixed = re.findall(r'\b(?:die|step) "([^"$`\n]{12,240})"', script)
    known = [text for text in dict.fromkeys(fixed) if text in output]
    types = [name for name in ('ModuleNotFoundError', 'ImportError', 'FileNotFoundError',
              'PermissionError', 'ConnectionError', 'TimeoutError', 'SSLCertVerificationError')
             if re.search(r'\b' + name + ':', output)]
    return {'program': Path(str(argv[0])).name, 'exit_code': returncode,
            'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
            'known_errors': known[-8:], 'exception_types': types}


class SubprocessFailure(AssertionError):
    def __init__(self, argv, returncode, stdout, stderr):
        self.diagnostics = subprocess_diagnostics(argv, returncode, stdout, stderr)
        super().__init__(f"{self.diagnostics['program']} returned {returncode}")


def run(argv, *, timeout=30, environment=None):
    # Never expose captured installer/control output: it may contain authority.
    process = subprocess.Popen([str(arg) for arg in argv], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
        raise
    if process.returncode != 0:
        raise SubprocessFailure(argv, process.returncode, out, err)
    require(len(out) <= 1024 * 1024, "Subprocess output exceeded receipt bound")
    return out

def wait(label, probe, seconds=45):
    deadline = time.monotonic() + seconds
    while True:
        result = probe()
        if result:
            return result
        require(time.monotonic() < deadline, f"Timed out: {label}")
        time.sleep(0.25)

def read_json(path):
    require(path.stat().st_size <= 1024 * 1024, "JSON input exceeded bound")
    return json.loads(path.read_text())

def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.chmod(0o600)
    temporary.replace(path)

def verify_release(root=None):
    """Read-only verification; no checkout history, credentials or network."""
    root = ROOT if root is None else Path(root)
    lock_path = root / "release-lock.json"
    require(lock_path.is_file() and not lock_path.is_symlink(), "Release lock must be a regular file")
    require(hashlib.sha256(lock_path.read_bytes()).hexdigest() == LOCK_SHA256, "Release lock changed")
    lock = read_json(lock_path)
    release = root / "release"
    require(release.is_dir() and not release.is_symlink(), "Release directory must be real")
    require(set(p.name for p in release.iterdir()) == set(lock["artifacts"]), "Unexpected release files")
    for name, digest in lock["artifacts"].items():
        require(Path(name).name == name, "Artifact must be a basename")
        path = release / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024 * 1024,
                "Artifact must be a bounded regular file")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "Artifact checksum differs")
    manifest = read_json(release / "release.json")
    validate_manifest(manifest, lock["source_commit"],
                      lock["artifacts"]["meshia_node-1.3.17-py3-none-any.whl"],
                      lock["artifacts"]["MeshiaNode-1.3.17.app.zip"])
    require(manifest["version"] == lock["version"] == "1.3.17", "Unexpected release version")
    require(manifest["install"]["posix_sha256"] == lock["artifacts"][manifest["install"]["posix"]],
            "Installer binding differs")
    with zipfile.ZipFile(release / manifest["macos_node_app"]) as archive:
        info = plistlib.loads(archive.read("Meshia Node.app/Contents/Info.plist"))
    require(info.get("MeshiaNodeSourceCommit") == lock["source_commit"]
            and info.get("CFBundleShortVersionString") == lock["version"]
            and info.get("CFBundleIdentifier") == LABEL, "Native app source/version binding differs")
    return lock, manifest

def fetch(directory):
    fresh_account()  # Before staging or changing this account.
    lock, manifest = verify_release()
    require(not directory.exists(), "Artifact directory already exists")
    directory.mkdir(mode=0o700, parents=True)
    for name in lock["artifacts"]:
        with (directory / name).open("xb") as output:
            output.write((ROOT / "release" / name).read_bytes())
    artifacts = {name: digest for name, digest in lock["artifacts"].items() if name != "release.json"}
    write_json(directory / "context.json", {
        "base": "checkout", "source": lock["source_commit"],
        "wheel_sha": manifest["sha256"], "app_sha": manifest["macos_node_app_sha256"],
        "artifacts": artifacts, "test_deadline_epoch": time.time() + 660,
    })
    print("PASS exact standalone release artifacts", flush=True)

def validate_manifest(document, source, wheel_sha, app_sha):
    require(re.fullmatch(r"[a-f0-9]{40}", source or ""), "Expected a full source commit")
    require(all(re.fullmatch(r"[a-f0-9]{64}", value or "") for value in (wheel_sha, app_sha)),
            "Expected full artifact SHA256 values")
    require(document.get("schema") == "meshia.node.public_release.v2"
            and document.get("source_commit") == source and document.get("source_dirty") is False,
            "Manifest source differs from reviewed clean source")
    version = document.get("version", "")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "Invalid release version")
    require(document.get("package") == f"meshia_node-{version}-py3-none-any.whl"
            and document.get("sha256") == wheel_sha, "Wheel binding differs")
    require(document.get("macos_node_app") == f"MeshiaNode-{version}.app.zip"
            and document.get("macos_node_app_sha256") == app_sha, "Signed app binding differs")
    install = document.get("install", {})
    require(install.get("posix") == f"install-{version}.sh"
            and re.fullmatch(r"[a-f0-9]{64}", install.get("posix_sha256", "")),
            "Installer binding differs")

@contextmanager
def artifact_origin(context, directory):
    account()  # This transport is only available in the owned hosted-Mac job.
    payloads = {}
    for filename, digest in context["artifacts"].items():
        require(Path(filename).name == filename, "Artifact must be a basename")
        content = (directory / filename).read_bytes()
        require(hashlib.sha256(content).hexdigest() == digest, "Local staging artifact changed")
        payloads["/" + filename] = content

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            # No directory listing, URL decoding, query aliases or filesystem
            # reads: only the immutable bytes verified immediately above.
            content = payloads.get(self.path)
            if content is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        require(not thread.is_alive(), "Artifact server did not stop")

def account():
    require(sys.platform == "darwin" and os.getuid() > 0 and os.getuid() == os.geteuid(),
            "Requires a non-root macOS account")
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")),
            "This destructive-to-fixture helper requires a fresh GitHub-hosted runner")
    user = pwd.getpwuid(os.getuid())
    require(user.pw_name == "runner" and Path(user.pw_dir) == Path.home(),
            "Requires the actual hosted runner account home")
    return Path(user.pw_dir)

def fresh_account():
    home = account()
    require(not any(os.path.lexists(path) for path in (
                home / ".meshia", home / "Meshia", home / "Library/LaunchAgents/io.meshia.node.plist",
                home / "meshia-acceptance-personal.txt", home / "meshia-acceptance-personal.escape")),
            "Runner contains a prior Meshia installation")
    run(["/bin/launchctl", "print", f"gui/{os.getuid()}"])
    require(subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{LABEL}"],
                           capture_output=True, timeout=5).returncode != 0, "Meshia service already exists")
    return home

def mount_records(text, root):
    records = []
    for line in text.splitlines():
        match = re.match(r"^.+ on (.+) \(([^,)]+)", line)
        if not match:
            continue
        path = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), match[1]))
        if path == root or root in path.parents:
            records.append({"path": str(path), "type": match[2]})
    return records

def mounts(root):
    return mount_records(run(["/sbin/mount"], timeout=5).decode(), root)

def runtime_projection(status):
    runtime = status.get("service", {}).get("runtime", {})
    return {key: runtime.get(key) for key in PUBLIC_KEYS}

def validate_owned(marker, home):
    require(marker == {"run_id": os.environ.get("GITHUB_RUN_ID"), "uid": os.getuid(),
                      "home": str(home), "fresh_installation_claimed": True},
            "Cleanup does not own this runner installation")

def cleanup(directory):
    marker = directory / "owned.json"
    if not marker.exists():
        return {"required": False, "passed": True}
    home = account()
    validate_owned(read_json(marker), home)
    cli = home / ".meshia/runtime/bin/meshia-node"
    failures = []
    if cli.is_file():
        # Controller stop closes mounts and owned native command coalitions.
        for action in ("stop", "uninstall"):
            try:
                run([cli, "--json", "service", action], timeout=45)
            except Exception as error:
                failures.append({"action": action, "error_type": type(error).__name__})
    unit = home / "Library/LaunchAgents/io.meshia.node.plist"
    registered = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{LABEL}"],
                                capture_output=True, timeout=5).returncode == 0
    remaining = mounts(home / "Meshia")
    for name in ("meshia-acceptance-personal.txt", "meshia-acceptance-personal.escape"):
        (home / name).unlink(missing_ok=True)
    # The receipt contains only owned PID versions, never process command lines.
    processes_gone = True
    identities_path = directory / "owned-processes.json"
    if identities_path.exists():
        from meshia_node.macos_native import Kernel, Identity
        kernel = Kernel()
        for entry in read_json(identities_path):
            prior = Identity(entry["pid"], entry["unique"], entry["version"], tuple(entry["coalition"]))
            processes_gone &= kernel.identity(prior.pid) != prior
    receipt = {"required": True, "service_registered": registered,
               "service_definition_exists": unit.exists(), "mounts_remaining": remaining,
               "owned_processes_gone": processes_gone, "errors": failures,
               "passed": not registered and not unit.exists() and not remaining and processes_gone and not failures}
    write_json(directory / "cleanup.json", receipt)
    return receipt

def acceptance(directory):
    context = read_json(directory / "context.json")
    manifest = read_json(directory / "release.json")
    validate_manifest(manifest, context["source"], context["wheel_sha"], context["app_sha"])
    remaining = min(600, int(context["test_deadline_epoch"] - time.time()))
    require(remaining > 0, "Test deadline expired before any installation")
    for filename, digest in context["artifacts"].items():
        require(hashlib.sha256((directory / filename).read_bytes()).hexdigest() == digest,
                "Staged artifact changed after verification")
    home = fresh_account()
    node_home = home / ".meshia"
    mount = home / "Meshia"
    unit = home / "Library/LaunchAgents/io.meshia.node.plist"
    from meshia_node.macos_native import Kernel
    from fixture_plane import AcceptancePlane
    plane = AcceptancePlane()
    plane.select_access_mode("full")
    kernel = Kernel()
    identities = []
    cli = node_home / "runtime/bin/meshia-node"
    python = node_home / "runtime/bin/python3"
    workspace = mount / plane.workspace_name
    receipt = {"passed": False, "source_commit": context["source"], "artifacts": context["artifacts"],
               "run_id": os.environ["GITHUB_RUN_ID"], "scope": "hosted_macos_packaged_loopback_account",
               "production_account_tested": False, "customer_privacy_prompt_ux_tested": False,
               "artifact_transport": "verified_bundle_loopback",
               "deployed_https_delivery_tested": False, "native_apps_tested": False,
               "development_host_override": False, "loopback_control_transport": True, "steps": []}
    phase = "preflight"

    def record(name, **facts):
        receipt["steps"].append({"name": name, "passed": True, **facts})
        write_json(directory / "receipt.json", receipt)
        print("PASS " + name, flush=True)

    def snapshot():
        value = json.loads(run([cli, "--json", "status"], timeout=15))
        receipt["last_runtime"] = runtime_projection(value)
        return value

    def ready():
        value = snapshot()
        service = value.get("service", {})
        runtime = service.get("runtime", {})
        return value if (service.get("native_host_owned") is True and runtime.get("runtime_ready") is True
                         and runtime.get("command_safe") is True and runtime.get("sync_converged") is True
                         and runtime.get("package_version") == manifest["version"] and mounts(mount)) else None

    def remember(pid):
        identity = kernel.identity(pid)
        require(identity is not None, "Native process disappeared before identity capture")
        identities.append(identity)
        write_json(directory / "owned-processes.json", [asdict(item) for item in identities])
        return identity

    def enqueue(source, *args, timeout=25):
        return plane.enqueue("exec", {"argv": [str(python), "-I", "-c", source, *map(str, args)],
            "cwd": ".", "timeout_seconds": timeout, "max_output_bytes": 16384})

    def complete(command_id):
        value = wait("command completion", lambda: plane.completions.get(command_id), 55)
        receipt["last_command"] = {"status": value.get("status"), "error_code": value.get("error_code"),
                                   "exit_code": value.get("result", {}).get("exit_code")}
        require(value.get("status") == "succeeded" and value.get("result", {}).get("exit_code") == 0,
                "Native queued command failed")
        return json.loads(base64.b64decode(value["result"]["output_base64"]))

    def expired(_signum, _frame):
        raise TimeoutError("Mac acceptance reached its ten-minute test deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.signal(signal.SIGTERM, expired)
    signal.alarm(remaining)
    try:
        record("fresh_host", uid=os.getuid(), os=run(["sw_vers", "-productVersion"]).decode().strip(),
               architecture=run(["uname", "-m"]).decode().strip(), gui_domain=True,
               image=os.environ.get("ImageVersion"), sip=run(["csrutil", "status"]).decode().strip(),
               gatekeeper=gatekeeper_status())
        plane.start()
        write_json(directory / "owned.json", {"run_id": os.environ["GITHUB_RUN_ID"],
                   "uid": os.getuid(), "home": str(home), "fresh_installation_claimed": True})
        phase = "canonical_installer"
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("MESHIA_", "UV_", "PYTHON")) and key not in ("PAIR_CODE", "PAIR_GRANT")}
        environment.update(MESHIA_PLAIN="1", MESHIA_NATIVE_APP="off",
            MESHIA_NODE_MACOS_APP_SHA256=context["app_sha"], PAIR_GRANT=plane.mint_pairing_code())
        try:
            with artifact_origin(context, directory) as origin:
                environment["MESHIA_NODE_MACOS_APP_URL"] = origin + "/" + manifest["macos_node_app"]
                run(["bash", directory / manifest["install"]["posix"], "--insecure-dev",
                     "--package-url", origin + "/" + manifest["package"],
                     "--package-sha256", context["wheel_sha"], "--", "--api-url", plane.origin,
                     "--access", "full"], timeout=360, environment=environment)
        finally:
            environment.pop("PAIR_GRANT", None)
        phase = "native_service_readiness"
        status = wait("signed app service readiness", ready, 90)
        runtime = status["service"]["runtime"]
        actual_app = node_home / "runtime/native/Meshia Node.app"
        executable = actual_app / "Contents/MacOS/MeshiaNode"
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", actual_app])
        run(["/usr/bin/xcrun", "stapler", "validate", actual_app])
        assess_gatekeeper(actual_app)
        record("signed_notarized_app", codesign_verified=True,
               notarization_ticket_valid=True, gatekeeper_accepted=True)
        definition = plistlib.loads(unit.read_bytes())
        arguments = definition["ProgramArguments"]
        require(Path(arguments[0]).resolve() == executable.resolve()
                and arguments[1:] == ["--home", str(node_home), "service", "run"],
                "LaunchAgent did not select the exact native app")
        require(definition.get("AssociatedBundleIdentifiers") == [LABEL], "Service app association missing")
        remember(runtime["pid"])
        remember(runtime["native_host_pid"])
        require(runtime["fabric_head_generation"] == 0, "Fresh empty workspace head was not accepted")
        # Execute through installed Python; verify every package module against
        # the exact downloaded wheel, without injecting checkout imports.
        module_count = int(run([python, "-I", "-c", "import meshia_node,pathlib,sys,zipfile\n"
            "root=pathlib.Path(meshia_node.__file__).parent.parent\n"
            "with zipfile.ZipFile(sys.argv[1]) as z:\n"
            " names=[n for n in z.namelist() if n.startswith('meshia_node/') and n.endswith('.py')]\n"
            " assert names and all((root/n).read_bytes()==z.read(n) for n in names)\n"
            " print(len(names))", directory / manifest["package"]]))
        record("canonical_signed_service", installed_modules=module_count, empty_head=0,
               native_host_owned=True, native_host_pid=runtime["native_host_pid"], runner_pid=runtime["pid"])
        phase = "mounted_roundtrip"
        run([python, "-I", "-c", "import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);"
             "f=p.open('w');f.write('mounted');f.flush();os.fsync(f.fileno());f.close();"
             "assert p.read_text()=='mounted'", workspace / "mac-mounted.txt"])
        wait("mounted write publication", lambda: plane.fabric_files.get("mac-mounted.txt") == b"mounted", 90)
        records = mounts(mount)
        require(records and all(item["type"] in ("smbfs", "nfs", "fuse", "osxfuse", "macfuse") for item in records),
                "No actual native filesystem mount was observed")
        record("native_mount_roundtrip", mounts=records)
        phase = "full_command"
        private = home / "meshia-acceptance-personal.txt"
        require(not private.exists(), "Personal canary unexpectedly exists")
        full = complete(enqueue("import json,os,pathlib,sys\np=pathlib.Path(sys.argv[1]);"
            "p.write_text('full');assert p.read_text()=='full';"
            "print(json.dumps({'uid':os.getuid(),'cwd':os.getcwd()}))", private))
        require(full["uid"] == os.getuid() and private.read_text() == "full", "Full did not use ordinary account")
        record("full_native_outside_workspace", ordinary_uid=True, outside_read_write=True)
        phase = "limited_command"
        plane.select_access_mode("limited")
        wait("owner permission downgrade", lambda: json.loads(run([python, "-I", "-c",
             "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['access']))", node_home / "config.json"]))
             == "limited", 40)
        wait("limited readiness", ready, 40)
        limited = complete(enqueue("""import json,os,pathlib,socket,sys
import cryptography
p=pathlib.Path(sys.argv[1]); checks={}
for name, action in {'read':p.read_text,'write':lambda:p.write_text('escape'),
                     'stat':p.stat,'create':lambda:p.with_suffix('.escape').write_text('escape')}.items():
 try: action()
 except (PermissionError,FileNotFoundError): checks[name]='denied'
 else: checks[name]='ALLOWED'
with pathlib.Path('mac-limited.txt').open('w') as result:
 result.write('computed');result.flush();os.fsync(result.fileno())
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0));listener.listen()
 with socket.create_connection(listener.getsockname()) as client:
  peer,_=listener.accept()
  with peer: peer.sendall(b'compute');assert client.recv(7)==b'compute'
checks.update(uid=os.getuid(),cpus=os.cpu_count(),runtime=cryptography.__version__)
print(json.dumps(checks))
""", private))
        require(all(limited[key] == "denied" for key in ("read", "write", "stat", "create"))
                and limited["uid"] == os.getuid() and private.read_text() == "full",
                "Workspace-only native boundary failed")
        wait("limited publication", lambda: plane.fabric_files.get("mac-limited.txt") == b"computed", 90)
        record("limited_native_compute", **limited, workspace_read_write=True, networking=True)
        phase = "detached_cancel"
        command_started = time.monotonic()
        command_id = enqueue("""import os,pathlib,time
if os.fork(): time.sleep(240);os._exit(0)
os.setsid()
if os.fork(): os._exit(0)
with pathlib.Path('mac-detached.pid').open('w') as marker:
 marker.write(str(os.getpid()));marker.flush();os.fsync(marker.fileno())
time.sleep(240)
""", timeout=240)
        pid = int(wait("detached child publication", lambda: plane.fabric_files.get("mac-detached.pid"), 90))
        child = remember(pid)
        require(child.coalition != kernel.own.coalition, "Command lacks separate native coalition")
        cancelled_at = time.monotonic()
        plane.cancelled.add(command_id)
        wait("detached child cancellation", lambda: kernel.identity(pid) != child, 30)
        cancelled_elapsed = time.monotonic() - cancelled_at
        require(time.monotonic() - command_started < 240, "Natural command timeout cannot prove cancellation")
        completion = wait("cancellation completion", lambda: plane.completions.get(command_id), 30)
        require(completion.get("status") in ("failed", "canceled"), "Canceled command unexpectedly succeeded")
        record("signed_native_detached_cancel", pid=pid, stale_pid_safe_identity=True,
               completion_status=completion["status"], cancellation_seconds=round(cancelled_elapsed, 3),
               command_timeout_seconds=240, cancellation_before_natural_exit=True)
        private.unlink()
        receipt["passed"] = True
    except Exception as error:
        # Error labels are local constants; never include command output or
        # private config/control response bodies in uploaded evidence.
        receipt["failure"] = {"phase": phase, "error_type": type(error).__name__,
                              "message": str(error)[:240] if isinstance(error, AssertionError) else None}
        if isinstance(error, SubprocessFailure):
            receipt['failure']['diagnostics'] = error.diagnostics
        receipt['failure']['installer_state'] = {
            'cli_exists': cli.exists(), 'native_app_exists': (node_home / 'runtime/native/Meshia Node.app').exists(),
            'service_definition_exists': unit.exists(), 'node_home_exists': node_home.exists()}
        receipt['failure']['fixture_errors'] = list(plane.safe_errors)
        receipt['failure']['fixture_requests'] = dict(plane.v2_calls)
    finally:
        signal.alarm(0)
        try:
            if cli.exists():
                try:
                    snapshot()
                except Exception:
                    pass
            receipt["cleanup"] = cleanup(directory)
            receipt["passed"] &= receipt["cleanup"]["passed"]
        except Exception as error:
            receipt["passed"] = False
            receipt["cleanup"] = {"passed": False, "error_type": type(error).__name__}
        finally:
            plane.stop()
            write_json(directory / "receipt.json", receipt)
    print(json.dumps({"passed": receipt["passed"], "receipt": str(directory / "receipt.json")}))
    return 0 if receipt["passed"] else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "fetch", "run", "cleanup"))
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    try:
        if args.action == "verify":
            verify_release()
            print("PASS exact standalone release bytes")
            return 0
        if args.action == "fetch":
            fetch(directory)
            return 0
        if args.action == "run":
            return acceptance(directory)
        result = cleanup(directory)
        print(json.dumps(result))
        return 0 if result["passed"] else 1
    except Exception as error:
        if directory.is_dir():
            path = directory / ("cleanup.json" if args.action == "cleanup" else "receipt.json")
            if not path.exists():
                write_json(path, {"passed": False, "failure": {
                    "phase": args.action, "error_type": type(error).__name__}})
        print(f"FAIL {args.action}: {type(error).__name__}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
