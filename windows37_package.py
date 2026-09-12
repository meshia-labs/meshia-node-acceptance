"""Download only the immutable public wheel and bind installed import evidence."""
import hashlib
import ctypes
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.request

NAME = "meshia_node-1.3.37-py3-none-any.whl"
PUBLIC_SHA = "fb244ca7e315414322751f96549a703b2d3abace19bd4cf573e9e1941663cb6e"
SHA = "2c847d9013ecb398a9c0745af675971f56fdcd5ce45579265d0c49d62e4a5e99"
SOURCE = "960b22f019705e269010662526335a7e953ad5be"
directory = Path("windows37-evidence")
directory.mkdir(exist_ok=True)
if sys.argv[1] == "download":
    with urllib.request.urlopen("https://meshia.io/meshia-node/" + NAME, timeout=30) as response:
        data = response.read(20 * 1024 * 1024 + 1)
    assert len(data) <= 20 * 1024 * 1024
    assert hashlib.sha256(data).hexdigest() == PUBLIC_SHA
    (directory / NAME).write_bytes(data)
elif sys.argv[1] == "candidate":
    candidate = Path("candidate-wheel") / NAME
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == SHA
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--force-reinstall", str(candidate)],
        check=True, timeout=60)
    shutil.copyfile(candidate, directory / NAME)
elif sys.argv[1] == "verify":
    import meshia_node
    from meshia_node.workspace import WorkspaceBoundary
    from meshia_node.winsec import current_user_sid, is_owner_restricted, ensure_owner_restricted
    assert sys.platform == "win32"
    assert not hasattr(os, "pread"), "Windows must exercise portable seek/read"
    assert importlib.metadata.version("meshia-node") == "1.3.37"
    assert "site-packages" in str(Path(meshia_node.__file__).resolve())
    assert "workspace_win" in WorkspaceBoundary.__module__
    assert not ctypes.windll.shell32.IsUserAnAdmin(), "Qualification requires an ordinary user"
    state = Path(os.environ["TEMP"]) / "owner-proof"
    state.mkdir()
    ensure_owner_restricted(state)
    assert is_owner_restricted(state), "Actual owner must match the current ordinary SID"
    assert hashlib.sha256((directory / NAME).read_bytes()).hexdigest() == SHA
    (directory / "installed.json").write_text(json.dumps({
        "schema": "meshia.windows_descriptor_qualification.v1", "package": NAME,
        "qualification_artifact": "unpublished_candidate", "baseline_public_sha256": PUBLIC_SHA,
        "sha256": SHA, "source_commit": SOURCE, "platform": platform.platform(),
        "python": platform.python_version(), "workspace_boundary": WorkspaceBoundary.__module__,
        "portable_pread": True, "paired": False, "mount_started": False,
        "current_sid": current_user_sid(), "state_owner_matches_current_sid": True, "admin": False,
    }, indent=2) + "\n", encoding="utf-8")
else:
    raise SystemExit("unknown operation")
